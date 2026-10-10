function Invoke-PurviewPurge {
    <#
    .SYNOPSIS
        Executes an end-to-end Purview mailbox HardDelete purge workflow.

    .DESCRIPTION
        Invoke-PurviewPurge orchestrates a full content purge workflow against
        Microsoft Purview Compliance Search using the fixed case name "Content
        Search".

        Workflow summary:
        - Initializes TechToolbox runtime/config and logging.
        - Normalizes and validates the ticket as "#INC-<integer>".
        - Optionally prompts to confirm/correct ticket input.
        - Connects to Purview (SearchOnly session via Exchange Online module).
        - Reuses an existing search query when safe, or prompts for a new query.
        - Lints ContentMatchQuery and blocks continuation until valid.
        - Ensures mailbox-only Compliance Search exists/updates by ticket name.
        - Waits for search object registration (when newly created).
        - Starts the search when required and waits for completion.
        - Submits a HardDelete purge when matching mailbox items are found.

        The function supports ShouldProcess (-WhatIf/-Confirm) for start and
        purge actions. If WhatIf/Confirm prevents actionable steps, execution
        exits safely with logs.

        Interactive behavior:
        - When prompting is enabled by config, missing/invalid ticket and query
          values are requested interactively.
        - Enter q, quit, or exit at prompts to cancel.

        Default timeout/poll values are sourced from config and fall back to:
        - Search completion timeout: 2400 seconds
        - Search completion poll: 20 seconds
        - Registration timeout: 90 seconds
        - Registration poll: 3 seconds

    .PARAMETER UserPrincipalName
        UPN used to connect to Purview/Exchange Online (for example,
        analyst@company.com).

    .PARAMETER Ticket
        Internal ticket identifier. Expected format is "#INC-<integer>". The
        value is normalized to uppercase, prefixed with # if omitted, validated,
        and used as the Compliance Search name.

    .PARAMETER ContentMatchQuery
        KQL/keyword query used by Compliance Search to select mailbox items for
        purge.

        If omitted and prompting is enabled, the function prompts for input. If
        a search with the same ticket already exists and has a query, the
        function can reuse that query. Query text is linted before continuing.

    .PARAMETER Log
        Optional hashtable of per-invocation logging overrides. Values are
        merged into module logging behavior.

    .PARAMETER ShowProgress
        Enables console progress/log output for this invocation.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        None. Operational status is emitted through logging.

    .NOTES
        - Requires permissions to create/start Compliance Searches and submit
          purge actions in Purview.
        - Uses fixed case name: "Content Search".
        - Search name is the normalized ticket (for example, #INC-151695).
        - Purge is submitted only when completed search item count is greater
          than zero.
        - Function logs reminder to disconnect Exchange Online at end.

    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" `
            -Ticket "#INC-151695" `
            -ContentMatchQuery 'from:("pm-bounces.broobe.*" OR "broobe.*") AND subject:"Aligned Assets"'
        Runs a full purge with explicit ticket and query values.

    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" -Ticket "inc-151695"
        Prompts for query (when enabled), normalizes ticket to #INC-151695, then
        runs the workflow.

    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" -Ticket "#INC-151695" -WhatIf
        Simulates start/purge actions and logs intended operations without
        submitting a purge.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Invoke-PurviewPurge
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Ticket,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ContentMatchQuery,

        [Parameter()]
        [hashtable]$Log,

        [switch]$ShowProgress
    )

    # Load dependencies + fixed case
    Initialize-TechToolboxRuntime
    $CaseName = $script:cfg.settings.purview.caseName

    # Ensure these exist for finally/catch paths
    $exo = $null
    $ticketNorm = $null
    $purgeSubmitted = $false

    function Convert-FriendlyContentMatchQuery {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Query
        )

        $normalized = $Query
        $notes = New-Object System.Collections.Generic.List[string]

        # Convert field=value and field==value into Purview KQL field:value form.
        $eqPattern = '(?ix)\b(?<field>[a-z][a-z0-9_]*)\s*(?:=|==)\s*(?<value>"[^"]+"|''[^'']+''|[^\s\)\(]+)'
        $rewritten = [regex]::Replace($normalized, $eqPattern, {
                param($m)
                $field = $m.Groups['field'].Value
                $value = $m.Groups['value'].Value.Trim()

                if ($value.StartsWith("'") -and $value.EndsWith("'")) {
                    $value = '"{0}"' -f $value.Trim("'")
                }
                elseif ($value -notmatch '^".*"$') {
                    $value = '"{0}"' -f $value.Trim('"')
                }

                return ('{0}:{1}' -f $field, $value)
            })

        if ($rewritten -ne $normalized) {
            $notes.Add("Converted '=' or '==' clauses to Purview field:value syntax.")
            $normalized = $rewritten
        }

        # Convert user-friendly contains on subject into wildcard contains semantics.
        $subjectContainsPattern = '(?ix)\b(?<field>subject)\s+contains\s+(?<value>"[^"]+"|''[^'']+''|[^\s\)\(]+)'
        $rewritten = [regex]::Replace($normalized, $subjectContainsPattern, {
                param($m)
                $field = $m.Groups['field'].Value
                $rawValue = $m.Groups['value'].Value.Trim()

                if (($rawValue.StartsWith('"') -and $rawValue.EndsWith('"')) -or ($rawValue.StartsWith("'") -and $rawValue.EndsWith("'"))) {
                    $rawValue = $rawValue.Substring(1, $rawValue.Length - 2)
                }

                $rawValue = $rawValue -replace '"', '""'
                return ('{0}:"*{1}*"' -f $field, $rawValue)
            })

        if ($rewritten -ne $normalized) {
            $notes.Add("Converted 'subject contains ...' to subject:`"*...*`" for a forgiving contains-style match.")
            $normalized = $rewritten
        }

        # Address fields do not support wildcard matching in Purview KQL; map contains to exact value.
        $addressContainsPattern = '(?ix)\b(?<field>from|sender|to|cc|bcc|participants)\s+contains\s+(?<value>"[^"]+"|''[^'']+''|[^\s\)\(]+)'
        $rewritten = [regex]::Replace($normalized, $addressContainsPattern, {
                param($m)
                $field = $m.Groups['field'].Value
                $rawValue = $m.Groups['value'].Value.Trim()

                if (($rawValue.StartsWith('"') -and $rawValue.EndsWith('"')) -or ($rawValue.StartsWith("'") -and $rawValue.EndsWith("'"))) {
                    $rawValue = $rawValue.Substring(1, $rawValue.Length - 2)
                }

                $rawValue = $rawValue -replace '"', '""'
                return ('{0}:"{1}"' -f $field, $rawValue)
            })

        if ($rewritten -ne $normalized) {
            $notes.Add("Converted address-field 'contains' clauses to exact field:`"value`" because wildcard contains is unsupported.")
            $normalized = $rewritten
        }

        return [pscustomobject]@{
            Query = $normalized
            Notes = $notes.ToArray()
        }
    }

    try {
        # ---- Config & defaults ----
        $purv = $script:cfg.settings.purview
        $defaults = $script:cfg.settings.defaults
        $exo = $script:cfg.settings.exchangeOnline
        $confirm = $purv.purge.requireConfirmation

        # Support both legacy and purge.* keys in config
        $timeoutSeconds = [int]$purv.purge.timeoutSeconds
        if ($timeoutSeconds -le 0) { $timeoutSeconds = 2400 }

        $pollSeconds = [int]$purv.purge.pollSeconds
        if ($pollSeconds -le 0) { $pollSeconds = 20 }

        # Registration wait (configurable)
        $regTimeout = [int]$purv.registrationWaitSeconds
        if ($regTimeout -le 0) { $regTimeout = 90 }

        $regPoll = [int]$purv.registrationPollSeconds
        if ($regPoll -le 0) { $regPoll = 3 }

        # ---- Ticket normalization using config-driven rules ----

        # Load ticket rules from config (with safe fallbacks)
        $ticketCfg = $script:cfg.settings.purview.ticket
        $pattern = $ticketCfg.pattern
        if (-not $pattern) { $pattern = '^(?<prefix>[A-Za-z]+-)?(?<id>\d+)$' }

        $normalizePrefix = $ticketCfg.normalizePrefix
        $requireHash = $ticketCfg.requireHash
        $forceUpper = $ticketCfg.forceUpper
        if ($null -eq $forceUpper) { $forceUpper = $true }

        while ($true) {
            $raw = [string]$Ticket
            $raw = $raw.Trim()

            if ($raw -match '^(?i)(q|quit|exit)$') {
                throw "User cancelled: ticket entry aborted."
            }

            if ([string]::IsNullOrWhiteSpace($raw)) {
                $Ticket = Read-Host "Enter ticket (or 'q' to cancel)"
                continue
            }

            # Apply uppercase normalization if configured
            if ($forceUpper) {
                $raw = $raw.ToUpper()
            }

            # Allow users to enter the configured hash prefix before validating
            # against the base ticket pattern.
            if ($requireHash -and $raw.StartsWith('#')) {
                $raw = $raw.Substring(1)
            }

            # Validate against configured pattern
            if ($raw -notmatch $pattern) {
                Write-Log -Level Warn -Message "Ticket does not match required pattern: $pattern"
                $Ticket = Read-Host "Re-enter ticket (or 'q' to cancel)"
                continue
            }

            # Extract captured groups
            $prefix = $Matches['prefix']
            $id = $Matches['id']

            # Normalize prefix if configured
            if ($normalizePrefix) {
                $prefix = $normalizePrefix
            }

            # Rebuild normalized ticket
            $ticketNorm = "$prefix$id"

            # Optional leading '#'
            if ($requireHash -and $ticketNorm -notmatch '^#') {
                $ticketNorm = "#$ticketNorm"
            }

            # Confirm with user
            $resp = Read-Host "Ticket is '$ticketNorm'. Is this correct? (Y/n/q)"
            if ($resp -match '^(?i)(q|quit|exit)$') {
                throw "User cancelled: ticket confirmation aborted."
            }
            if ($resp -match '^(?i)n(o)?$') {
                $Ticket = Read-Host "Enter the correct ticket (or 'q' to cancel)"
                continue
            }

            Write-Log -Level Info -Message ("Using ticket: {0}" -f $ticketNorm)
            break
        }

        # ---- Module & session ----
        Import-ExchangeOnlineModule -ErrorAction Stop
        Connect-Purview -UserPrincipalName $UserPrincipalName -ErrorAction Stop

        # ----- Query prompt + validation/normalization -----
        $promptQuery = $defaults.promptForContentMatchQuery
        if ($null -eq $promptQuery) { $promptQuery = $true }
        $normalizeFriendlyQuery = $true
        if ($purv.purge -is [hashtable]) {
            if ($purv.purge.ContainsKey('normalizeFriendlyQuery')) {
                $normalizeFriendlyQuery = [bool]$purv.purge['normalizeFriendlyQuery']
            }
        }
        elseif ($purv.purge.PSObject.Properties['normalizeFriendlyQuery']) {
            $normalizeFriendlyQuery = [bool]$purv.purge.normalizeFriendlyQuery
        }
        $UseExistingQuery = $false
        $UpdateScope = $false
        $AllowQueryWeaken = $true

        # If the search already exists, offer to reuse its query
        $existing = Get-ComplianceSearch -Identity $ticketNorm -ErrorAction SilentlyContinue
        if ($existing -and -not [string]::IsNullOrWhiteSpace($existing.ContentMatchQuery)) {

            Write-Log -Level Info -Message ""
            Write-Log -Level Warn -Message "Existing Compliance Search found: $ticketNorm"
            Write-Log -Level Warn -Message ("  {0}" -f $existing.ContentMatchQuery)
            Write-Log -Level Info -Message ""

            # Only prompt if interactive prompting is enabled; otherwise default to reuse for safety
            if ($promptQuery) {
                $resp = Read-Host "Reuse the existing query instead of entering a new one? (Y/N)"
                if ($resp -match '^(?i)y(?:es)?$') {
                    $UseExistingQuery = $true
                }
            }
            else {
                # In non-interactive mode, safest default is to reuse existing query
                $UseExistingQuery = $true
                Write-Log -Level Info -Message "Prompting disabled by config; defaulting to reuse existing ContentMatchQuery."
            }

            if ($UseExistingQuery) {
                $ContentMatchQuery = $existing.ContentMatchQuery.Trim()
                Write-Log -Level Info -Message ("Using existing ContentMatchQuery: {0}" -f $ContentMatchQuery)
            }
        }

        # Work with a local query variable so parameter validation attributes do not
        # block retry attempts while prompting/linting.
        $workingContentMatchQuery = $ContentMatchQuery

        # If we didn’t reuse an existing query, run the normal prompt + lint loop
        if (-not $UseExistingQuery) {

            while ($true) {

                if ([string]::IsNullOrWhiteSpace($workingContentMatchQuery)) {
                    if ($promptQuery) {
                        $workingContentMatchQuery = Read-Host "Enter ContentMatchQuery (or type 'q' to cancel) (e.g., from:(""pm-bounces.broobe.*"" OR ""broobe.*"") AND subject:""Aligned Assets"")"
                    }
                    else {
                        throw "ContentMatchQuery is required but prompting is disabled by config."
                    }
                }

                $workingContentMatchQuery = $workingContentMatchQuery.Trim()

                if ($workingContentMatchQuery -match '^(?i)(q|quit|exit)$') {
                    throw "User cancelled: ContentMatchQuery entry aborted."
                }

                if ([string]::IsNullOrWhiteSpace($workingContentMatchQuery)) {
                    Write-Log -Level Warn -Message "ContentMatchQuery cannot be empty."
                    $workingContentMatchQuery = $null
                    continue
                }

                # Convert smart quotes from Outlook/Teams to straight quotes expected by KQL tooling.
                $queryAfterQuoteNormalization =
                ($workingContentMatchQuery -replace '[\u2018\u2019]', "'") -replace '[\u201C\u201D]', '"'
                if ($queryAfterQuoteNormalization -ne $workingContentMatchQuery) {
                    Write-Log -Level Warn -Message "Smart quotes detected in ContentMatchQuery; normalized to straight quotes."
                    $workingContentMatchQuery = $queryAfterQuoteNormalization
                }

                if ($normalizeFriendlyQuery) {
                    $converted = Convert-FriendlyContentMatchQuery -Query $workingContentMatchQuery
                    if ($converted.Query -ne $workingContentMatchQuery) {
                        foreach ($note in $converted.Notes) {
                            Write-Log -Level Info -Message $note
                        }
                        Write-Log -Level Info -Message ("Normalized ContentMatchQuery: {0}" -f $converted.Query)
                    }
                    $workingContentMatchQuery = $converted.Query
                }

                $warningsRef = [ref] $null
                $isValid = Test-ContentMatchQueryLint -Query $workingContentMatchQuery -Warnings $warningsRef

                if (-not $isValid) {
                    $warnings = $warningsRef.Value
                    if ($warnings) {
                        foreach ($w in $warnings) {
                            Write-Log -Level Warn -Message $w
                        }
                    }
                    Write-Log -Level Warn -Message "KQL must be corrected before continuing."
                    $workingContentMatchQuery = $null
                    continue
                }

                Write-Log -Level E-Info -Message ("Final ContentMatchQuery: {0}" -f $workingContentMatchQuery)
                $ContentMatchQuery = $workingContentMatchQuery
                break
            }
        }

        # ---- Build search name ----
        $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $searchName = "{0}" -f $ticketNorm
        $desc = "Possible Phishing/Spam/Marketing - $ticketNorm - $ts"

        Write-Log -Level E-Info -Message ("Ensuring mailbox-only Compliance Search '{0}' exists in case '{1}'..." -f $searchName, $CaseName)

        $ensureParams = @{
            Name              = $searchName
            CaseName          = $CaseName
            ExchangeLocation  = 'All'
            ContentMatchQuery = $ContentMatchQuery
            Description       = $desc
            ConfirmPreference = $confirm
            UpdateScope       = $true # Always update scope to ensure mailbox-only, even if reusing existing search
        }

        if ($UseExistingQuery) { $ensureParams.UseExistingQuery = $true }
        if ($AllowQueryWeaken) { $ensureParams.AllowQueryWeaken = $true }
        # if ($UpdateScope) { $ensureParams.UpdateScope = $true }

        $ensure = Get-ComplianceSearchOrCreate @ensureParams

        # If -WhatIf/-Confirm prevented creation/update, $ensure.Search may be $null
        if ($null -eq $ensure.Search) {
            Write-Log -Level Info -Message "Search ensure step skipped due to -WhatIf/-Confirm."
            return
        }

        $searchObj = $ensure.Search

        ## ---- Wait until the search object is registered/visible (only if created) ----
        if ($ensure.Created) {
            Write-Log -Level Info -Message ("Waiting for search '{0}' to register (timeout={1}s, poll={2}s)..." -f $searchName, $regTimeout, $regPoll)
            $registered = Wait-ComplianceSearchRegistration -SearchName $searchName -TimeoutSeconds $regTimeout -PollSeconds $regPoll
            if (-not $registered) {
                throw "Search object '$searchName' was not visible after creation (waited ${regTimeout}s). Aborting."
            }
        }
        else {
            Write-Log -Level Info -Message ("Search '{0}' existed; update applied. Registration wait skipped." -f $searchName)
        }

        # ---- Ensure the search is started ----
        $pre = Get-ComplianceSearch -Identity $searchName -ErrorAction Stop
        Write-Log -Level Info -Message ("Pre-start status: {0}" -f $pre.Status)

        # If we created or updated the search definition this run, always start a fresh job
        $mustStart = $ensure.Created -or $ensure.Updated

        if ($mustStart) {
            Write-Log -Level Info -Message "Search was created/updated; forcing Start to run the latest query."
        }

        if ($mustStart -or $pre.Status -eq 'NotStarted') {
            if ($PSCmdlet.ShouldProcess(("Search '{0}'" -f $searchName), 'Start compliance search')) {
                Start-ComplianceSearch -Identity $searchName | Out-Null
                Write-Log -Level Info -Message ("Search started: {0}" -f $searchName)
            }
            else {
                Write-Log -Level Info -Message "Start skipped due to -WhatIf/-Confirm."
                return
            }
        }
        else {
            Write-Log -Level Info -Message ("Search '{0}' already started (Status={1}); skipping Start." -f $searchName, $pre.Status)
        }

        # ---- Wait until completion ----
        Write-Log -Level Info -Message ("Waiting for search '{0}' to complete (timeout={1}s, poll={2}s)..." -f $searchName, $timeoutSeconds, $pollSeconds)
        $searchObj = Wait-SearchCompletion -SearchName $searchName -CaseName $CaseName -TimeoutSeconds $timeoutSeconds -PollSeconds $pollSeconds -ErrorAction Stop

        if ($null -eq $searchObj) { throw "Search object not returned for '$searchName' (case '$CaseName')." }
        Write-Log -Level Ok -Message ("Search status: {0}; Items: {1}" -f $searchObj.Status, $searchObj.Items)

        if ($searchObj.Items -le 0) {
            throw "Search '$searchName' returned 0 mailbox items. Purge aborted."
        }

        # ---- Purge (HardDelete) ----
        if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $searchName), 'Submit Purview HardDelete purge')) {
            $null = Invoke-HardDelete -SearchName $searchName -CaseName $CaseName -Confirm:$confirm -ErrorAction Stop
            $purgeSubmitted = $true
            Write-Log -Level Info -Message ""
        }
        else {
            Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
        }

        # ---- Summary ----
        Write-Log -Level Ok -Message ("Summary: ticket='{0}' search='{1}' status='{2}' items={3} purgeSubmitted={4}" -f $ticketNorm, $searchName, $searchObj.Status, $searchObj.Items, $purgeSubmitted)
    }
    catch {
        Write-Log -Level Error -Message ("[ERROR] {0}" -f $_.Exception.Message)
    }
    finally {
        Write-Log -Level E-Info -Message "`nRemember to disconnect from Purview when finished using Disconnect-ExchangeOnline command..."
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzSE2duxbZTjUn
# hKxGbqpz3Gfivuzvt4M6ZcIa9IbMt6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDX
# W+RGgqWlxzw4xo1HTCLtMhM7n+FVH3zsad81uVMhjDANBgkqhkiG9w0BAQEFAASC
# AYB+ywq+R1weeIGmF//9wDETjH2QC//DcgBO+joHfE8RJ+Aet1fT1JUrrDRSwC4+
# cFowzg3bpWlO9dDGokvx2n/GwqQ57j/k+k2WvZFDxHp6BXQKMJ5/VpSpa01WQVKp
# +7Qnwiy7sVnd5jP11mKadUqJMJS8wPIGz2auLhLd+YpyqznyGJ3Jfyc4WwqE7iK1
# o1XUvs2jnfs8x79sXLDJEo19P74mq3M7a+TrE8uh7CslUswOmqhffPICoNpzzr3O
# mssSx2ZT50rPdwd4xnRCJdrI8H4bVDYknbcW+m/pYjv7qjM3Vo9O2bZJFZAS7nqx
# o8OhQeT8KhJujj5PatUwF9fKgUyci9sZ27+RuAKdrNF/7PNBm26uPDwnmiPlI+3I
# vMV7w/S7+D25j1t4O/Yu+bYcGSRBWIVHxvqMVRatpkn3Ziajc6sVAMYv5YALo8qS
# C/CGzE9E+sNt3YWQ6+KyRginNWty4SYD2UGtKJsW3WkMsi8EqOfCf2mL0wN2SnBG
# TJShggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDEwMjIxMzM5WjAvBgkqhkiG
# 9w0BCQQxIgQghOEUIozf0pAA7sPlMlJ8SvreZWZ5G8imO72jsF0aatEwDQYJKoZI
# hvcNAQEBBQAEggIAc6wyHdM3ZJEvys2d0aBHuEZHyQTvKSxdVg4rWJ5asp6eYu1b
# WlV2/Me9CjxVaAix2XA7d9JfMSZtEgjN2vhjTAoNo9tTohXWDh2FtbwS2d/EM7C9
# sR7qxwa+5luY3xYVb837Oo15UYPcMAYBw0m+DKETlUv27mPRComDZ/YSnII2Cv3+
# j3u5Azj5N3SJmf2anGdoZt9qaVzbb+0hEmHUbO1xISbLGeEbjA2ODOzKgv3NjyS3
# 1jDBJ4WxT+W1KKhdWK+/vHm+0Xvq6Cutm3CjEA2/n1rmLqFtTB9xL8gC93SzKnnj
# sp2Mt1CSPW3TQjHNpCEpgcN1gD3ih5zgYX1oGRjB/njKiFoJikUFI3Q3NRD6iWpn
# 3zScxpmDhrLVkKZSulLqRm2QENPyeL20JndUjM6WdQQX5kJqDJox8cNd753anr/I
# eKfYfEwV9r4Kv1z4HwH8L+f4sWf42TlP47sg59OqygEToILfBLMiUiIMyJDxiVmE
# lBiJ5F92qK6PgV0MifNLrj3IXC+xhfMq0okjIatq6mqL8Kh1IhUKDZ2l7MW1MrCU
# eAGbiy8uelMt2ByH+Cft5ZuStGBDCKz7LsKgU0kxUF372KUubkPtwyKGqx9OQqv4
# Y0dwFRVKA911U/hvK9OaXXgrvzJCoh7YPKkh9tjxi4dfRWunqlkzIb04nzs=
# SIG # End signature block
