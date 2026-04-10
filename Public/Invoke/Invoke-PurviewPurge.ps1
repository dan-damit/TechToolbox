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
    $CaseName = 'Content Search'

    # Ensure these exist for finally/catch paths
    $exo = $null
    $ticketNorm = $null
    $purgeSubmitted = $false

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

        # ----- Ticket normalize + confirmation/fix loop (interactive) -----
        while ($true) {
            $raw = ($Ticket ?? '').Trim()

            if ([string]::IsNullOrWhiteSpace($raw)) {
                $Ticket = Read-Host "Enter ticket in format #INC-<integer> (or 'q' to cancel)"
                if ($Ticket -match '^(?i)(q|quit|exit)$') { throw "User cancelled: ticket entry aborted." }
                continue
            }

            # Normalize: uppercase, ensure leading '#'
            $ticketNorm = $raw.ToUpper()
            if ($ticketNorm -notmatch '^#') { $ticketNorm = "#$ticketNorm" }

            # Validate after normalization
            if ($ticketNorm -notmatch '^#INC-\d+$') {
                Write-Log -Level Warn -Message "Ticket must be '#INC-<integer>' (example: #INC-151695)."
                $Ticket = Read-Host "Re-enter ticket (or 'q' to cancel)"
                if ($Ticket -match '^(?i)(q|quit|exit)$') { throw "User cancelled: ticket entry aborted." }
                continue
            }

            # Confirm
            $resp = Read-Host "Ticket is '$ticketNorm'. Is this correct? (Y/n/q)"
            if ($resp -match '^(?i)(q|quit|exit)$') { throw "User cancelled: ticket confirmation aborted." }

            if ($resp -match '^(?i)n(o)?$') {
                $Ticket = Read-Host "Enter the correct ticket (or 'q' to cancel)"
                if ($Ticket -match '^(?i)(q|quit|exit)$') { throw "User cancelled: ticket entry aborted." }
                continue
            }

            # Default accept on Enter or 'y'
            Write-Log -Level Info -Message ("Using ticket: {0}" -f $ticketNorm)
            break
        }

        # ---- Module & session ----
        Import-ExchangeOnlineModule -ErrorAction Stop
        Connect-Purview -UserPrincipalName $UserPrincipalName -ErrorAction Stop

        # ----- Query prompt + validation/normalization -----
        $promptQuery = $defaults.promptForContentMatchQuery ?? $true
        $UseExistingQuery = $false
        $UpdateScope = $false
        $AllowQueryWeaken = $false

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

        # If we didn’t reuse an existing query, run the normal prompt + lint loop
        if (-not $UseExistingQuery) {

            while ($true) {

                if ([string]::IsNullOrWhiteSpace($ContentMatchQuery)) {
                    if ($promptQuery) {
                        $ContentMatchQuery = Read-Host "Enter ContentMatchQuery (or type 'q' to cancel) (e.g., from:(""pm-bounces.broobe.*"" OR ""broobe.*"") AND subject:""Aligned Assets"")"
                    }
                    else {
                        throw "ContentMatchQuery is required but prompting is disabled by config."
                    }
                }

                $ContentMatchQuery = $ContentMatchQuery.Trim()

                if ($ContentMatchQuery -match '^(?i)(q|quit|exit)$') {
                    throw "User cancelled: ContentMatchQuery entry aborted."
                }

                $warningsRef = [ref] $null
                $isValid = Test-ContentMatchQueryLint -Query $ContentMatchQuery -Warnings $warningsRef

                if (-not $isValid) {
                    $warnings = $warningsRef.Value
                    if ($warnings) {
                        foreach ($w in $warnings) {
                            Write-Log -Level Warn -Message $w
                        }
                    }
                    Write-Log -Level Warn -Message "KQL must be corrected before continuing."
                    $ContentMatchQuery = $null
                    continue
                }

                Write-Log -Level Info -Message ("Final ContentMatchQuery: {0}" -f $ContentMatchQuery)
                break
            }
        }

        # ---- Build search name ----
        $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $searchName = "{0}" -f $ticketNorm
        $desc = "Possible Phishing/Spam/Marketing - $ticketNorm - $ts"

        Write-Log -Level Info -Message ("Ensuring mailbox-only Compliance Search '{0}' exists in case '{1}'..." -f $searchName, $CaseName)

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
            Write-Log -Level Ok -Message ("[Done] Purview HardDelete purge submitted for '{0}' in case '{1}'." -f $searchName, $CaseName)
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
        Write-Log -Level Warn -Message "Remember to disconnect from Purview when finished using Disconnect-ExchangeOnline command..."
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDn3PQvsL3phtxW
# US9gI3RYmEIEw4/PuIuC/Ct8raZ+GqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDQW+wppAF3
# rsM02ZQmdMElcVoWAr0wxheeROfRiGncKjANBgkqhkiG9w0BAQEFAASCAgA3ccqf
# U5rxVmHgEBCBhaMn0BkFiu48n8/FB9hVv9O8wlbYTr40znCAHFpxax4nK+yLn8si
# qC68kfHo38WEHSVcmll0KgDGSy+4M2y0wgi2FLgLG8SbsXsS4h/aHt4OESKg/Ysx
# +QsjML+Do8zT6R3yNLspaobRdiIUfBEXywpVQHqbOi/ZTS6hSqyWPibMAE7zZ5rp
# GIOD/6+OLua/vcdp+YFrQmhbLrMVXbZPXrImRwF3sXZgkHQ+4mqwtwCi6AnoUUZP
# JUrw85rccBdC/S6nUQUnxjTOz1GnDJWq9/TRnVNl33wGICVSyQeK8izZGIhabN8o
# 9GcTMRILXgyFjKdcMhu15/pKB37fvhzD5I1i0PKinLjRbRom0ahNY+jAI+Y/yri4
# MnrFYfZhMetPwiya4H/huFt39YdlnyjaeVOAsJVrflv388VZZevgNAKYBOH9EIfD
# Bp+p2eJW6KJ+xRM8jvTnS6pHOGwuNl/WLSIh+9iD2u3Z7wzJ3NTQVeGmoxyfhZbq
# poOD/hbPq7vXMJ8FFtSnu7ANiVCI5jCBH7F0aJxvtNA8nooLOaelHifQd6LJ6t4J
# 7R83xWz7RSsImSNB+kPinjTty9wlxJKgeZ6eqGGr99J1xsgTw2y/QXRd74VmBjv4
# /iZf66cJvfuWJS4lrKSvoQ/PChD8zcjU8nT9iKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MTAxNTE4MDdaMC8GCSqGSIb3DQEJBDEiBCCX/8ZGsnpXDi0hXXHC
# 5G9GDLtj0VXJz9G9ZF3qcD95+TANBgkqhkiG9w0BAQEFAASCAgC7Hd84DLtBAV21
# e+1pOaB2elzvRETgVntVxHgMgzEhcWXZq2gu7JGpqByD+Rwchvh5W/oLbH2pBYoL
# j5AWGvMLpAdTX+qEsqJYfqlNtu6hqexgANk/ctda+GjHCTWvktuc26mMCiV5vmgr
# mXBE4/UthImrAYe5f1Ve2x+NV6a05aBcrlifISbaCHpJy7GhcXohoihA/hHO1xYb
# auqlgpEuP+0KCfLmuV8Ui8nOGywyehwk6HI4r7kxAt5I3zWR841q6tUU7z4ivGkp
# AXuZhqM5wkyUqtzwjn6wo1O6nan/ASsElZOLLMFJbt25mQ67aJ8JEJwPQpXDxw6b
# sYAKi8+D0XkjluNQjqJYWAwiKfAzKctwjigBRf4ZyO+2029uMhcXwH1ZGSd3+zZf
# YHZyaIFSgQLMDK2VPS9kCtS8X45leZgik6xTLUL8lMT6WyZCZpa72LqrS++IFI51
# FGFyphPIbaCfm/nzYlaHj+Q0bgu7BpI1lWqS/OzVRY720cpeF/RuQmAa0hcEy1vX
# lqmLYLGHTb8ffdqFtDFp1TFEli2XW5IpdNJi7z8UOmyEMI8yKVZO1TwuQQ9C8bV3
# jsLCwiwzN4/8TKZ1v9gBazAg+jODdWVcPm9pOv8Kh86f8fziULjDyL/C1rGSInH6
# s24ggha1XWfNxetq97i8GeqzS1tXzg==
# SIG # End signature block
