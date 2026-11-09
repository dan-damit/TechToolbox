[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [Parameter(Mandatory = $true)]
    [string] $FullNameFilter,

    [Parameter(Mandatory = $true)]
    [string] $ResultPath,

    [switch] $DiscoveryOnly
)

$ErrorActionPreference = 'Stop'
$selectedPath = $null
$failureCode = $null
$pesterResult = $null
$selectedTests = @()
$resultPathFull = $null
$requiredPowerShellVersion = $null
$mode = if ($DiscoveryOnly) { 'DiscoveryOnly' } else { 'Execution' }
$discoveredCount = 0
$selectedCount = 0
$testsExecuted = 0
$failures = [System.Collections.Generic.List[object]]::new()
$failureEvidenceTruncated = $false
$maxFailureEntries = 10
$maxErrorsPerTest = 3
$maxFailureMessageCharacters = 1024
$maxFailureFieldCharacters = 256

function Get-TTPesterPropertyValue {
    param(
        [Parameter(Mandatory = $true)] $InputObject,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function ConvertTo-TTBoundedFailureText {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)] [int] $MaximumCharacters
    )
    if ($null -eq $Value) { return [pscustomobject]@{ Value = $null; Truncated = $false } }
    if ($Value -isnot [string]) { return [pscustomobject]@{ Value = $null; Truncated = $false } }
    $text = [string]$Value
    if ($text.Length -le $MaximumCharacters) { return [pscustomobject]@{ Value = $text; Truncated = $false } }
    return [pscustomobject]@{ Value = $text.Substring(0, $MaximumCharacters); Truncated = $true }
}

try {
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { throw 'ResultPath is required.' }
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $requestedResultPath = [IO.Path]::GetFullPath($ResultPath)
    $resultDirectory = [IO.Path]::GetDirectoryName($requestedResultPath)
    if ([string]::IsNullOrWhiteSpace($resultDirectory) -or !(Test-Path -LiteralPath $resultDirectory -PathType Container)) {
        throw 'ResultPath parent must be an existing test-owned temporary directory.'
    }
    $resolvedResultDirectory = (Resolve-Path -LiteralPath $resultDirectory).ProviderPath
    $resultDirectoryInfo = Get-Item -LiteralPath $resolvedResultDirectory -Force
    $resolvedResultPath = [IO.Path]::GetFullPath((Join-Path $resolvedResultDirectory ([IO.Path]::GetFileName($requestedResultPath))))
    if (!$resolvedResultPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        !$resultDirectoryInfo.Name.StartsWith('tt-pester-', [StringComparison]::OrdinalIgnoreCase) -or
        ($resultDirectoryInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [IO.Path]::GetExtension($resolvedResultPath) -ne '.json' -or
        (Test-Path -LiteralPath $resolvedResultPath -PathType Container)) {
        throw 'ResultPath must be a JSON file under the system temporary root.'
    }
    if (Test-Path -LiteralPath $resolvedResultPath -PathType Leaf) {
        $existingResult = Get-Item -LiteralPath $resolvedResultPath -Force
        if (($existingResult.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ResultPath cannot be a reparse point.' }
    }
    $resultPathFull = $resolvedResultPath

    $manifestPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'TechToolbox.psd1'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $versionMatch = [regex]::Match($manifestText, '(?m)^\s*PowerShellVersion\s*=\s*''([^'']+)''\s*(?:#.*)?$')
    if (!$versionMatch.Success) { throw 'The TechToolbox manifest PowerShellVersion requirement could not be read.' }
    $requiredPowerShellVersion = [version]$versionMatch.Groups[1].Value
    $currentPowerShellVersion = [version]$PSVersionTable.PSVersion
    $currentPowerShellEdition = [string]$PSVersionTable.PSEdition
    if ($currentPowerShellEdition -ne 'Core' -or $currentPowerShellVersion -lt $requiredPowerShellVersion) {
        $failureCode = 'UnsupportedPowerShellVersion'
        throw 'The current PowerShell host does not meet the TechToolbox module runtime requirement.'
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or !(Test-Path -LiteralPath $Path)) {
        $failureCode = 'InvalidPath'
        throw 'The supplied test path does not exist.'
    }
    $selectedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
    if (!(Test-Path -LiteralPath $selectedPath -PathType Leaf) -and !(Test-Path -LiteralPath $selectedPath -PathType Container)) {
        $failureCode = 'InvalidPath'
        throw 'The supplied test path is not a file or directory.'
    }

    try {
        Import-Module Pester -MinimumVersion 6.0.1 -MaximumVersion 6.0.1 -ErrorAction Stop | Out-Null
    }
    catch {
        $failureCode = 'PesterImportFailed'
        throw
    }

    try {
        if ($DiscoveryOnly) {
            $configuration = New-PesterConfiguration
            $configuration.Run.Path = $selectedPath
            $configuration.Run.SkipRun = $true
            $configuration.Run.PassThru = $true
            $configuration.Filter.FullName = @($FullNameFilter)
            $configuration.Output.Verbosity = 'None'
            $pesterResult = Invoke-Pester -Configuration $configuration
        }
        else {
            $pesterResult = Invoke-Pester -Path $selectedPath -FullNameFilter $FullNameFilter -PassThru -Output None -ErrorAction Stop
        }
    }
    catch {
        $failureCode = 'PesterExecutionFailed'
        throw
    }

    if ($null -eq $pesterResult) {
        $failureCode = 'PesterExecutionFailed'
        throw 'Pester did not return a structured result.'
    }

    $discoveredCount = [int]$pesterResult.TotalCount
    $testsProperty = $pesterResult.PSObject.Properties['Tests']
    if ($null -ne $testsProperty) {
        $pesterTests = @($testsProperty.Value)
        if ($DiscoveryOnly) {
            $allIdentities = @(
                foreach ($test in $pesterTests) {
                    if ($test.ExpandedPath) { [string]$test.ExpandedPath }
                }
            )
            $selectedTests = @($allIdentities | Where-Object { $_ -like $FullNameFilter } | Select-Object -Unique)
            $selectedCount = $selectedTests.Count
        }
        else {
            $selectedTests = @(
                foreach ($test in $pesterTests) {
                    $testResult = [string]$test.Result
                    if ($testResult -ne 'NotRun' -and $test.ExpandedPath) {
                        [string]$test.ExpandedPath
                    }
                }
            )
            $selectedCount = [int]$pesterResult.TotalCount - [int]$pesterResult.NotRunCount
            $testsExecuted = [int]$pesterResult.PassedCount + [int]$pesterResult.FailedCount + [int]$pesterResult.SkippedCount
            foreach ($test in $pesterTests) {
                if ([string]$test.Result -ne 'Failed') { continue }
                $rawErrors = Get-TTPesterPropertyValue -InputObject $test -Name 'ErrorRecord'
                if ($null -eq $rawErrors) { $rawErrors = Get-TTPesterPropertyValue -InputObject $test -Name 'ErrorRecords' }
                $testErrors = @($rawErrors | Where-Object { $null -ne $_ })
                if ($testErrors.Count -eq 0) {
                    $parentBlock = Get-TTPesterPropertyValue -InputObject $test -Name 'Block'
                    while ($null -ne $parentBlock -and $testErrors.Count -eq 0) {
                        $parentErrors = Get-TTPesterPropertyValue -InputObject $parentBlock -Name 'ErrorRecord'
                        $testErrors = @($parentErrors | Where-Object { $null -ne $_ })
                        $parentBlock = Get-TTPesterPropertyValue -InputObject $parentBlock -Name 'Parent'
                    }
                }
                if ($testErrors.Count -eq 0) { $testErrors = @($null) }
                $errorLimit = [Math]::Min($testErrors.Count, $maxErrorsPerTest)
                if ($testErrors.Count -gt $maxErrorsPerTest) { $failureEvidenceTruncated = $true }
                for ($errorIndex = 0; $errorIndex -lt $errorLimit; $errorIndex++) {
                    if ($failures.Count -ge $maxFailureEntries) { $failureEvidenceTruncated = $true; break }
                    $errorRecord = $testErrors[$errorIndex]
                    $exception = if ($null -ne $errorRecord) { Get-TTPesterPropertyValue -InputObject $errorRecord -Name 'Exception' } else { $null }
                    $invocation = if ($null -ne $errorRecord) { Get-TTPesterPropertyValue -InputObject $errorRecord -Name 'InvocationInfo' } else { $null }
                    $messageText = if ($null -ne $exception) { Get-TTPesterPropertyValue -InputObject $exception -Name 'Message' } else { $null }
                    $typeText = if ($null -ne $exception) { Get-TTPesterPropertyValue -InputObject $exception -Name 'FullName' } else { $null }
                    if ($null -eq $typeText -and $null -ne $exception) { $typeText = $exception.GetType().FullName }
                    $scriptBlock = Get-TTPesterPropertyValue -InputObject $test -Name 'ScriptBlock'
                    $fileText = if ($scriptBlock -is [scriptblock]) { $scriptBlock.File } else { $null }
                    if ($null -eq $fileText -and $null -ne $invocation) { $fileText = Get-TTPesterPropertyValue -InputObject $invocation -Name 'ScriptName' }
                    $lineValue = Get-TTPesterPropertyValue -InputObject $test -Name 'StartLine'
                    if ($null -eq $lineValue -and $null -ne $invocation) { $lineValue = Get-TTPesterPropertyValue -InputObject $invocation -Name 'ScriptLineNumber' }
                    $errorId = if ($null -ne $errorRecord) { Get-TTPesterPropertyValue -InputObject $errorRecord -Name 'FullyQualifiedErrorId' } else { $null }
                    $fullName = Get-TTPesterPropertyValue -InputObject $test -Name 'ExpandedPath'
                    if ($null -eq $fullName) { $fullName = Get-TTPesterPropertyValue -InputObject $test -Name 'FullName' }
                    if ($null -eq $fullName) { $fullName = Get-TTPesterPropertyValue -InputObject $test -Name 'ExpandedName' }
                    $testName = Get-TTPesterPropertyValue -InputObject $test -Name 'ExpandedName'
                    if ($null -eq $testName) { $testName = Get-TTPesterPropertyValue -InputObject $test -Name 'Name' }
                    $boundedMessage = ConvertTo-TTBoundedFailureText -Value $messageText -MaximumCharacters $maxFailureMessageCharacters
                    $boundedType = ConvertTo-TTBoundedFailureText -Value $typeText -MaximumCharacters $maxFailureFieldCharacters
                    $boundedName = ConvertTo-TTBoundedFailureText -Value $testName -MaximumCharacters $maxFailureFieldCharacters
                    $boundedFullName = ConvertTo-TTBoundedFailureText -Value $fullName -MaximumCharacters $maxFailureFieldCharacters
                    $boundedFile = ConvertTo-TTBoundedFailureText -Value $fileText -MaximumCharacters $maxFailureFieldCharacters
                    $boundedErrorId = ConvertTo-TTBoundedFailureText -Value $errorId -MaximumCharacters $maxFailureFieldCharacters
                    $entryTruncated = $boundedMessage.Truncated -or $boundedType.Truncated -or $boundedName.Truncated -or $boundedFullName.Truncated -or $boundedFile.Truncated -or $boundedErrorId.Truncated
                    if ($entryTruncated) { $failureEvidenceTruncated = $true }
                    $failures.Add([ordered]@{
                            FullName     = $boundedFullName.Value
                            Name         = $boundedName.Value
                            Result       = 'Failed'
                            ErrorType    = $boundedType.Value
                            ErrorMessage = $boundedMessage.Value
                            File         = $boundedFile.Value
                            Line         = if ($null -ne $lineValue -and [string]$lineValue -match '^\d+$') { [int]$lineValue } else { $null }
                            FailureKind  = $boundedErrorId.Value
                            Truncated    = $entryTruncated
                        })
                }
            }
        }
    }

    if ($DiscoveryOnly -and $selectedCount -eq 0) {
        $failureCode = 'NoTestsSelected'
    }
    elseif ($DiscoveryOnly -and $selectedCount -ne 1) {
        $failureCode = 'MultipleTestsSelected'
    }
    elseif (-not $DiscoveryOnly -and $selectedCount -le 0) {
        $failureCode = 'NoTestsSelected'
    }
}
catch {
    if (-not $failureCode) { $failureCode = 'PesterExecutionFailed' }
}

$hasResult = $null -ne $pesterResult
$agentAssemblyLoaded = [bool](@([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -like 'TechToolbox.Agent*' }).Count -gt 0)
$envelope = [ordered]@{
    Mode                      = $mode
    SelectedPath              = $selectedPath
    FullNameFilter            = $FullNameFilter
    DiscoveredCount           = $discoveredCount
    SelectedCount             = $selectedCount
    TotalCount                = if ($hasResult) { [int]$pesterResult.TotalCount } else { 0 }
    PassedCount               = if ($DiscoveryOnly) { 0 } elseif ($hasResult) { [int]$pesterResult.PassedCount } else { 0 }
    FailedCount               = if ($DiscoveryOnly) { 0 } elseif ($hasResult) { [int]$pesterResult.FailedCount } else { 0 }
    SkippedCount              = if ($DiscoveryOnly) { 0 } elseif ($hasResult) { [int]$pesterResult.SkippedCount } else { 0 }
    NotRunCount               = if ($hasResult) { [int]$pesterResult.NotRunCount } else { 0 }
    TestsExecuted             = $testsExecuted
    Duration                  = if ($hasResult -and $pesterResult.Duration -is [timespan]) { [double]$pesterResult.Duration.TotalMilliseconds } elseif ($hasResult) { [string]$pesterResult.Duration } else { $null }
    Result                    = if ($failureCode) { 'Failed' } elseif ($DiscoveryOnly) { 'Discovered' } elseif ($hasResult) { [string]$pesterResult.Result } else { 'Failed' }
    ProcessId                 = $PID
    SelectedTests             = @($selectedTests)
    Failures                  = if ($DiscoveryOnly) { , ([object[]]@()) } else { , ([object[]]$failures.ToArray()) }
    FailureEvidenceTruncated  = if ($DiscoveryOnly) { $false } else { $failureEvidenceTruncated }
    FailureCode               = $failureCode
    AgentAssemblyLoaded       = $agentAssemblyLoaded
    PowerShellVersion         = if ($PSVersionTable.PSVersion.ToString().Length -le 32) { $PSVersionTable.PSVersion.ToString() } else { $PSVersionTable.PSVersion.ToString().Substring(0, 32) }
    PowerShellEdition         = if ([string]$PSVersionTable.PSEdition -and ([string]$PSVersionTable.PSEdition).Length -le 16) { [string]$PSVersionTable.PSEdition } elseif ([string]$PSVersionTable.PSEdition) { ([string]$PSVersionTable.PSEdition).Substring(0, 16) } else { $null }
    RequiredPowerShellVersion = if ($null -ne $requiredPowerShellVersion) { $requiredPowerShellVersion.ToString() } else { $null }
}

$envelope.SchemaVersion = 1
$envelope.CompletedUtc = [DateTime]::UtcNow.ToString('o')
$runnerExitCode = if (-not $hasResult -or $failureCode -or (-not $DiscoveryOnly -and [int]$pesterResult.FailedCount -gt 0)) { 1 } else { 0 }
$envelope.RunnerExitCode = $runnerExitCode

if ([string]::IsNullOrWhiteSpace($resultPathFull)) {
    [Console]::Error.WriteLine('PESTER_RESULT_WRITE_FAILED')
    exit 2
}

$tempResultPath = $null
try {
    $json = ConvertTo-Json -InputObject $envelope -Compress -Depth 4
    $utf8 = [Text.UTF8Encoding]::new($false)
    $bytes = $utf8.GetBytes($json)
    $tempResultPath = Join-Path ([IO.Path]::GetDirectoryName($resultPathFull)) ('.' + [IO.Path]::GetFileName($resultPathFull) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.FileStream]::new($tempResultPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    $parsed = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($tempResultPath, $utf8)) -ErrorAction Stop
    foreach ($field in @('Mode', 'SelectedPath', 'FullNameFilter', 'DiscoveredCount', 'SelectedCount', 'TotalCount', 'PassedCount', 'FailedCount', 'SkippedCount', 'NotRunCount', 'TestsExecuted', 'Duration', 'Result', 'ProcessId', 'SelectedTests', 'Failures', 'FailureEvidenceTruncated', 'FailureCode', 'AgentAssemblyLoaded', 'PowerShellVersion', 'PowerShellEdition', 'RequiredPowerShellVersion', 'SchemaVersion', 'CompletedUtc', 'RunnerExitCode')) {
        if ($null -eq $parsed.PSObject.Properties[$field]) { throw "Result envelope is missing field: $field" }
    }

    if (Test-Path -LiteralPath $resultPathFull -PathType Leaf) {
        [IO.File]::Replace($tempResultPath, $resultPathFull, $null, $true)
    }
    else {
        [IO.File]::Move($tempResultPath, $resultPathFull)
    }
    $tempResultPath = $null

    $finalJson = [IO.File]::ReadAllText($resultPathFull, $utf8)
    $finalParsed = ConvertFrom-Json -InputObject $finalJson -ErrorAction Stop
    if ($finalParsed.RunnerExitCode -ne $runnerExitCode -or $finalParsed.SchemaVersion -ne 1) { throw 'Persisted result verification failed.' }
    [Console]::Out.WriteLine('PESTER_RESULT_WRITTEN ' + $resultPathFull)
}
catch {
    [Console]::Error.WriteLine('PESTER_RESULT_WRITE_FAILED: ' + $_.Exception.Message)
    if ($tempResultPath -and (Test-Path -LiteralPath $tempResultPath -PathType Leaf)) {
        Remove-Item -LiteralPath $tempResultPath -Force -ErrorAction SilentlyContinue
    }
    exit 2
}

exit $runnerExitCod
# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/8gbVnjzTXJ1x
# 5DJJKA6xISFt2dGJ65cV+nDSHY6kMKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCn
# ouC0fIgm2CNSMulprXu1HxVISzCwTzLUeX1Dz8ZtPzANBgkqhkiG9w0BAQEFAASC
# AYBV3RQBd9CnnNuqGpfVDqVbL9Fw5DJtHEBz3e/H4HH93zJuUcpPLaasIa4tog0U
# TD5V/kA+EeMgBbS3gQu9Xp+sj3ES1I1TMLPoO14ikSRZgcnKj4r9yhlgN3OrPSqW
# a12Jv3+RpWEQ1WI/nJ8/8fWWnhTJ0IlZKZp8vpMSXaRExn622p5zEfGfKOebw2C1
# 1l9TcRoI007jDHufvptNfaV/HpSn9XySLAVqJiRqeuc2fR2/CAJg5tftRBmtsjCy
# SNFg3LwfuVVfS4sieww4ZbzxwAFxfhOUuJoKPwrmi35YUzEK/zBkeNTMouBuWuny
# jak67epe08QqZ1MLy8gGYBvXHG3EUre0TgOv1FhzYe2FZAA0h2/7BSyi1JxE6HtU
# QHF2yt/r0FXKyMMN/qGgFlp1G/uax/g00jfEed+Pt508GLFPnL6SlFmQV1YytOqC
# HB5BmSlYPineJ+RB0CLYvsBY0IKjNbYLa2qKR5db3bAfH1ZlhIcO7nALZURX1+gl
# wsChggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTA5MDUyNjA0WjAvBgkqhkiG
# 9w0BCQQxIgQgOzQkygqxThY9uXlKA6cEK8L4bcHnuKFvFu7tFFNj5G0wDQYJKoZI
# hvcNAQEBBQAEggIAMpC9IFdaaAFpHuXxqd7Un/XSq+3Omgfpha9ISFmqasF5jqmr
# qemIl7gi3fvLcnVfvTOB4Fd74G81F4i3bbAancjYc+/tQ0u0TeveKnjEFi+NVp9N
# JzpP2GnZ2eP7SiBAboOIrtPRsA9zd1itcSco3dTGXyiWuXfecVNadjlsc979jWFw
# Xtdn+oZ1/Z7+eOGxayRHdJ0M466P4Y8+7+dBwgw4jfIxcBXOiWjvLH6zm57ZioU4
# LT2TZp+aBFNwel8gVOLM0zuT0Q9GKM3Q+mtSGgCtoO0edjETWbDADAjHKrH/g/Sn
# lAYvddu/0+p9J/OmM8ysagysEKB7O064xUh4tBfg1Hsg2UucO17i3lCXrne1sdeZ
# rr8AeX+7xN+m92WsuDFQUWKvVOpZY9PUiozouuZPZDRyjLNaab0MNT2xB7WjUwTY
# GZkN/wuv7sPSUhzS2Gv2rTrz/OquIdkr+V0WY7tNziCBixN/YMQAJ+E10MThhYPu
# 4Uc1iuyfrlubFqgPWUiEm7taqsIMnvYKJtJflDMC20CbupvpfxOuQEsv2L7iRDwG
# 6/Y9/O/Td/oGvCIm9ZSD+/ufA9pkiKpWnEmMZwZcFP3WiEfXVWNGvdrQMbXrcHxj
# WdUDSU/QDlcAW4AYTovtJ806LfvcJcdfCQKAqu2WSXnVVHu7dZfZ42QufT0=
# SIG # End signature block
