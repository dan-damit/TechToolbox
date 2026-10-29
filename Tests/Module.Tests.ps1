Describe "TechToolbox Module" {
    BeforeAll {
        Import-Module -Name "$PSScriptRoot/../TechToolbox.psd1" -Force -ErrorAction Stop
    }

    Context "Module Load" {
        It "Should load without errors" {
            { Import-Module -Name "$PSScriptRoot/../TechToolbox.psd1" -Force } | Should -Not -Throw
        }

        It "Should be available in Get-Module" {
            $module = Get-Module -Name TechToolbox
            $module | Should -Not -BeNullOrEmpty
        }

        It "Should default agent filesystem and allowed-path roots to LocalDataRoot when no env override is set" {
            $moduleRoot = $env:TT_ModuleRoot
            $moduleRoot | Should -Not -BeNullOrEmpty

            $localDataRoot = Join-Path $env:LOCALAPPDATA 'TechToolbox'
            $agentFilesystemRoot = $env:TT_AGENT_FILESYSTEM_ROOT
            $agentAllowedRoots = $env:TT_AGENT_ALLOWED_PATH_ROOTS

            $agentFilesystemRoot | Should -Be $localDataRoot
            $agentAllowedRoots | Should -Not -BeNullOrEmpty
            ($agentAllowedRoots -split [System.IO.Path]::PathSeparator) | Should -Contain $localDataRoot
            ($agentAllowedRoots -split [System.IO.Path]::PathSeparator) | Should -Not -Contain $moduleRoot
        }

        It "Should honor a callsite WriteDirectory override for filesystem access" {
            InModuleScope TechToolbox {
                $result = Resolve-TTAgentWriteDirectorySettings -WriteDirectory @('C:\Temp\Alpha', 'D:\Temp\Beta')
                $result.FilesystemRoot | Should -Be 'C:\Temp\Alpha'
                $result.AllowedRoots | Should -Contain 'C:\Temp\Alpha'
                $result.AllowedRoots | Should -Contain 'D:\Temp\Beta'
            }
        }

        It "Should resolve runtime paths beneath LocalAppData and packaged paths beneath the executing module" {
            InModuleScope TechToolbox {
                $paths = Test-TTPathRoots
                $expectedLocalDataRoot = Join-Path $env:LOCALAPPDATA 'TechToolbox'

                $paths.ModuleRoot | Should -Be $script:TT.ModuleRoot
                $paths.ModuleRoot | Should -Be $ExecutionContext.SessionState.Module.ModuleBase
                $paths.LocalDataRoot | Should -Be $expectedLocalDataRoot
                $paths.ConfigDefaultsPath | Should -Be (Join-Path $paths.ModuleRoot 'Config\config.json')
                $paths.ConfigPath | Should -Be (Join-Path $paths.LocalDataRoot 'Config\config.json')
                $paths.SecretsTemplatePath | Should -Be (Join-Path $paths.ModuleRoot 'Config\config.secrets.json')
                $paths.SecretsPath | Should -Be (Join-Path $paths.LocalDataRoot 'Config\config.secrets.json')
                $paths.LogsRoot | Should -Be (Join-Path $paths.LocalDataRoot 'Logs')
                $paths.ExportsRoot | Should -Be (Join-Path $paths.LocalDataRoot 'Exports')
                $paths.ConfigPathsLogs | Should -Be $paths.LogsRoot
                $script:cfg.settings.systemUptime.exportPath | Should -Be (Join-Path $paths.ExportsRoot 'SystemUptime')
                $paths.SecretsPathUnderLocalDataRoot | Should -BeTrue
                $paths.LogsRootUnderLocalDataRoot | Should -BeTrue
                $paths.ExportsRootUnderLocalDataRoot | Should -BeTrue
                $paths.ConfigDefaultsUnderModuleRoot | Should -BeTrue
                $paths.ConfigPathUnderLocalDataRoot | Should -BeTrue
                $paths.SecretsTemplateUnderModuleRoot | Should -BeTrue
                $paths.LocalDataRootExists | Should -BeTrue
                $paths.SecretsPathExists | Should -BeTrue
                $paths.LogsRootExists | Should -BeTrue
                $paths.ExportsRootExists | Should -BeTrue
            }
        }

        It "Should merge LocalDataRoot user settings over packaged config defaults" {
            InModuleScope TechToolbox {
                $userConfigPath = Join-Path ([System.IO.Path]::GetTempPath()) ("config.user.{0}.json" -f [System.Guid]::NewGuid().ToString('N'))
                try {
                    @{
                        schemaVersion = 1
                        settings      = @{
                            oneTimeReboot = @{ at = '02:30' }
                        }
                    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $userConfigPath -Encoding UTF8

                    $config = Get-TechToolboxConfig -Path $script:TT.ConfigDefaultsPath -UserConfigPath $userConfigPath

                    $config.settings.oneTimeReboot.at | Should -Be '02:30'
                    $config.settings.oneTimeReboot.taskNamePrefix | Should -Be 'TT_OneTimeReboot'
                    (Test-Path -LiteralPath $script:TT.ConfigDefaultsPath -PathType Leaf) | Should -BeTrue
                }
                finally {
                    Remove-Item -LiteralPath $userConfigPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should merge user overrides when packaged defaults contain null values" {
            InModuleScope TechToolbox {
                $userConfigPath = Join-Path ([System.IO.Path]::GetTempPath()) ("config.user.null-merge.{0}.json" -f [System.Guid]::NewGuid().ToString('N'))
                try {
                    @{
                        schemaVersion = 1
                        settings      = @{
                            browserCleanup = @{
                                defaultProfiles = @('Default', 'Profile 1')
                            }
                        }
                    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $userConfigPath -Encoding UTF8

                    $config = Get-TechToolboxConfig -Path $script:TT.ConfigDefaultsPath -UserConfigPath $userConfigPath

                    $config.settings.browserCleanup.defaultProfiles | Should -Be @('Default', 'Profile 1')
                }
                finally {
                    Remove-Item -LiteralPath $userConfigPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should save first-run effective config only to LocalDataRoot config path" {
            InModuleScope TechToolbox {
                $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tt-config-save.{0}" -f [System.Guid]::NewGuid().ToString('N'))
                $userConfigPath = Join-Path $tempRoot 'Config\config.json'
                $previousConfigPath = $script:ConfigPath
                $previousConfig = $script:cfg
                $script:ConfigPath = $userConfigPath
                $script:cfg = Get-TechToolboxConfig -Path $script:TT.ConfigDefaultsPath -UserConfigPath $userConfigPath

                try {
                    Save-Config

                    (Test-Path -LiteralPath $userConfigPath -PathType Leaf) | Should -BeTrue
                    $savedConfig = Get-Content -LiteralPath $userConfigPath -Raw | ConvertFrom-Json -AsHashtable
                    $savedConfig.settings.oneTimeReboot.taskNamePrefix | Should -Be 'TT_OneTimeReboot'
                    (Test-Path -LiteralPath $script:TT.ConfigDefaultsPath -PathType Leaf) | Should -BeTrue
                }
                finally {
                    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
                    $script:ConfigPath = $previousConfigPath
                    $script:cfg = $previousConfig
                }
            }
        }

        It "Should leave existing LocalDataRoot secrets untouched on reimport" {
            InModuleScope TechToolbox {
                $secretsPath = $script:TT.SecretsPath
                $beforeHash = (Get-FileHash -LiteralPath $secretsPath -Algorithm SHA256).Hash

                Import-Module -Name (Join-Path $script:TT.ModuleRoot 'TechToolbox.psd1') -Force -ErrorAction Stop

                $afterHash = (Get-FileHash -LiteralPath $secretsPath -Algorithm SHA256).Hash
                $afterHash | Should -Be $beforeHash
            }
        }
    }

    Context "Exported Functions" {
        BeforeAll {
            $expectedFunctions = @(
                'Clear-BrowserProfileData',
                'Copy-Directory',
                'Disable-User',
                'Enable-NetFx3',
                'Export-ToolboxFunctions',
                'Find-LargeFiles',
                'Get-AllUsers',
                'Get-AuditSharedMailboxDeletions',
                'Get-AutodiscoverXmlInteractive',
                'Get-BatteryHealth',
                'Get-CUCredentialManagerContents',
                'Get-DomainAdminCredential',
                'Get-ErrorEvents',
                'Get-FilesUsingKeywords',
                'Get-InstalledPrinters',
                'Get-LocalAdminMembers',
                'Get-MessageTrace',
                'Get-NewPSRemoteSession',
                'Get-PDQDiagLogs',
                'Get-RemoteInstalledSoftware',
                'Get-SharedMailboxPermissions',
                'Get-SystemSnapshot',
                'Get-SystemTrustDiagnostic',
                'Get-SystemUptime',
                'Get-TechToolboxConfig',
                'Get-ToolboxHelp',
                'Get-WindowsProductKey',
                'Initialize-TTWordList',
                'Install-TechAgentRuntime',
                'Invoke-AADSyncRemote',
                'Invoke-DownloadsCleanup',
                'Invoke-PurviewPurge',
                'Invoke-RestartService',
                'Invoke-SubnetScan',
                'Invoke-SystemRepair',
                'Invoke-TechAgent',
                'Get-TechAgentQualitySummary',
                'New-OnPremUserFromTemplate',
                'Remove-EpicorEdgeAgent',
                'Remove-Printers',
                'Reset-ADPassword',
                'Reset-WindowsUpdateComponents',
                'Search-User',
                'Set-EmailAlias',
                'Set-OneTimeReboot',
                'Set-PageFileSize',
                'Set-ProxyAddress',
                'Set-TechAgentApiKey',
                'Set-TechAgentMcpApiKey',
                'Set-TechAgentMcpOAuthCallback',
                'Set-TechAgentSearchWebApiKey',
                'Start-DnsQueryLogger',
                'Start-NewPSRemoteSession',
                'Start-PDQDiagLocalElevated',
                'Stop-PSRemoteSession',
                'Test-MailHeaderAuth',
                'Test-PathAs',
                'Test-TechAgentLocalMcpAdapter',
                'Test-TechAgentMcpConnection',
                'Test-TechAgentProvider',
                'Test-TTPathRoots',
                'Unlock-User',
                'Use-TechAgentTaskTemplate',
                'Watch-ISPConnection'
            )
        }

        It "Should export all expected functions" {
            $exportedFunctions = (Get-Command -Module TechToolbox).Name
            foreach ($func in $expectedFunctions) {
                $exportedFunctions | Should -Contain $func
            }
        }

        It "Should not export unexpected functions" {
            $exportedFunctions = (Get-Command -Module TechToolbox).Name
            $unexpectedFunctions = @()
            foreach ($func in $exportedFunctions) {
                if ($func -notin $expectedFunctions) {
                    $unexpectedFunctions += $func
                }
            }
            $unexpectedFunctions | Should -BeNullOrEmpty
        }
    }

    Context "Domain admin credential secret shape" {
        It "does not retain the deprecated legacy plaintext username/password keys" {
            InModuleScope TechToolbox {
                $tempSecretsPath = Join-Path ([System.IO.Path]::GetTempPath()) ("config.secrets.{0}.json" -f [System.Guid]::NewGuid().ToString('N'))
                @{
                    passwords = @{
                        domainAdminCred = @{
                            usernameEncrypted = ''
                            passwordEncrypted = ''
                            username          = 'legacy-user'
                            password          = 'legacy-pass'
                        }
                    }
                } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tempSecretsPath -Encoding UTF8

                Mock Get-SecretsPath { $tempSecretsPath }

                $secrets = Read-Secrets

                $secrets.passwords.domainAdminCred.ContainsKey('username') | Should -BeFalse
                $secrets.passwords.domainAdminCred.ContainsKey('password') | Should -BeFalse
            }
        }
    }
}
# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBH/bbf2U9XxCYF
# ixDxDEzljOS+jP7L3GZIevvbZOSTR6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC/
# 8nvUdxDRKFcS3dxFAajT0HQqFNH68GmZ+MZwc/qrYDANBgkqhkiG9w0BAQEFAASC
# AYC65x+yjZIiEVBcCppD6bDnctrOfA8qoDuHNVGQTi2K5RnP4dUyVqPJCdnIXqv4
# BIDCNB4NesUzzpfeSFRNLVRilFVcho5mQAgRRkZMkPesvOIKQ5DNdQFHQX55v8ew
# 8nLq3njfFPxFLjfIuwNR4klGmVtz69ONZSnwrQ0GRaeo1MV0hXBGXs/VMw0z4yEC
# UJeuqMPGYG4dTfXBGVYupeblj2e8LjXpPQ7Fqb3Kf/KEOHsPgvxIHama8XTreVMR
# CPN6ZrQAxsWncZcedrQigjae83jzopzW6GxpR+P53H8GKFaaE+TKPP+0OLbQujVO
# rOHeRzBmPDdfCkPlIPQEYDKeBE2UPRYlq1xFkHwcOeMkObh+mtptFcvie4OLLLFB
# 2iyajsrusGtvWdJuk1eb1/pyeRTuwChnwXvklNcuFAusJ8namDLSy7cMiOOKkj/D
# QISXWW2oqSLEMcir1jeovlLIw8CoO/1woOR+yh8A1+Myotc+Z21dPJCDouHOiW8K
# kBOhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDI5MTY1NzUwWjAvBgkqhkiG
# 9w0BCQQxIgQgDG1fWRiE3pHwAmxbqoTZs0lTfsi15I4CxirFfFiITWwwDQYJKoZI
# hvcNAQEBBQAEggIAAllmStQoPj8dMb7Z0aAM7kurW9EmrUnTYFhcoA241LoDgbf2
# fV+qWbDLTz8C8uw8+DxD8rPN6JIfm9WmQbGCorLrPY/BLxDXhgeo4tauc9AIFzsk
# VQh2sCTXqaIXZurCSdm2GfNHv8/RvDLU2anlZWyt2tY+J37KdfxAYyySRX18zQb/
# gFkFjZ69SQeElvJMNrlnr5ZF/qdVGUk/LxkiZQ+Vz1pyhZiVakmXMG0jgk2D8AWm
# 2AtLRtjPZTuf9XW+cjKx0UFHK/p9ZxyH3HP1FQO5aKSNvPcDfmGR53UqNMvVtCmU
# Bla0h5pe+kFZR5TpLnwCuK95WR7J1liG5TuYlo8uOD2gndbP6PezaRzO5MJSzz8p
# +/Q4RU5VP5KP/itakoZzfW1PIiyiS8+owA/WiVOY3yp/vMDFwBqOXAWT/rq9iGvQ
# p2Jmk8wlr0zW1aXSKkbrOY3sIqKtguviMNagpglNpV0+od5F7+TbH6iCvJiPu8by
# NMnf6I5sfvkQBQMFy0HpdhuaKozf3XZDLdPBp5njxDJxRA6QL+v2uBe2G77w8xbn
# JyhGno8qLbiexen7z+UYQfUoSJomRCFdnuSn0+m/jeL/QdO0UCEI4qaEE0MK1uLj
# ZJawwdb8pjdGRfIlEf7R77mFYZPdddYUKx02pjMAeON2C7ZgnctnmtFrBmg=
# SIG # End signature block
