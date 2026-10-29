Describe 'Config baseline persistence' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\Private\Loader\ConfigPersistence.ps1')
        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tt-config-tests-' + [guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($script:TestRoot)
        $script:Defaults = Join-Path $script:TestRoot 'defaults.json'
        $script:Config = Join-Path $script:TestRoot 'Config\config.json'
        $script:Baseline = Join-Path $script:TestRoot 'Config\config.defaults.json'
        $script:BaseDefaults = @{ schemaVersion = 1; settings = @{ inner = @{ inherited = 'old'; customized = 'default' }; unchanged = 1 } }
        $script:BaseDefaults | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:Defaults -Encoding utf8
    }
    AfterAll { Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue }

    It 'creates complete config and baseline on clean install and merges defaults on upgrade' {
        Initialize-TTConfigPersistence $script:Defaults $script:Config
        (Read-TTConfigJsonRoot $script:Config).settings.inner.inherited | Should Be 'old'
        (Test-Path $script:Baseline) | Should Be $true
        $user = Read-TTConfigJsonRoot $script:Config
        $user.settings.inner.customized = 'user choice'
        $user.settings.inner.inherited = 'old'
        $user | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:Config -Encoding utf8
        $nextDefaults = @{ schemaVersion = 1; settings = @{ inner = @{ inherited = 'new'; customized = 'new-default'; added = 'new-key' }; unchanged = 2 } }
        $nextDefaults | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:Defaults -Encoding utf8
        Initialize-TTConfigPersistence $script:Defaults $script:Config
        $merged = Read-TTConfigJsonRoot $script:Config
        $merged.settings.inner.inherited | Should Be 'new'
        $merged.settings.inner.customized | Should Be 'user choice'
        $merged.settings.inner.added | Should Be 'new-key'
        $merged.settings.unchanged | Should Be 2
    }

    It 'preserves every legacy materialized value on first migration and establishes baseline' {
        $root = Join-Path $script:TestRoot 'migration'
        $defaults = Join-Path $root 'defaults.json'; $config = Join-Path $root 'Config\config.json'
        [void][System.IO.Directory]::CreateDirectory((Split-Path $config))
        @{ settings = @{ inherited = 'old-value'; nested = @{ keep = 9 } }; custom = 'intentional' } | ConvertTo-Json -Depth 20 | Set-Content $config -Encoding utf8
        @{ settings = @{ inherited = 'new-value'; nested = @{ keep = 0; added = 1 } }; newTop = $true } | ConvertTo-Json -Depth 20 | Set-Content $defaults -Encoding utf8
        $before = Get-Content $config -Raw
        Initialize-TTConfigPersistence $defaults $config
        $migrated = Read-TTConfigJsonRoot $config
        $migrated.settings.inherited | Should Be 'old-value'
        $migrated.settings.nested.keep | Should Be 9
        $migrated.custom | Should Be 'intentional'
        $migrated.newTop | Should BeNullOrEmpty
        (Test-Path (Join-Path (Split-Path $config) 'config.defaults.json')) | Should Be $true
    }

    It 'rejects null scalar and array roots' {
        foreach ($bad in @('null', '7', '[]', '"text"')) {
            $path = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N') + '.json')
            [System.IO.File]::WriteAllText($path, $bad)
            $threw = $false; try { Read-TTConfigJsonRoot $path | Out-Null } catch { $threw = $true }; $threw | Should Be $true
        }
    }

    It 'rejects malformed roots before changing the original mutable file' {
        $config = Join-Path $script:TestRoot 'bad-root\Config\config.json'
        $defaults = Join-Path (Split-Path (Split-Path $config)) 'defaults.json'
        [void][System.IO.Directory]::CreateDirectory((Split-Path $config))
        @{ settings = @{} } | ConvertTo-Json | Set-Content $defaults -Encoding utf8
        [System.IO.File]::WriteAllText($config, '[]')
        $threw = $false; try { Initialize-TTConfigPersistence $defaults $config } catch { $threw = $true }; $threw | Should Be $true
        (Get-Content $config -Raw | ConvertFrom-Json -AsHashtable).Count | Should Be 0
    }

    It 'preserves the existing config parseability when atomic replacement fails' {
        $path = Join-Path $script:TestRoot 'atomic.json'
        [System.IO.File]::WriteAllText($path, '{"good":true}')
        $lockStream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        try { $threw = $false; try { Write-TTConfigAtomic -Path $path -Value @{ bad = [System.Object]::new() } } catch { $threw = $true }; $threw | Should Be $true }
        finally { $lockStream.Dispose() }
        (Read-TTConfigJsonRoot $path).good | Should Be $true
    }

    It 'keeps legacy secret fields out and writes the raw defaults baseline without resolved paths' {
        $root = Join-Path $script:TestRoot 'secrets'
        $defaults = Join-Path $root 'defaults.json'; $config = Join-Path $root 'Config\config.json'
        [void][System.IO.Directory]::CreateDirectory((Split-Path $config))
        @{ settings = @{ passwords = @{ domainAdminCred = @{ username = 'secret'; password = 'secret'; passwordEncrypted = 'secret' } }; agent = @{ apiKeyEncrypted = 'secret'; clientSecret = 'secret' }; path = '%TT_ModuleRoot%\data' } } | ConvertTo-Json -Depth 20 | Set-Content $defaults -Encoding utf8
        Initialize-TTConfigPersistence $defaults $config
        $persisted = Read-TTConfigJsonRoot $config
        $persisted.settings.passwords.domainAdminCred.Contains('password') | Should Be $false
        $persisted.settings.passwords.domainAdminCred.Contains('passwordEncrypted') | Should Be $false
        $persisted.settings.agent.Contains('apiKeyEncrypted') | Should Be $false
        $persisted.settings.agent.Contains('clientSecret') | Should Be $false
        $persisted.settings.path | Should Be '%TT_ModuleRoot%\data'
        (Get-Content -LiteralPath (Join-Path (Split-Path $config) 'config.defaults.json') -Raw) | Should Match '%TT_ModuleRoot%'
    }
    It 'handles missing and malformed nested secret branches under StrictMode' {
        Set-StrictMode -Version Latest
        foreach ($settings in @(@{}, @{ passwords = $null }, @{ passwords = @{ domainAdminCred = 'scalar' } }, @{ passwords = @{ domainAdminCred = @{ username = 'legacy'; password = 'legacy' } } })) {
            $config = @{ settings = $settings }
            { Remove-TTConfigLegacySecrets -Config $config } | Should Not Throw
            if ($settings.Contains('passwords') -and $settings['passwords'] -is [System.Collections.IDictionary] -and $settings['passwords'].Contains('domainAdminCred') -and $settings['passwords']['domainAdminCred'] -is [System.Collections.IDictionary]) {
                $settings['passwords']['domainAdminCred'].Contains('username') | Should Be $false
                $settings['passwords']['domainAdminCred'].Contains('password') | Should Be $false
            }
        }
        Set-StrictMode -Off
    }

    It 'serializes concurrent initializers across processes' {
        $root = Join-Path $script:TestRoot 'concurrent'
        $defaults = Join-Path $root 'defaults.json'; $config = Join-Path $root 'Config\config.json'
        [void][System.IO.Directory]::CreateDirectory((Split-Path $config))
        @{ settings = @{ value = 'default' } } | ConvertTo-Json -Depth 10 | Set-Content $defaults -Encoding utf8
        $helper = Join-Path $PSScriptRoot '..\Private\Loader\ConfigPersistence.ps1'
        $jobs = 1..2 | ForEach-Object {
            Start-Job -ArgumentList $helper, $defaults, $config -ScriptBlock {
                param($helperPath, $defaultsPath, $configPath)
                . $helperPath
                Initialize-TTConfigPersistence -DefaultsPath $defaultsPath -ConfigPath $configPath
            }
        }
        try {
            $jobs | Wait-Job | Out-Null
            foreach ($job in $jobs) { $job.State | Should Be 'Completed'; Receive-Job $job -ErrorAction Stop | Out-Null }
            (Read-TTConfigJsonRoot $config).settings.value | Should Be 'default'
            (Read-TTConfigJsonRoot (Join-Path (Split-Path $config) 'config.defaults.json')).settings.value | Should Be 'default'
        }
        finally { $jobs | Remove-Job -Force -ErrorAction SilentlyContinue }
    }

    It 'does not modify packaged defaults and uses raw token values in baseline persistence' {
        $root = Join-Path $script:TestRoot 'integrity'
        $defaults = Join-Path $root 'defaults.json'; $config = Join-Path $root 'Config\config.json'
        [void][System.IO.Directory]::CreateDirectory((Split-Path $config))
        @{ settings = @{ path = '%TT_ModuleRoot%\worker'; value = 'default' } } | ConvertTo-Json -Depth 10 | Set-Content $defaults -Encoding utf8
        $before = (Get-FileHash $defaults -Algorithm SHA256).Hash
        Initialize-TTConfigPersistence $defaults $config
        (Get-FileHash $defaults -Algorithm SHA256).Hash | Should Be $before
        (Read-TTConfigJsonRoot $config).settings.path | Should Be '%TT_ModuleRoot%\worker'
        (Read-TTConfigJsonRoot (Join-Path (Split-Path $config) 'config.defaults.json')).settings.path | Should Be '%TT_ModuleRoot%\worker'
    }
    It 'fails clearly when the named mutex cannot be acquired within the bound' {
        $path = Join-Path $script:TestRoot 'lock-timeout\config.json'
        $canonical = [System.IO.Path]::GetFullPath($path).ToLowerInvariant()
        $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($canonical))
        $name = 'Local\TechToolbox.Config.' + [Convert]::ToHexString($hash)
        $ready = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N') + '.ready')
        $holderCode = "`$mutex = [System.Threading.Mutex]::new(`$false, '$name'); [void]`$mutex.WaitOne(); [System.IO.File]::WriteAllText('$ready', 'locked'); Start-Sleep -Seconds 10; `$mutex.ReleaseMutex(); `$mutex.Dispose()"
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($holderCode))
        $process = Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList @('-NoProfile', '-EncodedCommand', $encoded) -PassThru -WindowStyle Hidden
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(8)
            while (-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
            (Test-Path -LiteralPath $ready) | Should Be $true
            $threw = $false
            try { Enter-TTConfigMutex -Path $path -TimeoutMilliseconds 50 | Out-Null } catch { $threw = $_.Exception.Message -like '*Timed out after 50 ms*' }
            $threw | Should Be $true
        }
        finally {
            if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
        }
    }
    It 'leaves the actual packaged defaults file byte-for-byte unchanged' {
        $moduleDefaults = Join-Path $PSScriptRoot '..\Config\config.json'
        $config = Join-Path $script:TestRoot 'packaged-integrity\Config\config.json'
        $before = (Get-FileHash -LiteralPath $moduleDefaults -Algorithm SHA256).Hash
        Initialize-TTConfigPersistence -DefaultsPath $moduleDefaults -ConfigPath $config
        (Get-FileHash -LiteralPath $moduleDefaults -Algorithm SHA256).Hash | Should Be $before
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDe8XauyP25IE6I
# jJgg+OQXGnA3t6uMFhZviL7JW5EFiKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDd
# dVFaWi+AeIcvYTR+EDq5rT3j5uRmZQ2hrQoS1lZwqDANBgkqhkiG9w0BAQEFAASC
# AYCw8TrtJCSGxlj+jFlalPa6UxwiTc/4LvpOnO1rBQdgL1xA1LhMl7q1xHc+Ppsd
# pRi32WRRJINSaziEy5LBP4gqPL8PQmwXaxeuaUJVNjJGmyL5z+Aa4LfCpr5cnxpN
# rXHNrwfJwQ6IQhkNzFfHexg6hrR2GFeRyFj9H7LRM4qfK3KhMGgBPKJ8zkXuupuW
# KmUO2FBVYC1XJ/tkC+59Cc1vNsFrL25mnjyadkskcU8sFCPxKjNrKG4DtUIFn9ae
# wCDFW4rRQcfmynoRtaWKgkaj5FawV4hLZOprMMYbifQf8IXQJYZGZhHxwojq6trQ
# ulWu84Xtazb7E7K3amEI1M62en6KbvV2ru8eN5absOD/iNl1RoVTzTPzVnTiMold
# F05XB1bCQz6IaKqfyOVFVJJ9MDIOeXRzJfEgIFZL4XdNqoSOPplHbFL1eDsfU+yn
# YhMBuhhC50ZQZnRK80FCJsARq7UHEl+FmKiplriAYA8jqh12piBklODdosSGZYdF
# wSmhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDI5MTY1NzQ4WjAvBgkqhkiG
# 9w0BCQQxIgQgIIf6L8Z1I12bgE1dDmgpqZeHjeS1es4V77Bm3ayDWvEwDQYJKoZI
# hvcNAQEBBQAEggIAgwrNHS6VnopwCS35MHlp67Q2kNnBxhWTW9oVvJhLUD32z3jQ
# laNGeajm0uz5WpIc5wQkv+HIar2lP1phdLtdnLP8Ddh+Fc3t58+UsvGH61BpqrLt
# LnWMtckCE8nb7vBYhBqYbiEMNQHJbNTLUVtv/uJe4pnSLnuigsdOTvANtwkAPLzN
# RUqCkH7cESxVYEailRh0OFCqsZyoPFSj//BrCI1meI56quJQuyM8UH/efyFKoMzb
# cr6GUOjItw8jcm1qIEwYnrCtmypmbKBgMcwb99FW/xOsoyiZyGsBKpBgv1cr8EWc
# jEF+AE6QSz+xp3XSMPqSdo1XCf2q+IIo/i9t9CyVO+rvBw7Vs7NqFSBvrb5VB0dL
# 5QlpJIzTUYX/BH4AS1/SjurUzkgbYj2/0ifj9ACHi9UpzchE6UA+1wxSReMorJhx
# NAIN6K1PQNAVj7pl4L/y8VL208xOeRS9tbnIq980gcRtLicGk/PLDqQK3wLa61p+
# rsFV0bDmpu9sCZKOyENOoySpmGd+8cI6HIQzePCOmyrWuPt/rvLJPLVfMO+u8976
# tMdxRBPnOMbCih5A9oGu2QqAoolW26KDZTK5S/OLHVXj+b2MYFic65IehuYizbQa
# omjjLHp3XxARYhzfQQ69B7qKA/5gj7dMhCQj6Ns5KVeG6xafAg9fHbTIAkk=
# SIG # End signature block
