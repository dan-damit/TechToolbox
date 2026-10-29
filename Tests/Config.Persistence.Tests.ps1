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
