function ConvertTo-TTConfigHashtable {
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach ($key in $Value.Keys) { $copy[$key] = ConvertTo-TTConfigHashtable -Value $Value[$key] }
        return ,$copy
    }
    if ($Value -is [System.Collections.IList] -and $Value -isnot [string]) {
        $items = @(); foreach ($item in $Value) { $items += ,(ConvertTo-TTConfigHashtable -Value $item) }; return ,$items
    }
    return $Value
}

function Read-TTConfigJsonRoot {
    param([Parameter(Mandatory)][string]$Path, [switch]$AllowMissing)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($AllowMissing) { return $null }
        throw "Configuration file does not exist: '$Path'."
    }
    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "Configuration file is empty: '$Path'." }
    $value = ConvertFrom-Json -InputObject $raw -AsHashtable -ErrorAction Stop
    if ($value -isnot [System.Collections.IDictionary]) { throw "Configuration JSON root must be an object: '$Path'." }
    return ,$value
}

function Copy-TTConfigValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    return (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 100 -Compress) -AsHashtable -ErrorAction Stop)
}

function Test-TTConfigValueEqual {
    param($Left, $Right)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    if ($Left -is [System.Collections.IDictionary] -and $Right -is [System.Collections.IDictionary]) {
        if ($Left.Count -ne $Right.Count) { return $false }
        foreach ($key in $Left.Keys) { if (-not $Right.Contains($key) -or -not (Test-TTConfigValueEqual $Left[$key] $Right[$key])) { return $false } }
        return $true
    }
    if ($Left -is [System.Collections.IList] -and $Right -is [System.Collections.IList] -and $Left -isnot [string] -and $Right -isnot [string]) {
        if ($Left.Count -ne $Right.Count) { return $false }
        for ($i = 0; $i -lt $Left.Count; $i++) { if (-not (Test-TTConfigValueEqual $Left[$i] $Right[$i])) { return $false } }
        return $true
    }
    return [object]::Equals($Left, $Right)
}

function Merge-TTConfigThreeWay {
    param($Current, $Previous, $User)
    if ($Current -is [System.Collections.IDictionary]) {
        $result = @{}
        $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $Current.Keys) { [void]$keys.Add([string]$key) }
        if ($User -is [System.Collections.IDictionary]) { foreach ($key in $User.Keys) { [void]$keys.Add([string]$key) } }
        foreach ($key in $keys) {
            $hasCurrent = $Current.Contains($key)
            $hasUser = $User -is [System.Collections.IDictionary] -and $User.Contains($key)
            $hasPrevious = $Previous -is [System.Collections.IDictionary] -and $Previous.Contains($key)
            if (-not $hasCurrent) {
                if ($hasUser -and (-not $hasPrevious -or -not (Test-TTConfigValueEqual $User[$key] $Previous[$key]))) { $result[$key] = Copy-TTConfigValue $User[$key] }
                continue
            }
            if (-not $hasUser) { $result[$key] = Copy-TTConfigValue $Current[$key]; continue }
            if ($hasPrevious -and (Test-TTConfigValueEqual $User[$key] $Previous[$key])) { $result[$key] = Copy-TTConfigValue $Current[$key]; continue }
            if ($Current[$key] -is [System.Collections.IDictionary] -and $User[$key] -is [System.Collections.IDictionary]) {
                $prior = if ($hasPrevious -and $Previous[$key] -is [System.Collections.IDictionary]) { $Previous[$key] } else { @{} }
                $result[$key] = Merge-TTConfigThreeWay -Current $Current[$key] -Previous $prior -User $User[$key]
            }
            else { $result[$key] = Copy-TTConfigValue $User[$key] }
        }
        return ,$result
    }
    if ($null -eq $User) { return (Copy-TTConfigValue $Current) }
    if ($null -ne $Previous -and (Test-TTConfigValueEqual $User $Previous)) { return (Copy-TTConfigValue $Current) }
    return (Copy-TTConfigValue $User)
}

function Remove-TTConfigSecretValues {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Config)
    foreach ($key in @($Config.Keys)) {
        $name = [string]$key
        if ($name -match '(?i)(encrypted|secret|token|password|apikey)$') {
            $Config.Remove($key)
            continue
        }
        if ($Config[$key] -is [System.Collections.IDictionary]) {
            Remove-TTConfigSecretValues -Config $Config[$key]
        }
        elseif ($Config[$key] -is [System.Collections.IList] -and $Config[$key] -isnot [string]) {
            foreach ($item in $Config[$key]) {
                if ($item -is [System.Collections.IDictionary]) { Remove-TTConfigSecretValues -Config $item }
            }
        }
    }
}

function Remove-TTConfigLegacySecrets {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Config)
    if (-not $Config.Contains('settings') -or $Config['settings'] -isnot [System.Collections.IDictionary]) { return }
    $settings = $Config['settings']
    if (-not $settings.Contains('passwords') -or $settings['passwords'] -isnot [System.Collections.IDictionary]) { return }
    $passwords = $settings['passwords']
    if (-not $passwords.Contains('domainAdminCred') -or $passwords['domainAdminCred'] -isnot [System.Collections.IDictionary]) { return }
    foreach ($key in @('username', 'password')) { if ($passwords['domainAdminCred'].Contains($key)) { $passwords['domainAdminCred'].Remove($key) } }
}

function Write-TTConfigAtomic {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    $temp = Join-Path $directory ('.{0}.{1}.tmp' -f [System.IO.Path]::GetFileName($Path), [guid]::NewGuid().ToString('N'))
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 100))
    try {
        $stream = [System.IO.File]::Open($temp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Move($temp, $Path, $true) }
        else { [System.IO.File]::Move($temp, $Path) }
    }
    finally { if ([System.IO.File]::Exists($temp)) { [System.IO.File]::Delete($temp) } }
}

function Enter-TTConfigMutex {
    param([Parameter(Mandatory)][string]$Path, [int]$TimeoutMilliseconds = 30000)
    $canonical = [System.IO.Path]::GetFullPath($Path).ToLowerInvariant()
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($canonical))
    $name = 'Local\TechToolbox.Config.' + [Convert]::ToHexString($hash)
    $mutex = [System.Threading.Mutex]::new($false, $name)
    try {
        try { $acquired = $mutex.WaitOne($TimeoutMilliseconds) } catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw "Timed out after $TimeoutMilliseconds ms waiting for config lock '$name'." }
        return $mutex
    }
    catch { $mutex.Dispose(); throw }
}

function Exit-TTConfigMutex {
    param([Parameter(Mandatory)][System.Threading.Mutex]$Mutex)
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}

function Initialize-TTConfigPersistence {
    param([Parameter(Mandatory)][string]$DefaultsPath, [Parameter(Mandatory)][string]$ConfigPath)
    if ([System.IO.Path]::GetFullPath($DefaultsPath) -eq [System.IO.Path]::GetFullPath($ConfigPath)) { throw 'User config path must not point to packaged defaults.' }
    $mutex = Enter-TTConfigMutex -Path $ConfigPath
    try {
        $defaults = Read-TTConfigJsonRoot -Path $DefaultsPath
        $baselinePath = Join-Path (Split-Path -Parent $ConfigPath) 'config.defaults.json'
        $previous = Read-TTConfigJsonRoot -Path $baselinePath -AllowMissing
        # Re-read mutable config only after acquiring the cross-process lock.
        $user = Read-TTConfigJsonRoot -Path $ConfigPath -AllowMissing
        if ($null -eq $previous -and $null -ne $user) {
            # One-time migration: preserve every existing value without guessing which
            # values were defaults; snapshot current packaged defaults for later upgrades.
            $merged = Copy-TTConfigValue $user
        }
        elseif ($null -eq $user) { $merged = Copy-TTConfigValue $defaults }
        else { $merged = Merge-TTConfigThreeWay -Current $defaults -Previous $previous -User $user }
        Remove-TTConfigSecretValues -Config $merged
        Remove-TTConfigLegacySecrets -Config $merged
        Write-TTConfigAtomic -Path $ConfigPath -Value $merged
        $baseline = Copy-TTConfigValue $defaults
        Remove-TTConfigSecretValues -Config $baseline
        Remove-TTConfigLegacySecrets -Config $baseline
        Write-TTConfigAtomic -Path $baselinePath -Value $baseline
    }
    finally { Exit-TTConfigMutex -Mutex $mutex }
}
