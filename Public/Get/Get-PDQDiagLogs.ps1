
function Get-PDQDiagLogs {
  <#
    .SYNOPSIS
      Collect PDQ diagnostics under SYSTEM context (local and remote), zip on
      target, and copy back to C:\PDQDiagLogs on the machine running this script.
    
    .DESCRIPTION
      - Local & remote: run a one-time Scheduled Task as SYSTEM that performs
        collection.
      - PS7-first remoting via New-PSRemoteSession helper if present (fallback
        included).
      - Resilient copy (Copy-Item then robocopy /B), plus Event Log export via
        wevtutil.
      - ZIP pulled back to the collector and named
        PDQDiag_<Computer>_<timestamp>.zip.
    
    .PARAMETER ComputerName
      Target computer(s). Defaults to local machine.
    
    .PARAMETER Credential
      Optional credential for remote connections. If omitted and
      $Global:TTDomainCred exists, New-PSRemoteSession helper may use it.
    
    .PARAMETER LocalDropPath
      Path on the collector to store retrieved ZIP(s). Default: C:\PDQDiagLogs.
    
    .PARAMETER TransferMode
      Retrieval method for remote ZIPs: FromSession (default), Bytes, or SMB.
    
    .PARAMETER ExtraPaths
      Extra file/folder paths on the target(s) to include.
    
    .PARAMETER ConnectDataPath
      PDQ Connect data root. Default: "$env:ProgramData\PDQ\PDQConnectAgent"
    
    .PARAMETER UseSsh, SshPort, Ps7ConfigName, WinPsConfigName
      Passed through to session creation if helper supports them.
    
    .EXAMPLE
      Get-PDQDiagLogs
    .EXAMPLE
      Get-PDQDiagLogs -ComputerName EDI-2.vadtek.com -Credential (Get-Credential)
    .EXAMPLE
      Get-PDQDiagLogs. -ComputerName PC01,PC02 -ExtraPaths 'C:\Temp\PDQ','D:\Logs\PDQ'
    #>

  [CmdletBinding()]
  param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN', 'DNSHostName', 'Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [pscredential]$Credential,

    [string]$LocalDropPath = 'C:\PDQDiagLogs',

    [ValidateSet('FromSession', 'Bytes', 'SMB')]
    [string]$TransferMode = 'FromSession',

    [string[]]$ExtraPaths,

    [string]$ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),

    [switch]$UseSsh,
    [int]$SshPort = 22,

    [string]$Ps7ConfigName = 'PowerShell.7',
    [string]$WinPsConfigName = 'Microsoft.PowerShell',

    [switch]$VerifyHash,      # optional: compare SHA256 before cleanup
    [switch]$NoCleanup        # optional: keep remote artifacts
  )

  begin {
    $useUserHelper = [bool](Get-Command -Name Start-NewPSRemoteSession -ErrorAction SilentlyContinue)

    # Local session fallback if helper isn't present
    function New-ToolboxSession {
      param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [switch]$UseSsh,
        [int]$Port = 22,
        [string]$Ps7ConfigName = 'PowerShell.7',
        [string]$WinPsConfigName = 'Microsoft.PowerShell'
      )

      if ($UseSsh) {
        $sshParams = @{
          HostName    = $ComputerName
          Port        = $Port
          ErrorAction = 'Stop'
        }
        if ($Credential) {
          $sshParams.UserName = $Credential.UserName
          $sshParams.Password = $Credential.GetNetworkCredential().Password
        }
        return New-PSSession @sshParams
      }
      else {
        try {
          return New-PSSession -ComputerName $ComputerName -Credential $Credential `
            -ConfigurationName $Ps7ConfigName -ErrorAction Stop
        }
        catch {
          return New-PSSession -ComputerName $ComputerName -Credential $Credential `
            -ConfigurationName $WinPsConfigName -ErrorAction Stop
        }
      }
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $results = New-Object System.Collections.Generic.List[object]
  }

  process {
    foreach ($comp in $ComputerName) {
      if ([string]::IsNullOrWhiteSpace($comp)) { continue }

      $display = $comp
      $fileName = "PDQDiag_{0}_{1}.zip" -f ($display -replace '[^\w\.-]', '_'), $timestamp
      $collectorZipPath = Join-Path $LocalDropPath $fileName

      Write-Log -Level Info -Message ("[{0}] Starting collection (SYSTEM)..." -f $display)

      # Remote session lifecycle
      $session = $null
      try {
        if ($useUserHelper) {
          $params = @{
            ComputerName    = $comp
            Credential      = $Credential
            UseSsh          = $UseSsh
            Port            = $SshPort
            Ps7ConfigName   = $Ps7ConfigName
            WinPsConfigName = $WinPsConfigName
          }
          $session = Start-NewPSRemoteSession @params
        }
        else {
          $session = New-ToolboxSession -ComputerName $comp -Credential $Credential -UseSsh:$UseSsh -Port $SshPort -Ps7ConfigName $Ps7ConfigName -WinPsConfigName $WinPsConfigName
        }

        # Run the SYSTEM worker on the remote
        $remote = Invoke-RemoteSystemCollection -Session $session -Timestamp $timestamp -ExtraPaths $ExtraPaths -ConnectDataPath $ConnectDataPath

        # Make sure the worker actually finished and ZIP exists
        $completed = $remote.PSObject.Properties['Completed'] -and $remote.Completed
        if (-not $completed) {
          # If the new property isn't present, fall back to probing the flag/zip
          $zipExists = Invoke-Command -Session $session -ScriptBlock { param($p) Test-Path -LiteralPath $p } -ArgumentList $remote.ZipPath
          if (-not $zipExists) {
            throw "Remote worker did not complete within the timeout; ZIP not found at $($remote.ZipPath)"
          }
        }

        # (Optional) compute remote hash before transfer
        $remoteHash = $null
        if ($VerifyHash) {
          $remoteHash = Invoke-Command -Session $session -ScriptBlock {
            param($p)
            if (Test-Path -LiteralPath $p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } else { $null }
          } -ArgumentList $remote.ZipPath
        }

        # Retrieve ZIP to collector
        Receive-RemoteFile -Session $session -RemotePath $remote.ZipPath -LocalPath $collectorZipPath -Mode $TransferMode
        Write-Log -Level Info -Message ("[{0}] ZIP retrieved: {1}" -f $comp, $collectorZipPath)

        # (Optional) verify local hash matches
        if ($VerifyHash -and $remoteHash) {
          $localHash = (Get-FileHash -LiteralPath $collectorZipPath -Algorithm SHA256).Hash
          if ($localHash -ne $remoteHash) {
            throw "Hash mismatch after transfer. Remote=$remoteHash Local=$localHash"
          }
          Write-Log -Level Ok -Message ("[{0}] SHA256 verified." -f $comp)
        }

        # Remote cleanup (optional)
        if (-not $NoCleanup) {
          try {
            Invoke-Command -Session $session -ScriptBlock {
              param($stag, $zip, $scr, $arg)
              foreach ($p in @($stag, $zip, $scr, $arg)) {
                if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
                  Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                }
              }
            } -ArgumentList $remote.Staging, $remote.ZipPath, $remote.Script, $remote.Args -ErrorAction SilentlyContinue | Out-Null
          }
          catch { }
        }

        $obj = [pscustomobject]@{
          ComputerName = $comp
          Status       = 'Success'
          ZipPath      = $collectorZipPath
          Notes        = 'Remote SYSTEM collection'
        }
        $results.Add($obj) | Out-Null
        Write-Output $obj
      }
      catch {
        $msg = $_.Exception.Message
        Write-Log -Level Error -Message ("[{0}] FAILED: {1}" -f $comp, $msg)
        $obj = [pscustomobject]@{
          ComputerName = $comp
          Status       = 'Failed'
          ZipPath      = $null
          Notes        = $msg
        }
        $results.Add($obj) | Out-Null
        Write-Output $obj
      }
      finally {
        if ($session) { Remove-PSSession $session }
      }
    }
  }

  end {
    return
  }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVxNP4+Es1n7ay
# 6mdIbsvV/tw+95H0lxBSOgnDx3vJz6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCxWQf5xJ64
# 3xuY9WNxtWaKJSzdydpYkqcVoZTWdg5KHzANBgkqhkiG9w0BAQEFAASCAgBf7jvr
# 3PaNwixT2wGKdWkzt2hQY8N69g2BXWhGU+a4SmnQGd3XGzy++6SeTBD7OLzVoVR2
# BQullqWV5jKrQn8kZBrc5XOdArnfCqhq8ChBLMcGlfTxVdDe5s5YlcQmZwCqGWnQ
# spZer0ZsyrIPN5oBoHxQ5UAQb3TNk13Ob4RWPR82LRnpi8j2gYA1U4XkUG2rxwL8
# uY5VGThrsw2bP2ypLKoabucQ8EsQmSxxF1tZrbCTJQxWWnpHIT3B4FB2wTKYd1Y+
# KM+ouUBO3bIbxsNXGjSwFbNamHkODYE8imp6XVb5TE0EaiMjSy75hL6KXQYVXsof
# BS8aq6IsgCfNFokk7FdjpEOXDGQ5JLh6V5yg4qUZBGtlfGZVbc74j/GyJqfJIHMS
# jtGTV/5aMV/fxI6M5A1dsXAxFsUfqRv7W4sTtQofer2hlcHwngdtxUg5juHhxP8Z
# sYGnR15QkD6iDp+g7JRyjTwj0f9706agzilmTiGT1ARXM7S+hhDwEpF7K5bIDr/X
# vwqha/plwmc+HO1r8QEbZ/wyW6PDFHM4DXiDzsgjBV3VcF6OghRw0lwZuWpaa3ey
# sm58cXTXeSdhna52skD5nOy5+tSN/Tuc7iMG9kQkbQt3f7g1mDzx8R7VkN0kuDtm
# Yg/KBpaT92niapa+5Vaba12faqMgDq+je2T9MaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMDkyMjQ0MThaMC8GCSqGSIb3DQEJBDEiBCArNDVNOtGVHDzxmAX9
# Z2YS8nFRBJoCgWlyBsi7+qmN9zANBgkqhkiG9w0BAQEFAASCAgBqEGob0YtFO2o3
# iBAq5tLWXuHLiEQ67yCBhefW84xnTJGFJQHDxTc2Qt+c5geJYpxunsOVBc6L3f3M
# ZR1QFjWV2njlOomy5vi8+AWWn24wYSKn/L3W32/lt3TSQJPK15bzy4TQvuFrvR3n
# KFUnlNFzNvTRh6Z9WaAgnXQCP0+bJ4oUsMjr34dX9VocUwaXirDorSXvRYC4Ulg5
# 4R10/OWUlPK+1FQeqIsSFFsTlI33ZM9oCxWBB5GvRq1SUAG5kxP4VQI5btD5Qx1V
# TipbwesybCK33x2pBtuB1ejYhk/s4T7esMpBhZYTtI3HIDi9SCM21AMnlI1BOSDK
# bP1EUN9iWM0AzHDTFBs4t0mcEqpNIefhTk56ycSj6xmQb/iZ2EaFrm6P15C6XQP8
# PKGX34TL9dK+5qmGjcsY51Nd2/NEit48FPVNBK80GKak1h5LcdakOB5ciVuw2H7o
# Z3zOdE3VEPRs9skAef32l4QgdgZYZN9EH8qhfeXbnZfNFaYgtIdMJtFuSFW80qEq
# senMiCuuVaUxhTQ4YpAVxNDdhNEvoZiPsUfPk+FM6/tcndPP4nTNSTeXiT1j/w0B
# SUc8+Ej4md6CCxHtAGsk6QZyCSmkRnzOnkCktEiqApIrAYMZ/X2Ewtr/KFanMuIC
# 7aKC46jC/Lp6xdfOp2SrStQiflEVtg==
# SIG # End signature block
