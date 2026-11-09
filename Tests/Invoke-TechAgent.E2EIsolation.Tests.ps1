Describe 'Invoke-TechAgent fresh-process isolation bootstrap' {
   BeforeAll {
      . (Join-Path $PSScriptRoot 'Support\Invoke-TechAgent.E2EFixture.ps1')
      $script:manifest = Join-Path $PSScriptRoot '..\TechToolbox.psd1'
      $script:moduleRoot = (Resolve-Path (Split-Path -Parent $script:manifest)).Path
      $script:liveRoot = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TechToolbox' }else { $null }
      $script:envNames = @('TT_Home', 'TT_LocalDataRoot', 'TT_ModuleRoot', 'TT_LogsRoot', 'TT_ExportsRoot', 'TT_AGENT_FILESYSTEM_ROOT', 'TT_AGENT_ALLOWED_PATH_ROOTS', 'TT_AGENT_LOCAL_MCP_ADAPTER_PATH', 'TT_APPROVAL_RESPONSE', 'TT_AGENT_APPROVAL_RESPONSE')
      $script:parentEnvironment = Get-TTE2EParentEnvironment -Names $script:envNames
      $script:parentLocal = $script:parentEnvironment.LOCALAPPDATA; $script:parentEnv = $script:parentEnvironment.Values
      function Get-Inventory($root) { Get-TTE2EInventory -Root $root }
      function Assert-Inventory($a, $b) { Assert-TTE2EInventoryUnchanged -Before $a -After $b }
      function Resolve-Pwsh { Resolve-TTE2EPwsh }
      function Get-Descendants([int]$rootPid) { Get-TTE2EDescendantProcesses -RootProcessId $rootPid }
      function Assert-Evidence($e, $root, $runtime) { if (!$e.ImportSucceeded) { throw 'Module import failed.' }; if ([IO.Path]::GetFullPath($e.LocalAppData) -ine [IO.Path]::GetFullPath($root)) { throw 'LOCALAPPDATA mismatch.' }; $prefix = [IO.Path]::GetFullPath($root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar; if (![IO.Path]::GetFullPath($e.LocalDataRoot).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'LocalDataRoot escaped root.' }; foreach ($p in $e.CreatedPaths) { if (![IO.Path]::GetFullPath($p).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Created path escaped root: $p" } }; if (!$e.PrivateLoaded) { throw 'Private helpers missing or exported.' }; if (!$e.PublicCommand) { throw 'Invoke-TechAgent is unavailable.' }; if ([IO.Path]::GetFullPath($e.RuntimeAssemblyPath) -ine [IO.Path]::GetFullPath($runtime)) { throw 'Runtime provenance unacceptable.' }; if ($e.AgentLaunchCount -ne 0) { throw "Unexpected Agent launch count: $($e.AgentLaunchCount); descendants: $($e.DescendantProcessIds -join ',')" }; if ($e.DescendantCount -ne 0) { throw "Unexpected fixture-child descendants remain: $($e.DescendantProcessIds -join ',')" } }
      function Start-Child($root, $exe, $manifest) {
         if (!(Test-Path -LiteralPath $root -PathType Container)) { throw 'Isolated root cannot be created.' }; if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'pwsh cannot be resolved.' }
         $token = [guid]::NewGuid().ToString('N'); $logPath = Join-Path $root 'lifecycle.log'; $evidencePath = Join-Path $root 'evidence.json'; $parentId = $PID; $baselineDescendants = @(Get-Descendants $parentId); [IO.File]::AppendAllText($logPath, ('{0}|{1}|parent-descendant-baseline={2}{3}' -f $token, $parentId, (($baselineDescendants | ForEach-Object { '{0}:{1}:{2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name }) -join ','), [Environment]::NewLine), [Text.Encoding]::UTF8)
         $code = @'
$ErrorActionPreference='Stop';$token=$env:TT_TEST_TOKEN;$log=$env:TT_TEST_LIFECYCLE_LOG
function Mark([string]$name){[IO.File]::AppendAllText($log,('{0}|{1}|{2}{3}' -f $token,$PID,$name,[Environment]::NewLine),[Text.Encoding]::UTF8)}
function Get-Descendants([int]$rootPid){$all=@(Get-CimInstance Win32_Process -ErrorAction Stop|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine);$known=[Collections.Generic.HashSet[int]]::new();[void]$known.Add($rootPid);$found=[Collections.Generic.List[object]]::new();do{$added=$false;foreach($x in $all){if(!$known.Contains([int]$x.ProcessId)-and$known.Contains([int]$x.ParentProcessId)){[void]$known.Add([int]$x.ProcessId);$found.Add($x);$added=$true}}}while($added);@($found)}
Mark 'child-started';$beforeImport=@(Get-Descendants $PID);Mark 'localappdata-redirected'
foreach($n in @('TT_Home','TT_LocalDataRoot','TT_ModuleRoot','TT_LogsRoot','TT_ExportsRoot','TT_AGENT_FILESYSTEM_ROOT','TT_AGENT_ALLOWED_PATH_ROOTS','TT_AGENT_LOCAL_MCP_ADAPTER_PATH','TT_APPROVAL_RESPONSE','TT_AGENT_APPROVAL_RESPONSE')){Remove-Item "Env:$n" -ErrorAction SilentlyContinue}
# The source tree ships config.secrets.example.json, not the production packaged filename. Supply a harmless test-owned file so import stays isolated and deterministic.
$config=Join-Path $env:LOCALAPPDATA 'TechToolbox\Config';[void](New-Item -ItemType Directory -Path $config -Force);[IO.File]::WriteAllText((Join-Path $config 'config.secrets.json'),'{}',[Text.Encoding]::UTF8)
$state=$null
try{Mark 'module-import-started';$m=Import-Module $env:TT_TEST_MANIFEST -Force -PassThru -ErrorAction Stop;Mark 'module-import-completed';$state=$m.SessionState.PSVariable.GetValue('TT');Mark 'private-helper-inspection-started';$required=@('Resolve-TTAgentRuntimeAssemblyPath','Invoke-TTAgentApprovalProtocolLine','Read-TTAgentDestructiveApprovalResponse','Get-TTAgentPostflightDecision','Resolve-TTAgentWriteDirectorySettings');$found=@(& $m {param($names) Get-Command -Name $names -CommandType Function -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Name} $required);$private=(@($required|Where-Object{$found -contains $_}).Count -eq $required.Count)-and(@($required|Where-Object{$m.ExportedFunctions.ContainsKey($_)}).Count -eq 0);Mark 'private-helper-inspection-completed';$afterHelpers=@(Get-Descendants $PID);$newDescendants=@($afterHelpers|Where-Object{$_.ProcessId -notin @($beforeImport|ForEach-Object ProcessId)});Mark ('descendant-processes-after-import-and-helper-inspection='+$newDescendants.Count);foreach($d in $newDescendants){Mark ('owned-descendant;pid='+$d.ProcessId+';parent='+$d.ParentProcessId+';name='+$d.Name+';path='+$d.ExecutablePath)};Mark 'runtime-resolution-started';$runtime=& $m {param($r) Resolve-TTAgentRuntimeAssemblyPath -ModuleRoot $r} $m.ModuleBase;Mark 'runtime-resolution-completed';$paths=@(Get-ChildItem $env:TT_TEST_ROOT -Depth 2 -Force|Select-Object -First 200|Where-Object{$_.FullName -notin @($log,$env:TT_TEST_EVIDENCE)}|Select-Object -ExpandProperty FullName);$json=[ordered]@{LocalAppData=$env:LOCALAPPDATA;LocalDataRoot=[string]$state.LocalDataRoot;ProcessId=$PID;ParentProcessId=(Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId;CorrelationToken=$token;PowerShellVersion=$PSVersionTable.PSVersion.ToString();ImportSucceeded=$true;PrivateLoaded=$private;PrivateNames=$required;PublicCommand=[bool](Get-Command Invoke-TechAgent -CommandType Function -ErrorAction SilentlyContinue);RuntimeAssemblyPath=[string]$runtime;CreatedPaths=$paths;WritablePaths=@([string]$state.LocalDataRoot,[string]$state.ConfigPath,[string]$state.SecretsPath,[string]$state.LogsRoot,[string]$state.ExportsRoot);DescendantProcessIds=@($afterHelpers|ForEach-Object ProcessId);AgentLaunchCount=@($newDescendants|Where-Object{$_.Name -match '^TechToolbox\.Agent(\.exe)?$' -or $_.ExecutablePath -match '[\\/]TechToolbox\.Agent(\.exe)?$' -or $_.CommandLine -match 'TechToolbox\.Agent(\.dll|\.exe)'}).Count;DescendantCount=$newDescendants.Count}|ConvertTo-Json -Compress -Depth 3;[IO.File]::WriteAllText($env:TT_TEST_EVIDENCE,$json,[Text.Encoding]::UTF8);Mark 'evidence-serialized';Write-Output $json;[Console]::Out.Flush();Mark 'stdout-closed';Mark 'child-completing'}catch{Mark ('bootstrap-failed:'+$_.Exception.Message);$failure=[ordered]@{ImportSucceeded=$false;Error=$_.Exception.Message;CorrelationToken=$token}|ConvertTo-Json -Compress;[IO.File]::WriteAllText($env:TT_TEST_EVIDENCE,$failure,[Text.Encoding]::UTF8);Write-Output $failure;exit 17}
'@
         $si = [Diagnostics.ProcessStartInfo]::new(); $si.FileName = $exe; $si.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)); $si.UseShellExecute = $false; $si.CreateNoWindow = $true; $si.RedirectStandardOutput = $true; $si.RedirectStandardError = $true; $si.Environment['LOCALAPPDATA'] = $root; $si.Environment['TT_TEST_ROOT'] = $root; $si.Environment['TT_TEST_MANIFEST'] = $manifest; $si.Environment['TT_TEST_TOKEN'] = $token; $si.Environment['TT_TEST_LIFECYCLE_LOG'] = $logPath; $si.Environment['TT_TEST_EVIDENCE'] = $evidencePath; $p = [Diagnostics.Process]::new(); $p.StartInfo = $si; $ownedId = $null
         try {
            if (!$p.Start()) { throw 'Child did not start.' }; $ownedId = $p.Id; $ownedStarted = $p.StartTime.ToUniversalTime().Ticks; $p.Refresh(); $ownedParent = $p.Parent?.Id
            [IO.File]::AppendAllText($logPath, ('{0}|{1}|{2}|child-created;parent={3};startTicks={4}{5}' -f $token, $parentId, $ownedId, $ownedParent, $ownedStarted, [Environment]::NewLine), [Text.Encoding]::UTF8)
            $o = $p.StandardOutput.ReadToEndAsync(); $er = $p.StandardError.ReadToEndAsync()
            try { $result = Wait-TTE2EProcessAndPipes -Process $p -StandardOutputTask $o -StandardErrorTask $er -TimeoutMilliseconds 18000 -EvidencePath $evidencePath -MaximumEvidenceBytes 1048576 }
            catch { $stages = if (Test-Path $logPath) { [IO.File]::ReadAllText($logPath) } else { '<no checkpoints>' }; throw "Owned child wait failed; pid=$ownedId; token=$token; last checkpoints: $stages; $($_.Exception.Message)" }
            [IO.File]::AppendAllText($logPath, ('{0}|{1}|child-exit-observed;exit={2}{3}' -f $token, $ownedId, $result.ExitCode, [Environment]::NewLine), [Text.Encoding]::UTF8)
            [IO.File]::AppendAllText($logPath, ('{0}|{1}|stdout-stderr-eof{2}' -f $token, $ownedId, [Environment]::NewLine), [Text.Encoding]::UTF8)
            $jsonText = $result.Evidence; $e = $jsonText | ConvertFrom-Json; if ($result.StandardOutput -notmatch [regex]::Escape($jsonText.Trim())) { throw "JSON stdout evidence mismatch; pid=$ownedId; token=$token" }; if ($result.ExitCode -ne 0) { throw "Child bootstrap failed: $($e.Error)" }; if ($e.ProcessId -ne $ownedId -or $e.ParentProcessId -ne $parentId) { throw "Child ownership chain mismatch; expected child=$ownedId parent=$parentId, observed child=$($e.ProcessId) parent=$($e.ParentProcessId)" }; $e
         }
         finally {
            if ($ownedId) { try { Stop-TTE2EOwnedProcess -Process $p -ProcessId $ownedId -StartTimeUtcTicks $ownedStarted -TimeoutMilliseconds 5000 } catch { throw "Owned child cleanup failed; pid=$ownedId; token=$token; $($_.Exception.Message)" } }
            if ($ownedId) { $p.Dispose(); [IO.File]::AppendAllText($logPath, ('{0}|{1}|process-object-disposed{2}' -f $token, $ownedId, [Environment]::NewLine), [Text.Encoding]::UTF8) } else { $p.Dispose() }
         }
      }
   }
   It 'redirects LOCALAPPDATA before normal import and isolates module/runtime state' {
      $root = $null; $before = Get-Inventory $script:liveRoot; $moduleBefore = [bool](Get-Module TechToolbox); $made = $false
      try { $root = New-TTE2EOwnedRoot -Prefix 'tt-e2e-isolation-'; $made = $true; $exe = Resolve-Pwsh; $e = Start-Child $root $exe $script:manifest; $candidates = @((Join-Path $script:moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'), (Join-Path $script:moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish\TechToolbox.Agent.dll'), (Join-Path $script:moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'), (Join-Path $script:moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll')); $expected = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1; if (!$expected -or $expected -match '[\\/]bin[\\/]Debug[\\/]') { throw 'Expected packaged/published/Release runtime unavailable; stopping before Agent launch.' }; Assert-Evidence $e $root $expected; $e.PrivateNames | Should -Contain 'Resolve-TTAgentRuntimeAssemblyPath'; $e.PrivateNames | Should -Contain 'Invoke-TTAgentApprovalProtocolLine'; $e.PrivateNames | Should -Contain 'Read-TTAgentDestructiveApprovalResponse'; $e.PrivateNames | Should -Contain 'Get-TTAgentPostflightDecision'; $e.PublicCommand | Should -BeTrue; $e.ProcessId | Should -BeGreaterThan 0; $e.PowerShellVersion | Should -Not -BeNullOrEmpty; foreach ($p in $e.WritablePaths) { [IO.Path]::GetFullPath($p).StartsWith(([IO.Path]::GetFullPath($root).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue } }
      finally { Assert-Inventory $before (Get-Inventory $script:liveRoot); Assert-TTE2EParentEnvironmentUnchanged -Snapshot $script:parentEnvironment; [bool](Get-Module TechToolbox) | Should -Be $moduleBefore; if ($made -and (Test-Path $root)) { Remove-TTE2EOwnedRoot -Path $root -ExpectedPrefix 'tt-e2e-isolation-' }; if ($root) { Test-Path $root | Should -BeFalse } }
   }
   It 'fails closed if isolated-root creation fails' { $block = Join-Path ([IO.Path]::GetTempPath()) ('tt-e2e-block-' + [guid]::NewGuid().ToString('N')); [IO.File]::WriteAllText($block, 'fixture'); try { { [void](New-Item -ItemType Directory -Path (Join-Path $block 'child') -ErrorAction Stop) } | Should -Throw }finally { Remove-Item $block -Force } }
   It 'fails closed if pwsh resolution fails' { Mock Get-Command { $null } -ParameterFilter { $Name -eq 'pwsh' }; { Resolve-Pwsh } | Should -Throw '*cannot be resolved*' }
   It 'rejects import, root escape, runtime provenance, and missing private helpers' { $root = Join-Path ([IO.Path]::GetTempPath()) 'test-root'; $runtime = Join-Path $script:moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'; $good = [pscustomobject]@{ImportSucceeded = $true; LocalAppData = $root; LocalDataRoot = (Join-Path $root 'TechToolbox'); CreatedPaths = @((Join-Path $root 'TechToolbox\Config')); PrivateLoaded = $true; PublicCommand = $true; RuntimeAssemblyPath = $runtime }; $mutations = @( { param($x)$x.ImportSucceeded = $false }, { param($x)$x.LocalAppData = [IO.Path]::GetTempPath() }, { param($x)$x.LocalDataRoot = [IO.Path]::GetTempPath() }, { param($x)$x.PrivateLoaded = $false }, { param($x)$x.RuntimeAssemblyPath = (Join-Path $script:moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll') }); foreach ($m in $mutations) { $bad = $good.PSObject.Copy(); &$m $bad; { Assert-Evidence $bad $root $runtime } | Should -Throw } }
   It 'inventories normal runtime file metadata without reading contents' { $script:liveRoot | Should -Not -BeNullOrEmpty; foreach ($v in (Get-Inventory $script:liveRoot).Values) { $v | Should -Match '^\d+\|\d+$' } }
}
# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCmL0NfrWE44pn2
# 0CSnIu5xYlf0XqOhk0uLxkJvTDbXY6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB/
# NoHOxOoCZdB11GuH+34jEM9nZ0b6TX2fV1vnIp2YfzANBgkqhkiG9w0BAQEFAASC
# AYAhcE21pNIS1Jf2S+q8km3pqyZqkmWJP9EQfyYsoKhh97WAHadbthcGpkoiIhZ2
# mvDheS9y3FNFz++6zwfHFt6z+L+/n9/t/l1ySkFxbsNBk4l/wxXuLoRTbrg+T9xk
# gQeHtlgd9FLWc4vrXRcSsxy2If4/hcYQ2MF7JL8k9wbmUVD+8BGU1zQn1fz1zKc8
# TZmz48DgZn3ODEF5PXCzN0qETzxUUKPoJQgoHuNXYsAJfQxBL/CKjA8GEW+8ukn7
# VSXMu/CG/XBSUnRueOm0uEI1pBmm0eGrBmptcTow/dIktCjvVXdkbL9o73et3H5I
# VYaP0yx8RgEjnyzctTOMW/cADCjD7Pw+CxR5thYiTOAPQzLi7ZyYFRVV1XrV9smr
# IF5x8KGRp849CRLDj/MCy57ULq+9VSBw7Z51DAHOuN6YFu78KGEaJpXNq6KNnsQu
# GIPaOZsbBoMdI/GyuTwuNR0tv1U4+8jo9wU7xJ7YWXPvAbZBj35fQCXgBDWOvQYG
# nj2hggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTA5MDUwMDQ5WjAvBgkqhkiG
# 9w0BCQQxIgQgvfL9Gb9hY31BSlBO8xWh2R8hU2Y79RmA47aIweEFGfQwDQYJKoZI
# hvcNAQEBBQAEggIASO+5amvrvS8UydgIKWnOo+DfFo3PQnaBkyxOReotflffQJap
# N0gbmsoeVoPx+LQhhkuUbwAPwF1VNJy5iKoRq4ROnwzJvMAaRp69gd87dA7E2kXC
# Nlgq5huOHD3uJVvpJp+6a4F/H5HgS4HVcmwV4mHG2PJwuxLdxRHSOPSkOlsDY+3C
# 5MXj9NCwy+45zLVXABxnJ1ylXWh+WXnhuZW/dH4/3ylpg/RsXJWTNFLTcIkgXp5Z
# mcwHzthi0ebaWR+MCULd3YgD34EDxoHZ+9rFjXgX7eXaz0TDBBXu/MfVJ9sWmxS3
# hES0QuliwSUxHhzy6m81mbGC6MntlIof+IYmUsQ4Gzsyqv5L1qUpaIXyvmeskkke
# 5wNSQ8udpynnUw3BvNKhQaPNSOkvlbiynym2xXT9zOAoJRkqMV5Kxt4ENGqUzDoR
# yHeF+roIyGsOMaG9cLFsaSpqfK7pU0eo/pFRW2xny6uzm9dP69qhy1XIr4DF4VZD
# 8rxEF8uLJ2UVPQAx4HpDJ5upcajsLMdYS9+kRM4YEPSO7fGmbqgjPS+6NNk6mUG5
# 9ZQi0JeJ7Gao6FfkZAYiqD4XhPxDRaRLWOgvdsroUzlNXF7X6BZgS+Z23ONB9bxa
# FkD5fDuQd/NmKpS2AU9F7JxTf4do1UQsXhoAi9zKV0QvBdYhrruthyD1jb8=
# SIG # End signature block
