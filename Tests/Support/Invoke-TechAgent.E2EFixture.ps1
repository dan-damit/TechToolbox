# Test-only shared helpers for isolated Invoke-TechAgent E2E coverage.

function Get-TTE2EInventory {
    param([AllowNull()][string]$Root)
    $inventory = @{}
    if ($Root -and (Test-Path -LiteralPath $Root -PathType Container)) {
        Get-ChildItem -LiteralPath $Root -Depth 2 -File -Force -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
            $inventory[[IO.Path]::GetRelativePath($Root, $_.FullName)] = '{0}|{1}' -f $_.Length, $_.LastWriteTimeUtc.Ticks
        }
    }
    return $inventory
}

function Assert-TTE2EInventoryUnchanged {
    param([hashtable]$Before, [hashtable]$After)
    foreach ($key in $Before.Keys) {
        if (!$After.ContainsKey($key)) { throw "Deleted file: $key" }
        if ($Before[$key] -cne $After[$key]) { throw "Metadata changed: $key" }
    }
    foreach ($key in $After.Keys) { if (!$Before.ContainsKey($key)) { throw "Created file: $key" } }
}

function New-TTE2EOwnedRoot {
    param([Parameter(Mandatory)][string]$Prefix)
    $root = Join-Path ([IO.Path]::GetTempPath()) ($Prefix + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $root -ErrorAction Stop)
    return $root
}

function Resolve-TTE2EPwsh {
    $command = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$command) { throw 'Fresh pwsh executable cannot be resolved.' }
    return $command.Source
}

function Get-TTE2EParentEnvironment {
    param([Parameter(Mandatory)][string[]]$Names)
    $snapshot = [ordered]@{ LOCALAPPDATA = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process'); Values = @{} }
    foreach ($name in $Names) { $snapshot.Values[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    return $snapshot
}

function Assert-TTE2EParentEnvironmentUnchanged {
    param([Parameter(Mandatory)]$Snapshot)
    [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process') | Should -BeExactly $Snapshot.LOCALAPPDATA
    foreach ($name in $Snapshot.Values.Keys) { [Environment]::GetEnvironmentVariable($name, 'Process') | Should -BeExactly $Snapshot.Values[$name] }
}

function New-TTE2EProcessStartInfo {
    param([Parameter(Mandatory)][string]$Executable, [Parameter(Mandatory)][string[]]$Arguments, [Parameter(Mandatory)][string]$LocalAppData, [Parameter(Mandatory)][System.Collections.IDictionary]$Environment)
    if (!(Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'pwsh cannot be resolved.' }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['LOCALAPPDATA'] = $LocalAppData
    foreach ($key in $Environment.Keys) { $startInfo.Environment[[string]$key] = [string]$Environment[$key] }
    foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add([string]$argument) }
    return $startInfo
}

function Assert-TTE2EPathUnderRoot {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (![IO.Path]::GetFullPath($Path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Path escaped test-owned root: $Path" }
}

function Remove-TTE2EOwnedRoot {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedPrefix)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (!$fullPath.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($fullPath) -notlike ($ExpectedPrefix + '*')) { throw "Refusing cleanup of state not conclusively owned by this fixture: $fullPath" }
    if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop }
    if (Test-Path -LiteralPath $fullPath) { throw "Owned fixture cleanup failed: $fullPath" }
}

function Get-TTE2EDescendantProcesses {
    param([Parameter(Mandatory)][int]$RootProcessId)
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
    $known = [Collections.Generic.HashSet[int]]::new()
    [void]$known.Add($RootProcessId)
    $descendants = [Collections.Generic.List[object]]::new()
    do {
        $added = $false
        foreach ($process in $processes) {
            if (!$known.Contains([int]$process.ProcessId) -and $known.Contains([int]$process.ParentProcessId)) {
                [void]$known.Add([int]$process.ProcessId)
                $descendants.Add($process)
                $added = $true
            }
        }
    } while ($added)
    return @($descendants)
}

function Test-TTE2EOwnedProcessIdentity {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process, [Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][long]$StartTimeUtcTicks)
    try {
        $Process.Refresh()
        return (!$Process.HasExited -and $Process.Id -eq $ProcessId -and $Process.StartTime.ToUniversalTime().Ticks -eq $StartTimeUtcTicks)
    }
    catch { return $false }
}

function Stop-TTE2EOwnedProcess {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process, [Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][long]$StartTimeUtcTicks, [int]$TimeoutMilliseconds = 5000)
    if (Test-TTE2EOwnedProcessIdentity -Process $Process -ProcessId $ProcessId -StartTimeUtcTicks $StartTimeUtcTicks) {
        $Process.Kill($true)
        if (!$Process.WaitForExit($TimeoutMilliseconds)) { throw "Owned fixture process did not exit after bounded cleanup: pid=$ProcessId" }
    }
}

function Wait-TTE2EProcessAndPipes {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][System.Threading.Tasks.Task[string]]$StandardOutputTask,
        [Parameter(Mandatory)][System.Threading.Tasks.Task[string]]$StandardErrorTask,
        [Parameter(Mandatory)][int]$TimeoutMilliseconds,
        [int]$PipeTimeoutMilliseconds = 5000,
        [string]$EvidencePath,
        [long]$MaximumEvidenceBytes = 1048576
    )
    if (!$Process.WaitForExit($TimeoutMilliseconds)) { throw "Owned fixture process timed out: pid=$($Process.Id)" }
    if (!$StandardOutputTask.Wait($PipeTimeoutMilliseconds)) { throw "Owned fixture stdout did not close: pid=$($Process.Id)" }
    if (!$StandardErrorTask.Wait($PipeTimeoutMilliseconds)) { throw "Owned fixture stderr did not close: pid=$($Process.Id)" }
    $evidence = $null
    if ($EvidencePath) {
        if (!(Test-Path -LiteralPath $EvidencePath -PathType Leaf)) { throw "Owned fixture process did not produce evidence: pid=$($Process.Id)" }
        $info = Get-Item -LiteralPath $EvidencePath -ErrorAction Stop
        if ($info.Length -gt $MaximumEvidenceBytes) { throw "Owned fixture evidence exceeds the configured bound ($MaximumEvidenceBytes bytes): $EvidencePath" }
        $evidence = [IO.File]::ReadAllText($EvidencePath)
        if ([Text.Encoding]::UTF8.GetByteCount($evidence) -gt $MaximumEvidenceBytes) { throw "Owned fixture evidence exceeds the configured bound ($MaximumEvidenceBytes bytes): $EvidencePath" }
    }
    return [pscustomobject]@{ ExitCode = $Process.ExitCode; StandardOutput = $StandardOutputTask.Result; StandardError = $StandardErrorTask.Result; Evidence = $evidence }
}

function New-TTE2ELoopbackEndpoint {
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')][AllowEmptyString()][string]$ResponseBody,
        [Parameter(Mandatory, ParameterSetName = 'Sequence')][ValidateNotNullOrEmpty()][string[]]$ResponseBodies
    )
    if (-not ('TTE2ELoopbackEndpoint' -as [type])) {
        $source = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class TTE2ELoopbackEndpoint : IDisposable {
    private const int MaximumResponses = 32;
    private readonly HttpListener listener = new HttpListener();
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private readonly string[] responseBodies;
    private readonly bool repeatSingleResponse;
    private readonly Task listenerTask;
    private readonly object evidenceLock = new object();
    private readonly List<int> responseIndices = new List<int>();
    private readonly List<int> requestOrder = new List<int>();
    private int requestCount;
    private int disposed;
    private bool sequenceExhausted;
    private string lastPath = "";
    private string lastMethod = "";
    private string lastBody = "";
    public int RequestCount => Volatile.Read(ref requestCount);
    public int[] ResponseIndices { get { lock (evidenceLock) return responseIndices.ToArray(); } }
    public int[] RequestOrder { get { lock (evidenceLock) return requestOrder.ToArray(); } }
    public bool SequenceExhausted { get { lock (evidenceLock) return sequenceExhausted; } }
    public bool IsStopped => listenerTask.IsCompleted;
    public string LastPath => Volatile.Read(ref lastPath);
    public string LastMethod => Volatile.Read(ref lastMethod);
    public string LastBody => Volatile.Read(ref lastBody);
    public string Url { get; }
    public TTE2ELoopbackEndpoint(string[] responseBodies, bool repeatSingleResponse) {
        if (responseBodies == null || responseBodies.Length == 0) throw new ArgumentException("At least one response body is required.", nameof(responseBodies));
        if (responseBodies.Length > MaximumResponses) throw new ArgumentOutOfRangeException(nameof(responseBodies), "The loopback response sequence is limited to 32 entries.");
        this.repeatSingleResponse = repeatSingleResponse;
        this.responseBodies = (string[])responseBodies.Clone();
        for (int i = 0; i < this.responseBodies.Length; i++) this.responseBodies[i] = this.responseBodies[i] ?? "";
        var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        Url = "http://127.0.0.1:" + port;
        listener.Prefixes.Add(Url + "/");
        listener.Start();
        listenerTask = Task.Run(async () => {
            while (!cancellation.IsCancellationRequested) {
                HttpListenerContext context = null;
                try {
                    context = await listener.GetContextAsync().ConfigureAwait(false);
                    int requestNumber = Interlocked.Increment(ref requestCount);
                    int responseIndex;
                    lock (evidenceLock) {
                        responseIndex = repeatSingleResponse ? 0 : requestNumber - 1;
                        if (responseIndex >= this.responseBodies.Length) {
                            responseIndex = -1;
                            sequenceExhausted = true;
                        }
                        // Keep bounded evidence for each configured response and the first unexpected request.
                        if (requestOrder.Count < MaximumResponses + 1) {
                            requestOrder.Add(requestNumber);
                            responseIndices.Add(responseIndex);
                        }
                    }
                    Volatile.Write(ref lastPath, context.Request.Url.AbsolutePath);
                    Volatile.Write(ref lastMethod, context.Request.HttpMethod);
                    using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
                        Volatile.Write(ref lastBody, await reader.ReadToEndAsync().ConfigureAwait(false));
                    if (responseIndex < 0) {
                        context.Response.StatusCode = 503;
                        context.Response.ContentType = "text/plain";
                        context.Response.ContentLength64 = 0;
                        context.Response.Close();
                        continue;
                    }
                    var payload = Encoding.UTF8.GetBytes(this.responseBodies[responseIndex]);
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json";
                    context.Response.ContentLength64 = payload.Length;
                    await context.Response.OutputStream.WriteAsync(payload, 0, payload.Length).ConfigureAwait(false);
                    context.Response.Close();
                } catch (HttpListenerException) { break; }
                  catch (ObjectDisposedException) { break; }
                  catch { if (context != null) { try { context.Response.Abort(); } catch {} } }
            }
        });
    }
    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        cancellation.Cancel();
        try { listener.Stop(); } catch {}
        try { listener.Close(); } catch {}
        if (!listenerTask.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Loopback endpoint listener did not stop within five seconds.");
        cancellation.Dispose();
    }
}
'@
        Add-Type -TypeDefinition $source -ErrorAction Stop
    }
    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        return [TTE2ELoopbackEndpoint]::new([string[]]@($ResponseBody), $true)
    }
    if ($ResponseBodies.Count -gt 32) { throw 'The loopback response sequence is limited to 32 entries.' }
    return [TTE2ELoopbackEndpoint]::new([string[]]$ResponseBodies, $false)
}

function Stop-TTE2ELoopbackEndpoint {
    param([Parameter(Mandatory)]$Endpoint)
    $Endpoint.Dispose()
}

function New-TTE2EDeterministicEmbeddingEndpoint {
    if (-not ('TTE2EDeterministicEmbeddingEndpoint' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
public sealed class TTE2EDeterministicEmbeddingEndpoint : IDisposable {
    private readonly HttpListener listener = new HttpListener();
    private readonly CancellationTokenSource stop = new CancellationTokenSource();
    private readonly Task loop;
    private int requests, tags, embeds;
    private readonly object evidenceLock = new object();
    private readonly List<string> requestEvidence = new List<string>();
    public string Url { get; }
    public int RequestCount => Volatile.Read(ref requests);
    public int TagCount => Volatile.Read(ref tags);
    public int EmbedCount => Volatile.Read(ref embeds);
    public string[] RequestEvidence { get { lock (evidenceLock) return requestEvidence.ToArray(); } }
    public TTE2EDeterministicEmbeddingEndpoint() {
        var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
        Url = "http://127.0.0.1:" + port;
        listener.Prefixes.Add(Url + "/"); listener.Start();
        loop = Task.Run(async () => {
            while (!stop.IsCancellationRequested) {
                HttpListenerContext context = null;
                try {
                    context = await listener.GetContextAsync().ConfigureAwait(false);
                    int requestNumber = Interlocked.Increment(ref requests);
                    string body;
                    string path = context.Request.Url.AbsolutePath;
                    string type = "other";
                    if (path == "/api/tags" && context.Request.HttpMethod == "GET") type = "tags";
                    else if (path == "/api/embed" && context.Request.HttpMethod == "POST") type = "embed";
                    lock (evidenceLock) {
                        if (requestEvidence.Count < 1024)
                            requestEvidence.Add(System.Text.Json.JsonSerializer.Serialize(new { requestNumber, path, type, timestampUtc = DateTimeOffset.UtcNow.ToString("O") }));
                    }
                    if (type == "tags") {
                        Interlocked.Increment(ref tags);
                        body = "{\"models\":[{\"name\":\"scenario-a-embedding\",\"digest\":\"sha256:scenario-a-fixture-v1\"}]}";
                    } else if (type == "embed") {
                        Interlocked.Increment(ref embeds);
                        string input; using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding)) input = await reader.ReadToEndAsync().ConfigureAwait(false);
                        using (var document = System.Text.Json.JsonDocument.Parse(input)) {
                            var items = document.RootElement.GetProperty("input");
                            var rows = new string[items.GetArrayLength()];
                            for (int i = 0; i < rows.Length; i++) rows[i] = "[0.6,0.8,0]";
                            body = "{\"embeddings\":[" + string.Join(",", rows) + "]}";
                        }
                    } else { context.Response.StatusCode = 404; context.Response.Close(); continue; }
                    var bytes = Encoding.UTF8.GetBytes(body); context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json"; context.Response.ContentLength64 = bytes.Length;
                    await context.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false); context.Response.Close();
                } catch (HttpListenerException) { break; } catch (ObjectDisposedException) { break; }
                  catch { if (context != null) { try { context.Response.StatusCode = 400; context.Response.Close(); } catch {} } }
            }
        });
    }
    public void Dispose() {
        stop.Cancel(); try { listener.Stop(); } catch {} try { listener.Close(); } catch {}
        if (!loop.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Embedding endpoint shutdown timed out.");
        stop.Dispose();
    }
}
'@ -ErrorAction Stop
    }
    return [TTE2EDeterministicEmbeddingEndpoint]::new()
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsqrplMUnDiBkR
# 6U23ss9nDszRXcBzr0mXfceDYorFIKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC6
# STiplQXmm+JoC0HanDHyLrOF6f5q6A+LZj2w1A8aWzANBgkqhkiG9w0BAQEFAASC
# AYCt+GObz2OyYxYFrU5pvApfrq9pnltoatxJuvxxY/Iv3GueWN52j87MY5GgmGRG
# dYZIwAF97Hvn01Qz3rCOgfv4FGzltace8wCml9tm6zNpoANS+X+wu9tYrmcxtpmr
# CEnQnIhWTeiaJONe/tyLPj9b0o5yuQpwiZ3mYQqRo0XzXeKdyTUHWiP9MOe/lSzj
# beZlxRHRY6XKAm1sIUTlIVtUnCJ6+VirqHZbfbSmPAW9s9vtbgjhkZ6U1E7r7Ejv
# fo+WkSPY6pFEvzQt2TS5tMIhuIfaEYAoymddQe0odKb69d3Zdk1bmxrg2/gvAQ2l
# WW43xvoug1caj6GCrlEfTnnzmmN8+5ay9a33fJ8orHFW0VfIIzpFCdWsP2KwsoCz
# hxPZJMCiUr8ykArzvAwhvAXQohrcSQwCvO112IPCwoofg27n1aP7e6bELW2VMT/E
# /4MlG4ZHeiEK1MxmIHCMXgMz5iCtfcCZPDjhw5qHiKNnln18RqyPkKkD1GKoo2r5
# S8WhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTA5MDMxNjM3WjAvBgkqhkiG
# 9w0BCQQxIgQgBcl/nQzz+2LssS4GP0vbIggtoipl6JER2xTyKsqCWFcwDQYJKoZI
# hvcNAQEBBQAEggIATyNVpYx00Hq3JlZOyKjCEhMB4pLkWeXodahvM9L39ME8pxy1
# i8Zo4cb5q3wlepdH7odY0ifxXZx/wT0Ojle895140CqBs/ZnkpZ46rV3jIpRPnCW
# PVpOQgjjxmtCX7M6OLbQbbpkRHUoPqZ/UTo0UldZW4K7jfDMnVdjA1rUqHcdrl19
# R45J1l86hJS61tAVw4ks+ZcTCFCDNUpIukUv/bAUm0eWnFXxX4Fw3LXRAjXL7vre
# 2V2y3gPbGuzQSDMf0POcZ29uzhosP0D29tvSZ7lDmo7Fdrb3KdE/1D5p6633Sf5E
# yz+HVXyW54RFlJaL2Axb1feBiV2ZPl+wwtR+V3RCuhWsPBf/HyGou/RLC++M2qhi
# nPk7MyuEKQKwLXKdUUlkpb4OjjZuu33S2P0L+03vefA4Q7boFgQZ2YpoMQxdWprL
# LxPjLHbze5i0jx0ir13SHXeDWz/qsjeES/gn/BF1XQNURffXFhn2figWbhtcEyBe
# aCBIlHofiAI8aNWkci5GLlcJLbinoMFjm4JKjKrprPUzOZ5u4kofgxjJHEao6V0z
# 1Piu/VkEwYfcPnGN+cmIF32U3DnotFK8rb2ugB+C8Y8/PWdqnqtxOTPetMydnUwW
# KFqRB7xkjs2O4iTJ3ydrWZw/F7Bd9sGmWthkPQd5qje/cQncx2W+7Y5qsnI=
# SIG # End signature block
