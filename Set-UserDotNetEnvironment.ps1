#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DotNetRoot = "$env:LOCALAPPDATA\dotnet",
    [switch]$SkipCurrentProcessUpdate
)

if ([string]::IsNullOrWhiteSpace($DotNetRoot)) {
    throw "DotNetRoot cannot be empty."
}

$resolvedDotNetRoot = [Environment]::ExpandEnvironmentVariables($DotNetRoot)
if (-not (Test-Path -LiteralPath $resolvedDotNetRoot -PathType Container)) {
    throw "DotNetRoot path does not exist: $resolvedDotNetRoot"
}

$updates = [ordered]@{
    DOTNET_ROOT              = $resolvedDotNetRoot
    DOTNET_ROOT_X64          = $resolvedDotNetRoot
    DOTNET_ROLL_FORWARD      = 'LatestMajor'
    DOTNET_MULTILEVEL_LOOKUP = '1'
}

Write-Host "Setting user-scoped .NET environment variables..." -ForegroundColor Green
foreach ($entry in $updates.GetEnumerator()) {
    if ($PSCmdlet.ShouldProcess("User environment variable '$($entry.Key)'", "Set to '$($entry.Value)'")) {
        [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'User')
    }

    if (-not $SkipCurrentProcessUpdate) {
        Set-Item -Path ("Env:{0}" -f [string]$entry.Key) -Value ([string]$entry.Value)
    }
}

if (-not $SkipCurrentProcessUpdate) {
    Write-Host "`nUpdated current process environment as well." -ForegroundColor Green
}

Write-Host "`nCurrent values:" -ForegroundColor Cyan
foreach ($entry in $updates.GetEnumerator()) {
    Write-Host ("  {0}={1}" -f $entry.Key, [Environment]::GetEnvironmentVariable([string]$entry.Key, 'User'))
}

Write-Host "`nOpen a new terminal for all apps/sessions to pick up the User-level changes." -ForegroundColor Yellow
