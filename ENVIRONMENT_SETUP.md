# TechToolbox Environment Setup

## Overview
This document describes the automatic environment setup that has been configured for the TechToolbox project.

## Installed Tools

The following tools have been installed in the shared environment to support the TechToolbox build and test pipeline:

### .NET SDK 10.0.112
- **Location**: `$env:LOCALAPPDATA\dotnet`
- **Status**: ✓ Installed
- **Includes**: .NET Runtime 10.0.12, ASP.NET Core Runtime 10.0.12, Windows Desktop Runtime 10.0.12
- **Purpose**: Build, test, and run the TechToolbox.Agent solution

### Node.js 20.11.0 with npm 10.2.4
- **Location**: `$env:LOCALAPPDATA\nodejs`
- **Status**: ✓ Installed
- **Purpose**: Support for MCP (Model Context Protocol) servers used by the TechAgent

### uv 0.5.3 (Python Package Manager)
- **Location**: `$env:LOCALAPPDATA\uv`
- **Status**: ✓ Installed
- **Purpose**: Support for Python-based MCP servers (git integration)

## PATH Configuration

A PowerShell profile has been created to automatically add these tools to the PATH in new PowerShell sessions:

**File**: `C:\Users\OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`

This profile prepends the tool directories to the PATH environment variable for all future PowerShell sessions.

## Verification

To verify the tools are available in a fresh PowerShell session:

```powershell
dotnet --version    # Should show 10.0.112
node --version      # Should show v20.11.0
npm --version       # Should show 10.2.4
uv --version        # Should show 0.5.3
```

For child-process runtime consistency in this repository:

```powershell
$env:DOTNET_ROOT           # Should point to $env:LOCALAPPDATA\dotnet
$env:DOTNET_ROLL_FORWARD   # Should be LatestMajor unless you explicitly override it
```

## One-time user bootstrap (dev machine)

To persist the .NET runtime policy for your user profile (no system-wide change), run:

```powershell
.\Set-UserDotNetEnvironment.ps1
```

Script: `Set-UserDotNetEnvironment.ps1` (repo root).  
This sets user-scoped `DOTNET_ROOT`, `DOTNET_ROOT_X64`, `DOTNET_ROLL_FORWARD=LatestMajor`, and `DOTNET_MULTILEVEL_LOOKUP=1`.

## MCP Servers

The following MCP servers are now available for the TechAgent:

1. **techtoolbox-local**: .NET-based local adapter (requires .NET SDK)
2. **filesystem**: File system operations (requires Node.js)
3. **powershell**: PowerShell execution (requires Node.js)
4. **ripgrep**: Code search (requires Node.js)
5. **tavily**: Web search (requires Node.js)
6. **git**: Git operations (requires uvx/Python)

## Known Issues

### .NET 8.0 Runtime

The test projects target `net8.0`. If only .NET 10 runtime is installed, testhost can fail without roll-forward settings in child processes.

**Current setup behavior**: `Setup-Environment.ps1` now sets `DOTNET_ROLL_FORWARD=LatestMajor` (when not already set) and exports `DOTNET_ROOT`, so child processes can resolve runtime policy consistently.

If you need strict no-major-roll-forward behavior, set `DOTNET_ROLL_FORWARD` explicitly in your shell before running tests.

## Next Steps

1. **Start a new PowerShell session** - The PATH configuration in the profile will apply automatically
2. **Run the TechAgent** - The environment is now configured to support all MCP servers
3. **Run tests** - Use `dotnet test` command as normal

## Environment Isolation

Since this is a shared environment, the tools are installed in user-local directories (`AppData\Local`) rather than system-wide directories. This isolates the installation to the current user and avoids affecting other users on the system.
