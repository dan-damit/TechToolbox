
# Purge-ComplianceSearch

A PowerShell module for purging compliance search results.
Run the main execution script in the PurviewTools folder.

---------------------------------------------------------------------
### PurviewTools Module
### Version: 1.1.2
### Date   : 2026-01-07
### Author : Dan Damit

### Changes in 1.1.2:
- Hardened parameter handling: all SearchName params accept [object]
  and normalize via Resolve-SearchName (supports string/array/PSObject).
- Case-scoped operations aligned: use -Case only with Get-* cmdlets;
  removed -Case from New-ComplianceSearchAction.
- Invoke-HardDelete: added regex confirmation (YES/Y), try/catch,
  and identity-based monitoring when available.
- Wait-ForPurgeCompletion: logs terminal states only, guards props,
  appends (items: N) from Get-ComplianceSearch on success.
- Removed redundant New-MailboxOnlySearch.
- Minor UX/logging refinements for clean console + solid audit trail.
---------------------------------------------------------------------

### All comments are in the original script one dir up.

## Overview

This module provides functionality to purge compliance search results from the organization. It has been refactored from a single script into a modular structure using PowerShell module best practices.

## Contents

- **PurviewTools.psm1** - Module script containing core cmdlets
- **PurviewTools.psd1** - Module manifest with metadata and configuration
- Removed commenting mostly for brevity here.

## Installation

1. Clone or download this folder to your PowerShell modules directory:
    ```
    $PROFILE\Modules\PurviewTools\
    ```

2. Import the module:
    ```powershell
    Import-Module PurviewTools
    ```

## Usage

```powershell
..\MainExecutionScript\Purge-ComplianceSearch.ps1
```

## Requirements

- PowerShell 7+
- Appropriate Microsoft 365 permissions
- A Search Case to be opened in Purview for reference during runtime.