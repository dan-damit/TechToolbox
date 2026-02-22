# Code Analysis Report
Generated: 02/21/2026 21:36:05

## Mode
ModuleReview

## Summary
# Module Overview

The TechToolbox PowerShell module is a comprehensive toolset designed for system administrators, network engineers, and security professionals to perform various tasks across Windows environments. The module includes numerous cmdlets that offer functionalities such as software deployment, system information retrieval, network diagnostics, and security analysis.

## Key Features

- **Software Deployment**: Supports deploying applications, managing MSI packages, and handling Epicor Edge Agent installations.
- **System Information Retrieval**: Provides detailed snapshots of system configurations, hardware specs, and service statuses.
- **Network Diagnostics**: Enables subnet scanning, port checking, and network path tracing.
- **Security Analysis**: Includes tools for testing email headers for authentication, analyzing file paths with alternate credentials, and performing downloads cleanup.

## Compatibility

TechToolbox is compatible with Windows PowerShell 5.1 and later versions. It leverages .NET Framework components to perform operations that require elevated privileges, ensuring robust functionality across different environments.

# Cmdlets Reference

## Deploying Software

### `Invoke-SoftwareDeployment`

Deploys software packages to target machines using remote execution techniques.

**Syntax**
```powershell
Invoke-SoftwareDeployment -TargetHosts <string[]> -InstallPath <string> [-UseCredential] [<CommonParameters>]
```

**Example**
```powershell
Invoke-SoftwareDeployment -TargetHosts @("PC01", "PC02") -InstallPath "\\Server\Software\FirefoxSetup.exe" -UseCredential
```

## System Information

### `Get-SystemSnapshot`

Retrieves a detailed snapshot of the system, including OS details, CPU information, memory usage, disk space, network configurations, and service statuses.

**Syntax**
```powershell
Get-SystemSnapshot [-IncludeServices] [<CommonParameters>]
```

**Example**
```powershell
Get-SystemSnapshot -IncludeServices
```

### `Get-WindowsProductKey`

Retrieves the Windows product key installed on the system.

**Syntax**
```powershell
Get-WindowsProductKey [<CommonParameters>]
```

**Example**
```powershell
Get-WindowsProductKey
```

## Network Diagnostics

### `Test-NetConnectionEx`

Extends the functionality of Test-NetConnection with additional features like banner grabbing and subnet scanning.

**Syntax**
```powershell
Test-NetConnectionEx -Target <string> [-Port <int>] [-SubnetScan] [-HttpBanner] [<CommonParameters>]
```

**Example**
```powershell
Test-NetConnectionEx -Target "192.168.1.0/24" -Port 80 -SubnetScan -HttpBanner
```

## Security Analysis

### `Test-MailHeaderAuth`

Analyzes email headers to determine authentication status and phishing risk.

**Syntax**
```powershell
Test-MailHeaderAuth [-HeadersText <string>] [-Path <string>] [-FromClipboard] [-Format <string>] [<CommonParameters>]
```

**Example**
```powershell
Test-MailHeaderAuth -Path "C:\EmailHeaders.txt" -Format Markdown
```

### `Test-PathAs`

Tests whether a path exists using alternate credentials.

**Syntax**
```powershell
Test-PathAs -Path <string> -Credential <PSCredential> [<CommonParameters>]
```

**Example**
```powershell
$cred = Get-Credential "Domain\User"
Test-PathAs -Path "\\Server\Share\File.txt" -Credential $cred
```

## Helper Cmdlets

### `Get-RemoteInstalledSoftware`

Retrieves a list of installed software on remote machines.

**Syntax**
```powershell
Get-RemoteInstalledSoftware [-IncludeAppx] [<CommonParameters>]
```

**Example**
```powershell
Get-RemoteInstalledSoftware -IncludeAppx
```

# Detailed Cmdlet Descriptions

## Deploying Software

### `Invoke-SoftwareDeployment`

Deploys software packages to target machines using remote execution techniques.

**Syntax**
```powershell
Invoke-SoftwareDeployment -TargetHosts <string[]> -InstallPath <string> [-UseCredential] [<CommonParameters>]
```

**Parameters**

- `-TargetHosts`: Specifies the list of hostnames or IP addresses where the software will be deployed.
- `-InstallPath`: The path to the installation file, either local or network accessible.
- `-UseCredential`: Indicates whether to use credentials for remote execution.

**Example**
```powershell
Invoke-SoftwareDeployment -TargetHosts @("PC01", "PC02") -InstallPath "\\Server\Software\FirefoxSetup.exe" -UseCredential
```

## System Information

### `Get-SystemSnapshot`

Retrieves a detailed snapshot of the system, including OS details, CPU information, memory usage, disk space, network configurations, and service statuses.

**Syntax**
```powershell
Get-SystemSnapshot [-IncludeServices] [<CommonParameters>]
```

**Parameters**

- `-IncludeServices`: If specified, includes service status in the snapshot.

**Example**
```powershell
Get-SystemSnapshot -IncludeServices
```

### `Get-WindowsProductKey`

Retrieves the Windows product key installed on the system.

**Syntax**
```powershell
Get-WindowsProductKey [<CommonParameters>]
```

**Example**
```powershell
Get-WindowsProductKey
```

## Network Diagnostics

### `Test-NetConnectionEx`

Extends the functionality of Test-NetConnection with additional features like banner grabbing and subnet scanning.

**Syntax**
```powershell
Test-NetConnectionEx -Target <string> [-Port <int>] [-SubnetScan] [-HttpBanner] [<CommonParameters>]
```

**Parameters**

- `-Target`: Specifies the target IP address, hostname, or CIDR block.
- `-Port`: The port number to check for connectivity and banner grabbing.
- `-SubnetScan`: Performs a subnet scan using the specified port.
- `-HttpBanner`: Retrieves the HTTP banner from the specified port.

**Example**
```powershell
Test-NetConnectionEx -Target "192.168.1.0/24" -Port 80 -SubnetScan -HttpBanner
```

## Security Analysis

### `Test-MailHeaderAuth`

Analyzes email headers to determine authentication status and phishing risk.

**Syntax**
```powershell
Test-MailHeaderAuth [-HeadersText <string>] [-Path <string>] [-FromClipboard] [-Format <string>] [<CommonParameters>]
```

**Parameters**

- `-HeadersText`: The raw email header text.
- `-Path`: Path to a file containing the email headers.
- `-FromClipboard`: Reads headers from the clipboard (Windows only).
- `-Format`: Specifies the output format ('Summary', 'Markdown', 'Object', 'Json').

**Example**
```powershell
Test-MailHeaderAuth -Path "C:\EmailHeaders.txt" -Format Markdown
```

### `Test-PathAs`

Tests whether a path exists using alternate credentials.

**Syntax**
```powershell
Test-PathAs -Path <string> -Credential <PSCredential> [<CommonParameters>]
```

**Parameters**

- `-Path`: The file system or UNC path to test.
- `-Credential`: The credential to impersonate while testing the path.

**Example**
```powershell
$cred = Get-Credential "Domain\User"
Test-PathAs -Path "\\Server\Share\File.txt" -Credential $cred
```

## Helper Cmdlets

### `Get-RemoteInstalledSoftware`

Retrieves a list of installed software on remote machines.

**Syntax**
```powershell
Get-RemoteInstalledSoftware [-IncludeAppx] [<CommonParameters>]
```

**Parameters**

- `-IncludeAppx`: If specified, includes AppX/MSIX packages in the results.

**Example**
```powershell
Get-RemoteInstalledSoftware -IncludeAppx
```

# Installation and Usage

## Installation

To install TechToolbox, use the following command:

```powershell
Install-Module -Name TechToolbox
```

Ensure you have the necessary permissions to install modules. If using a proxy, configure your PowerShell session accordingly.

## Importing the Module

After installation, import the module into your PowerShell session with:

```powershell
Import-Module TechToolbox
```

## Using Cmdlets

Each cmdlet comes with comprehensive help documentation that can be accessed using `Get-Help`. For example:

```powershell
Get-Help Invoke-SoftwareDeployment -Full
```

This provides detailed usage instructions, parameter descriptions, and examples.

# Troubleshooting and Support

For troubleshooting issues or obtaining support, refer to the official TechToolbox GitHub repository documentation. The repository includes a FAQ section and an issue tracker for reporting problems or requesting features.

# Conclusion

TechToolbox is a versatile PowerShell module that simplifies many administrative tasks across Windows environments. By leveraging its extensive cmdlets, administrators can streamline software deployment, gather system information, perform network diagnostics, and enhance security analysis, leading to more efficient IT management practices.

## Files Included in Analysis
This report summarizes analysis of the provided script or module. The full source code is intentionally omitted for clarity and to reduce report size.
