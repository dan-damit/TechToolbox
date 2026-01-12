@{
    RootModule           = 'TechToolbox.psm1'
    ModuleVersion        = '2.2.0'
    Author               = 'Dan Damit'
    CompanyName          = 'Value Added Companies'
    Description          = 'A technician-grade toolbox for automation, diagnostics, and enterprise workflows.'
    PowerShellVersion    = '7.5.3'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @() # Exported via TechToolbox.psm1
    CmdletsToExport      = @()
    VariablesToExport    = @('*')
    AliasesToExport      = @('*')
    RequiredModules      = @(@{ ModuleName = 'ExchangeOnlineManagement'; ModuleVersion = '3.9.0' })
    PrivateData          = @{
        PSData = @{
            Tags         = @('automation', 'networking', 'diagnostics', 'toolbox')
            ProjectUri   = 'https://github.com/dan-damit/Scripts-and-Snippets/tree/main/PowerShell/TechToolbox'
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ReleaseNotes = 'Initial release of TechToolbox.'
        }
    }
}
