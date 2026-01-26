
@{
    RootModule           = 'PurviewTools.psm1'
    ModuleVersion        = '1.1.2'
    GUID                 = 'b5e5c5f2-7a3f-4b4b-9e9e-1f6b2d4a5d11'
    Author               = 'Dan Damit'
    CompanyName          = 'Value Added Companies'
    Description          = 'Purview Compliance Search helpers: clone, waiters, guided purge, listings.'
    CompatiblePSEditions = @('Core')
    RequiredModules      = @(@{ ModuleName = 'ExchangeOnlineManagement'; ModuleVersion = '3.9.0' })

    FunctionsToExport    = @(
        'Import-ExchangeOnlineModule', `
            'Connect-SearchSession', `
            'Get-SearchDetails', `
            'Wait-ForSearchCompletion', `
            'Invoke-HardDelete', `
            'Wait-ForPurgeCompletion', `
            'Resolve-OrCreateSearch', `
            'Resolve-SearchName'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{ PSData = @{ Tags = @('Purview', 'Compliance', 'ExchangeOnline'); } }
}
