
function Ensure-ExchangeOnlineModule {
    if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable |
            Where-Object { $_.Version -eq [version]'3.9.0' })) {
        Initialize-TechToolboxModules
    }
    Import-Module ExchangeOnlineManagement -RequiredVersion 3.9.0 -Force
}
