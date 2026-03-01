function Get-SystemTrustDiagnosticCore {
    param(
        [Parameter(Mandatory)]
        [string]$HelpersPath
    )

    $secureBoot = Get-SecureBootSection
    $tpm = Get-TPMSection
    $windowsTrust = Get-WindowsTrustSection
    $system = Get-SystemSection

    [PSCustomObject]@{
        SecureBoot   = $secureBoot
        TPM          = $tpm
        WindowsTrust = $windowsTrust
        System       = $system
    }
}
