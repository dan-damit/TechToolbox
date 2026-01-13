function Invoke-SCW {
    (Get-Module TechToolbox).Invoke({ Invoke-SanityCheck })
}
