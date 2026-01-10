
function Show-ProgressBanner {
    <#
    .SYNOPSIS
        Displays a progress banner for subnet scanning operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Current,

        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter(Mandatory)]
        [double]$DisplayPct,

        [Parameter(Mandatory)]
        [TimeSpan]$ETA
    )

    try {
        $pct = "{0:N1}" -f $DisplayPct
        $etaStr = $ETA.ToString("hh\:mm\:ss")

        Write-Progress `
            -Activity "Subnet Scan" `
            -Status   "Progress: $pct% | ETA: $etaStr" `
            -PercentComplete $DisplayPct `
            -CurrentOperation "Host $Current of $Total"
    }
    catch {
        # UI failures should never break a scan
    }
}