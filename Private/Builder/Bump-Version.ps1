function Bump-Version {
    param([string]$Version)

    try {
        $v = [version]$Version
        return "{0}.{1}.{2}" -f $v.Major, $v.Minor, ($v.Build + 1)
    }
    catch {
        return $Version
    }
}