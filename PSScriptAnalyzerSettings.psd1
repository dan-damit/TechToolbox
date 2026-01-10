# PSScriptAnalyzer settings
@{
    ExcludeRules = @(
        # add exclusions if needed
    )
    Rules        = @{
        PSUseApprovedVerbs                          = $true
        PSAvoidUsingWriteOutput                     = $true
        PSAvoidUsingWriteHost                       = $true
        PSAvoidGlobalVars                           = $true
        PSAvoidUsingCmdletAliases                   = $true
        PSUseConsistentWhitespace                   = $true
        PSProvideCommentHelp                        = $true
        PSUseShouldProcessForStateChangingFunctions = $true
    }
}
