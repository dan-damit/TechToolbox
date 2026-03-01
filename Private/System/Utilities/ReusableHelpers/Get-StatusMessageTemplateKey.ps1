function Get-StatusMessageTemplateKey {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Healthy', 'Warning', 'Critical', 'Unsupported')]
        [string]$StatusCode,

        [Parameter(Mandatory)]
        [hashtable]$Templates
    )

    $TemplateKeyMap = @{
        Healthy     = 'StatusMessageTemplate_Healthy'
        Warning     = 'StatusMessageTemplate_Warning'
        Critical    = 'StatusMessageTemplate_Critical'
        Unsupported = 'StatusMessageTemplate_Unsupported'
    }

    $TemplateKey = $TemplateKeyMap[$StatusCode]

    if (-not $Templates.ContainsKey($TemplateKey)) {
        throw "Message template '$TemplateKey' is missing from messageTemplates.json. Add the required template and run the diagnostic again."
    }

    $Template = $Templates[$TemplateKey]

    if ($Template -notmatch '\{Condition\}') {
        throw "Message template '$TemplateKey' is missing the '{Condition}' placeholder. Update messageTemplates.json to include it."
    }

    if ($Template -notmatch '\{Context\}') {
        throw "Message template '$TemplateKey' is missing the '{Context}' placeholder. Update messageTemplates.json to include it."
    }

    return $TemplateKey
}
