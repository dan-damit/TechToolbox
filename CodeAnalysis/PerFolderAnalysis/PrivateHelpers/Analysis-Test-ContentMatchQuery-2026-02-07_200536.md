# Code Analysis Report
Generated: 2/7/2026 8:05:36 PM

## Summary
 Here is my analysis and suggestions for the provided PowerShell function `Test-ContentMatchQuery`:

1. **Naming Conventions**: Follow PowerShell naming conventions, use PascalCase for functions (`TestContentMatchQuery` instead of `Test-ContentMatchQuery`). Also, consider adding a comment at the beginning explaining what the function does.

2. **Parameters Validation**: You can validate the parameters more rigorously using `[ValidateSet]` and `[AllowNullOrEmptyString]` attributes on parameters to make it more clear about which values are allowed for specific parameters.

3. **Comments**: Add more comments to the code, especially when a complex expression or logic is used. This makes it easier for others to understand your code.

4. **Error Handling**: Consider using `throw` statements to provide more descriptive error messages instead of returning false when an error occurs. You can also use custom errors and exception handling to improve the user experience.

5. **Function Organization**: Organize the function into smaller, more focused sections for better readability. For example, you could separate the logic for checking balanced parentheses, quotes, allowed property names, and normalization into distinct functions or blocks.

6. **Code Formatting**: Improve code formatting by using consistent spacing, line breaks, and indentation to make the code easier to read. Consider using PowerShell Core's Preferred Style (PSS) as a guide: https://github.com/PowerShell/StyleGuide

7. **Performance**: To improve performance, you could consider using compiled scripts or C# for complex expressions that run many times or use heavy processing. However, in this case, the function appears to be simple enough that any performance concerns might not warrant the additional complexity of using a different language.

8. **Test-driven Development (TDD)**: Adopting TDD practices can help ensure your code is well-designed and easy to maintain by writing tests before implementing the actual functionality. This ensures that you're focusing on writing code that solves specific problems, rather than trying to write a perfect piece of code upfront.

Here's an example of how some of these suggestions could be implemented:

```powershell
function Test-ContentMatchQuery {
    [CmdletBinding()]
    param(
        [ValidateScript({ param($value) [string]::IsNullOrWhiteSpace($value) -eq $false })][string]$Query,
        [AllowNullOrEmptyString()][string]$NormalizedQuery = $null,
        [Switch]$Normalize
    )

    # Add comments explaining what each section does
    # ...

    # Validate the parameters more rigorously using attributes
    if ([string]::IsNullOrWhiteSpace($Query)) {
        if ($NormalizedQuery) { $NormalizedQuery = $null; return }
        throw "The Query parameter is required."
    }

    # Improve error handling with custom errors and exception handling
    try {
        # ... (the rest of the code)
    } catch {
        Write-Error $_
    }
}
```

## Source Code
```powershell

function Test-ContentMatchQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [switch]$Normalize,
        [ref]$NormalizedQuery
    )

    # Trim and basic checks
    if ([string]::IsNullOrWhiteSpace($Query)) {
        if ($NormalizedQuery) { $NormalizedQuery.Value = $null }
        return $false
    }

    $q = $Query.Trim()

    # 1) Balanced parentheses
    $stack = 0
    foreach ($ch in $q.ToCharArray()) {
        if ($ch -eq '(') { $stack++ }
        elseif ($ch -eq ')') { $stack-- }
        if ($stack -lt 0) { return $false } # early close
    }
    if ($stack -ne 0) { return $false }     # unbalanced overall

    # 2) Balanced quotes (simple even-count check; covers most cases)
    $quoteArray = $q.ToCharArray() | Where-Object { $_ -eq '"' }
    $quoteCount = @($quoteArray).Count       # ensure array semantics
    if (($quoteCount % 2) -ne 0) { return $false }

    # 3) Allowed property names (adjust as you need)
    $allowed = @(
        'from', 'to', 'cc', 'bcc', 'participants',
        'subject', 'body', 'sent', 'received', 'attachment', 'attachments',
        'kind', 'size', 'importance'
    )

    $propMatches = [regex]::Matches($q, '(?i)\b([a-z]+)\s*:')
    # MatchCollection.Count is safe, but we don't need it—just iterate
    foreach ($m in $propMatches) {
        $prop = $m.Groups[1].Value.ToLowerInvariant()
        if ($allowed -notcontains $prop) { return $false }
    }

    # 4) Optional normalization for common wildcard mistakes
    $norm = $q
    if ($Normalize) {
        $norm = [regex]::Replace(
            $norm,
            '(?i)(from|to|cc|bcc)\s*:\s*\(\s*([^)]*)\s*\)',
            {
                param($m)
                $prop = $m.Groups[1].Value
                $inner = $m.Groups[2].Value
                # Split OR terms and quote them if they contain @ or * and aren't already quoted
                $parts = $inner -split '(?i)\s+OR\s+'
                $parts = $parts | ForEach-Object {
                    $p = $_.Trim()
                    if ($p -notmatch '^".*"$' -and ($p -match '[@\*]')) { '"' + $p + '"' } else { $p }
                }
                "${prop}:(" + ($parts -join ' OR ') + ")"
            }
        )
    }

    if ($NormalizedQuery) { $NormalizedQuery.Value = $norm }
    return $true
}

[SIGNATURE BLOCK REMOVED]

```
