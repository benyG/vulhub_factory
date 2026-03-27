$content = Get-Content -Path environments.toml -Raw -Encoding UTF8
$blocks = ($content -split '\[\[environment\]\]') | Where-Object { $_.Trim() }
$allowed = "rce","deserialization","sqli","ssrf","lfi","xxe","auth_bypass","command_injection","ssti","path_traversal","unauth_access"
$priority = [ordered]@{
    'rce' = 'rce'
    'remote code execution' = 'rce'
    'deserialization' = 'deserialization'
    'sql injection' = 'sqli'
    'ssrf' = 'ssrf'
    'file inclusion' = 'lfi'
    'local file inclusion' = 'lfi'
    'path traversal' = 'path_traversal'
    'directory traversal' = 'path_traversal'
    'xxe' = 'xxe'
    'ssti' = 'ssti'
    'auth bypass' = 'auth_bypass'
    'authentication bypass' = 'auth_bypass'
    'command injection' = 'command_injection'
    'environment injection' = 'command_injection'
    'expression injection' = 'command_injection'
    'file upload' = 'command_injection'
    'info disclosure' = 'unauth_access'
    'dos' = 'unauth_access'
}
function Parse-Array($value) {
    if (-not $value) { return @() }
    $trimmed = $value.Trim()
    if ($trimmed -eq '') { return @() }
    if ($trimmed.StartsWith('[') -and $trimmed.EndsWith(']')) {
        try {
            $parsed = ConvertFrom-Json $trimmed
            return ,$parsed
        } catch {
        }
    }
    $inner = $trimmed -replace '\r?\n', ''
    $inner = $inner.Trim()
    $inner = $inner.Trim('[', ']')
    if (-not $inner) { return @() }
    return ($inner -split ',') | ForEach-Object {
        $clean = $_.Trim()
        $clean = $clean.Trim('"')
        $clean = $clean.Trim()
        $clean
    }
}
function Parse-Dockerfile($value) {
    $result = @{}
    if (-not $value) { return $result }
    $inner = $value.Trim()
    $inner = $inner.Trim('{', '}')
    if (-not $inner) { return $result }
    $pattern = '"([^"=]+)"\s*=\s*"([^\"]+)"'
    $matches = [regex]::Matches($inner, $pattern)
    foreach ($match in $matches) {
        $result[$match.Groups[1].Value] = $match.Groups[2].Value
    }
    return $result
}
function Map-Category($tags) {
    foreach ($tag in $tags) {
        $lower = $tag.ToLower()
        foreach ($needle in $priority.Keys) {
            if ($lower.Contains($needle)) {
                return $priority[$needle]
            }
        }
    }
    return 'unauth_access'
}
function Extract-Version($dockerfile) {
    foreach ($key in $dockerfile.Keys) {
        if ($key -match ':') {
            return ($key -split ':', 2)[1]
        }
        $value = $dockerfile[$key]
        if ($value -match '/') {
            $parts = $value.Split('/')
            return $parts[-1]
        }
        return $value
    }
    return ''
}
function Derive-CveId($cveArray, $path, $name) {
    if ($cveArray.Count -gt 0) {
        $first = $cveArray[0]
        if ($first -and -not [string]::IsNullOrWhiteSpace($first)) {
            return $first
        }
    }
    if ($path) {
        $segments = $path.Split('/') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($segments.Count -gt 0) { return $segments[-1] }
    }
    return $name
}
function Extract-Field($block, $field) {
    $pattern = "^$field\s*=\s*(.+)$"
    foreach ($line in ($block -split '\r?\n')) {
        $trim = $line.Trim()
        if ($trim -match $pattern) {
            return $Matches[1].Trim()
        }
    }
    return ''
}
$categories = @{}
foreach ($cat in $allowed) { $categories[$cat] = @() }
foreach ($block in $blocks) {
    $name = (Extract-Field $block 'name') -replace '^"(.*)"$', '$1'
    $app = (Extract-Field $block 'app') -replace '^"(.*)"$', '$1'
    $path = (Extract-Field $block 'path') -replace '^"(.*)"$', '$1'
    $tagsValue = Extract-Field $block 'tags'
    $cveValue = Extract-Field $block 'cve'
    $dockerfileValue = Extract-Field $block 'dockerfile'
    $tags = Parse-Array($tagsValue)
    $cveArray = Parse-Array($cveValue)
    $dockerfile = Parse-Dockerfile($dockerfileValue)
    $category = Map-Category($tags)
    $version = Extract-Version($dockerfile)
    $entry = [ordered]@{
        cve_id = Derive-CveId($cveArray, $path, $name)
        software = $app
        affected_version = $version
        category = $category
        cvss_score = 0.0
        difficulty = 'medium'
        vulhub_path = $path
        flag_placement = $null
        flag_path = $null
        solve_summary = $null
        vpn_required = $true
    }
    if (-not $name -and -not $path) { continue }
    $categories[$category] += $entry
}
$metadata = [ordered]@{
    source = 'Vulhub GitHub Repository (https://github.com/vulhub/vulhub)'
    generated = '2026-03-26'
    total_entries = ($categories.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    criteria = 'CVSS >= 7.0, clear exploitation steps, CTF-suitable, docker-compose available'
}
$output = [ordered]@{
    metadata = $metadata
    categories = [ordered]@{}
}
foreach ($cat in $allowed) { $output.categories[$cat] = $categories[$cat] }
$output | ConvertTo-Json -Depth 5 | Set-Content -Path vulhub_cve_list.json -Encoding UTF8
