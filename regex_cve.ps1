$text = [System.IO.File]::ReadAllText('vulhub_cve_list.json')
$pattern = '"software":\s*"Apache ActiveMQ".*?"cve_id":\s*"([^"]*)"'
$match = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
Write-Host "Matched cve_id: '$($match.Groups[1].Value)'"
Write-Host "Length: $($match.Groups[1].Value.Length)"
