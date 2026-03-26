$inner = '"CVE-2022-41678"'
$parts = $inner -split ','
Write-Host $parts.Count
Write-Host $parts[0].GetType().FullName
