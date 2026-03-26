$value = '["CVE-2022-41678"]'
$inner = $value.Trim()
$inner = $inner.Trim('[', ']')
$pattern = ',(?=(?:[^"\n]*"[^"\n]*")*[^"\n]*$)'
$parts = [regex]::Split($inner, $pattern)
$parts | ForEach-Object { Write-Host "Part:'$_'" }
