$inner = '"CVE-2022-41678"'
$parts = $inner -split ','
$items = $parts | ForEach-Object {
    $clean = $_.Trim()
    $clean = $clean.Trim('"')
    $clean = $clean.Trim('"')
    $clean = $clean.Trim()
    $clean
}
Write-Host $items[0].GetType().FullName
Write-Host "Value: '$($items[0])'"
