$items = ('"CVE-2022-41678"') | ForEach-Object {
    $clean = $_.Trim()
    $clean = $clean.Trim('"')
    $clean = $clean.Trim()
    $clean
}
Write-Host $items[0].GetType().FullName
Write-Host $items[0]
