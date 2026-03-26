$content = Get-Content -Raw -Path environments.toml -Encoding UTF8
$block = ($content -split '\[\[environment\]\]') | Where-Object { $_.Trim() } | Select-Object -First 6 | Select-Object -Last 1
$cveValue = ''
foreach ($line in ($block -split '\r?\n')) {
    $trim = $line.Trim()
    if ($trim -match '^cve\s*=\s*(.+)$') { $cveValue = $Matches[1]; break }
}
$items = ($cveValue -replace '\r?\n', '').Trim().Trim('[', ']') -split ','
$item = $items[0].Trim().Trim('"')
Write-Host "Raw item: '$item'"
Write-Host "Chars:"
$item.ToCharArray() | ForEach-Object { Write-Host ([int][char]$_) }
