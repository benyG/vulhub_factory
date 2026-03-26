function Parse-Array($value) {
    if (-not $value) { return @() }
    $inner = $value -replace '\r?\n', ''
    $inner = $inner.Trim()
    $inner = $inner.Trim('[', ']')
    if (-not $inner) { return @() }
    $items = ($inner -split ',') | ForEach-Object {
        $clean = $_.Trim()
        $clean = $clean.Trim('"')
        $clean = $clean.Trim('"')
        $clean = $clean.Trim()
        $clean
    }
    return ,$items
}
$content = Get-Content -Path environments.toml -Raw
$blocks = ($content -split '\[\[environment\]\]') | Where-Object { $_.Trim() }
$count = 0
foreach ($block in $blocks) {
    $count++
    $cveArray = @()
    foreach ($line in ($block -split '\r?\n')) {
        $trim = $line.Trim()
        if ($trim -match '^cve\s*=\s*(.+)$') { $cveArray = Parse-Array($Matches[1]) }
    }
    if ($count -le 5 -and $cveArray.Count -gt 0) {
        Write-Host "Entry $count cve type $($cveArray[0].GetType().FullName) value '$($cveArray[0])'"
    }
    if ($count -ge 5) { break }
}
