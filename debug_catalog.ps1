$content = Get-Content -Path environments.toml -Raw -Encoding UTF8
$blocks = ($content -split '\[\[environment\]\]') | Where-Object { $_.Trim() }
function Parse-Array($value) {
    if (-not $value) { return @() }
    $inner = $value -replace '\r?\n', ''
    $inner = $inner.Trim()
    $inner = $inner.Trim('[', ']')
    if (-not $inner) { return @() }
    return ($inner -split ',') | ForEach-Object { $_.Trim().Trim('"') }
}
$count = 0
foreach ($block in $blocks) {
    $count++
    $name = ''
    $path = ''
    $cveArray = @()
    foreach ($line in ($block -split '\r?\n')) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        if ($trim -match '^name\s*=\s*"([^"]*)"') { $name = $Matches[1] }
        if ($trim -match '^path\s*=\s*"([^"]*)"') { $path = $Matches[1] }
        if ($trim -match '^cve\s*=\s*(.+)$') { $cveArray = Parse-Array($Matches[1]) }
    }
    if ($count -le 5) {
        Write-Host "Entry #$count - name='$name' path='$path' cveArray='$($cveArray -join '|')'"
    }
    if ($count -ge 5) { break }
}
