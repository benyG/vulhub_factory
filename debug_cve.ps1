$line = Select-String -Path environments.toml -Pattern '^\s*cve\s*=' -List | Select-Object -First 2
foreach ($entry in $line) {
    $value = $entry.Line -replace '^.*=\s*', ''
    Write-Host "Line #: $($entry.LineNumber)"
    Write-Host "Raw value: $value"
    $inner = $value -replace '\r?\n', ''
    $inner = $inner.Trim().Trim('[', ']')
    $items = $inner -split ','
    foreach ($item in $items) {
        $itemClean = $item.Trim().Trim('"')
        Write-Host "Item: '$itemClean'"
    }
    Write-Host '---'
}
