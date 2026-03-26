$items = ('"abc"') | ForEach-Object { $_.Trim('"') }
Write-Host $items.GetType().FullName
foreach ($item in $items) { Write-Host $item.GetType().FullName }
