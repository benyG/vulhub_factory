$a = 'abc' | ForEach-Object { $_ }
Write-Host $a.GetType().FullName
Write-Host $a[0]
