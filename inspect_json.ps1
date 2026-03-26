$data = Get-Content -Raw -Path vulhub_cve_list.json | ConvertFrom-Json
Write-Host "First cve: $($data.categories.rce[0].cve_id)"
Write-Host "Second cve: $($data.categories.rce[1].cve_id)"
