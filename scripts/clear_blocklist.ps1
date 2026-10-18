$auth = @{
    Authorization  = 'Bearer febe63e1ed4dcd1271f79c2096fb6704954523597853f5f64dc36cbab0bf2713'
    'Content-Type' = 'application/json'
}

$rules = Invoke-RestMethod -Uri 'http://127.0.0.1:3030/api/blocking/rules' -Headers $auth
foreach ($r in $rules) {
    Write-Host "Excluding $($r.path)..."
    $body = @{ path = $r.path; exclude = $true } | ConvertTo-Json
    try {
        $res = Invoke-RestMethod -Uri 'http://127.0.0.1:3030/api/blocking/rules/exclude' -Method Post -Headers $auth -Body $body
        Write-Host "Result: $($res | ConvertTo-Json -Compress)"
    } catch {
        Write-Host "Error: $_"
    }
}
