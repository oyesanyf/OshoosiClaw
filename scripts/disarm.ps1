$auth = @{
    Authorization  = 'Bearer febe63e1ed4dcd1271f79c2096fb6704954523597853f5f64dc36cbab0bf2713'
    'Content-Type' = 'application/json'
}

$body = @{
    confirmation_phrase = 'RESTORE HOST'
    credential          = 'febe63e1ed4dcd1271f79c2096fb6704954523597853f5f64dc36cbab0bf2713'
    password            = 'febe63e1ed4dcd1271f79c2096fb6704954523597853f5f64dc36cbab0bf2713'
    reason              = 'Operator Full Restoration'
} | ConvertTo-Json

try {
    $res = Invoke-RestMethod -Uri 'http://127.0.0.1:3030/api/killchain/disarm' -Method Post -Headers $auth -Body $body
    Write-Host "Disarm Response:" ($res | ConvertTo-Json -Compress)
} catch {
    Write-Host "Disarm Error: $_"
}
