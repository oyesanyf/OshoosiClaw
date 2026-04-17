$l = (Get-Content 'yara\rules\capabilities\capabilities.yar')[80]
$i = $l.IndexOf('drivers')
$sub = $l.Substring($i, 30)
Write-Host "Substring: $sub"
Write-Host "Char codes:"
for ($j = 0; $j -lt $sub.Length; $j++) {
    $c = $sub[$j]
    $code = [int]$c
    Write-Host ("  [$j] = '$c' (0x{0:X2})" -f $code)
}

Write-Host ""
Write-Host "=== EK_Fragus line 124 ==="
$l2 = (Get-Content 'yara\rules\exploit_kits\EK_Fragus.yar')[123]
$i2 = $l2.IndexOf('\{')
if ($i2 -ge 0) {
    Write-Host "Found \{ at index $i2"
    for ($j = [Math]::Max(0,$i2-3); $j -lt [Math]::Min($l2.Length, $i2+5); $j++) {
        $c = $l2[$j]
        $code = [int]$c
        Write-Host ("  [$j] = '$c' (0x{0:X2})" -f $code)
    }
} else {
    Write-Host "Pattern \{ not found!"
    $i2 = $l2.IndexOf('{')
    if ($i2 -ge 0) {
        Write-Host "Found { at index $i2"
        for ($j = [Math]::Max(0,$i2-3); $j -lt [Math]::Min($l2.Length, $i2+5); $j++) {
            $c = $l2[$j]
            $code = [int]$c
            Write-Host ("  [$j] = '$c' (0x{0:X2})" -f $code)
        }
    }
}

Write-Host ""
Write-Host "=== CVE-2018-4878 line 29 ==="
$l3 = (Get-Content 'yara\rules\cve_rules\CVE-2018-4878.yar')[28]
$i3 = $l3.IndexOf('flash')
if ($i3 -ge 0) {
    $sub3 = $l3.Substring([Math]::Max(0,$i3-5), 20)
    Write-Host "Around flash: $sub3"
    for ($j = 0; $j -lt $sub3.Length; $j++) {
        $c = $sub3[$j]
        $code = [int]$c
        Write-Host ("  [$j] = '$c' (0x{0:X2})" -f $code)
    }
}
