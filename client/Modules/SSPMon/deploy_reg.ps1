$f = Get-Item C:\Windows\System32\sspmon.dll -ErrorAction SilentlyContinue
if (-not $f) { echo "DEPLOY:FAIL missing"; exit 1 }
echo "DEPLOY:OK size=$($f.Length)"
if ($f.Length -ne 230939) { echo "DEPLOY:SIZE-MISMATCH expected 230939"; exit 1 }

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d sspmon /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f

$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
echo "VERIFY SecPkgs=$($lsa.'Security Packages')"
echo "VERIFY RunAsPPL=$($lsa.RunAsPPL)"
echo "REG:DONE"
