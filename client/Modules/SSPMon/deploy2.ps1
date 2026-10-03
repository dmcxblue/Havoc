# Deploy v2 SSP (kssp-exact layout) — run ONLY after operator go-ahead for reboot cycle
$f = Get-Item C:\Windows\System32\sspmon2.dll -ErrorAction SilentlyContinue
if (-not $f) {
  # copy expected via prior scp; verify instead
  echo "DEPLOY:MISSING"
  exit 1
}
echo "DEPLOY:OK size=$($f.Length) expect 230942"
if ($f.Length -ne 230942) { echo "DEPLOY:SIZE-MISMATCH"; exit 1 }

# hash check (admin session): 66eefc85f5ff08d51a7985dcff3da194d1873b534a5a17e011da2c955df95614
$h = (Get-FileHash C:\Windows\System32\sspmon2.dll -Algorithm SHA256).Hash.ToLower()
echo "HASH=$h"
if ($h -ne '66eefc85f5ff08d51a7985dcff3da194d1873b534a5a17e011da2c955df95614') { echo "HASH:MISMATCH"; exit 1 }

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d sspmon2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f

$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
echo "VERIFY SecPkgs=[$($lsa.'Security Packages')] RunAsPPL=$($lsa.RunAsPPL)"
echo "REG:DONE"
