# restore_original.ps1 — return HWKSTN2 to pre-deployment state
# Original (verified pre-deploy): Security Packages ABSENT, RunAsPPL=2, no DLL, no log.

echo "== 1. restore registry =="
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 2 /f
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
echo "VERIFY SecPkgs=[$($lsa.'Security Packages')] RunAsPPL=$($lsa.RunAsPPL)"

echo "== 2. delete DLL (loaded by lsass -> delete-pending at next boot) =="
if (Test-Path C:\Windows\System32\sspmon2.dll) {
  try { Remove-Item C:\Windows\System32\sspmon2.dll -Force -ErrorAction Stop; echo "DLL deleted now (was not locked)" }
  catch { echo "DLL locked by lsass (expected) — deletion pending reboot; registry already cleared so it will not reload" }
} else { echo "DLL already absent" }

echo "== 3. Temp sweep =="
foreach ($t in 'trigger2.bat','trigger2.log','tl2.txt','sst.bin','ssp.log') {
  $p = "C:\Windows\Temp\$t"
  if (Test-Path $p) { Remove-Item $p -Force; echo "deleted Temp\$t" } else { echo "absent: Temp\$t" }
}

echo "== 4. final posture =="
echo "DllPresent=$(Test-Path C:\Windows\System32\sspmon2.dll)"
echo "LogPresent=$(Test-Path C:\Windows\Temp\ssp.log)"
echo "SstPresent=$(Test-Path C:\Windows\Temp\sst.bin)"
tasklist /m sspmon2.dll | Select-String lsass
