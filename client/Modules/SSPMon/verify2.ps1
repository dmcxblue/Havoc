echo "== module loaded in lsass? =="
tasklist /m sspmon2.dll
echo "== log present? =="
if (Test-Path C:\Windows\Temp\ssp.log) {
  echo "LOG-EXISTS size=$((Get-Item C:\Windows\Temp\ssp.log).Length)"
  echo "--- contents ---"
  Get-Content C:\Windows\Temp\ssp.log
} else { echo "LOG-ABSENT" }
