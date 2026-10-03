echo "== last 10 logon captures =="
Get-Content C:\Windows\Temp\ssp.log | Select-Object -Last 10
echo "== log age =="
(Get-Item C:\Windows\Temp\ssp.log).LastWriteTime
echo "== boot time (tick base) =="
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
