# READ-ONLY post-restore assessment — no changes to the target
echo "== boot health =="
$os = Get-CimInstance Win32_OperatingSystem
echo "LastBoot: $($os.LastBootUpTime)  Uptime(h): $([math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1))"

echo "== artifacts left behind =="
echo "DllPresent=$(Test-Path C:\Windows\System32\sspmon.dll)"
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
echo "SecPkgs=[$($lsa.'Security Packages')]  RunAsPPL=$($lsa.RunAsPPL)"
echo "LogPresent=$(Test-Path C:\Windows\Temp\ssp.log)"

echo "== crash evidence =="
$dumps = Get-ChildItem C:\Windows\Minidump\ -ErrorAction SilentlyContinue
if ($dumps) { $dumps | ForEach-Object { echo "MINIDUMP: $($_.Name) $($_.Length) $($_.LastWriteTime)" } } else { echo "no minidumps" }
echo "LiveKernelReports: $((Get-ChildItem C:\Windows\LiveKernelReports -ErrorAction SilentlyContinue | Measure-Object).Count) items"

echo "== bugcheck / lsass events around the crash =="
try {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001,41,6008} -MaxEvents 6 -ErrorAction Stop |
    ForEach-Object { echo "EVT $($_.Id) $($_.TimeCreated) $($_.ProviderName): $($_.Message.Substring(0,[Math]::Min(160,$_.Message.Length)))" }
} catch { echo "event query: $($_.Exception.Message)" }
try {
  Get-WinEvent -LogName 'Microsoft-Windows-LSA/Operational' -MaxEvents 8 -ErrorAction Stop |
    ForEach-Object { echo "LSA $($_.Id) $($_.TimeCreated): $($_.Message.Substring(0,[Math]::Min(140,$_.Message.Length)))" }
} catch { echo "LSA log: $($_.Exception.Message)" }
