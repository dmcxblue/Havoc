whoami
if(net session){echo ADMIN=yes}
[System.Environment]::OSVersion.VersionString
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
echo "RunAsPPL=$($lsa.RunAsPPL)"
echo "SecPkgs=$($lsa.'Security Packages')"
echo "DllPresent=$(Test-Path C:\Windows\System32\sspmon.dll)"
echo "LogPresent=$(Test-Path C:\Windows\Temp\ssp.log)"
