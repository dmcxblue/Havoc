Select-String -Path C:\Windows\Temp\ssp.log -Pattern 'jnovoa' | ForEach-Object { $_.Line }
echo "---"
echo "total capture lines: $((Get-Content C:\Windows\Temp\ssp.log).Count)"
(Get-Item C:\Windows\Temp\ssp.log).LastWriteTime
