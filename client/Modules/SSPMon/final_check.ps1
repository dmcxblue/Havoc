echo "== jnovoa entries in ssp.log (expect none - trigger failed on batch right) =="
Select-String -Path C:\Windows\Temp\ssp.log -Pattern 'jnovoa' | ForEach-Object { $_.Line }
echo "== total lines =="
(Get-Content C:\Windows\Temp\ssp.log | Measure-Object -Line).Lines
echo "== distinct accounts captured =="
Get-Content C:\Windows\Temp\ssp.log | ForEach-Object { ($_ -split ' ')[2] } | Sort-Object -Unique
echo "== module still loaded =="
tasklist /m sspmon2.dll | Select-String 'lsass'
