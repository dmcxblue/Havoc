Test-Path C:\Windows\Temp\ssp.log
Get-Item C:\Windows\Temp\ssp.log -ErrorAction SilentlyContinue | ForEach-Object { echo "size=$($_.Length) mtime=$($_.LastWriteTime)" }
Get-Content C:\Windows\Temp\ssp.log -ErrorAction SilentlyContinue
