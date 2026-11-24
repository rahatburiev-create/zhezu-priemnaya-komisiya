@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "database.txt.lock" (
  echo Сначала остановите сервер: Ctrl+C в окне START.bat.
  echo Если сервер завершился аварийно, запустите и корректно остановите его.
  pause
  exit /b 1
)
if not exist "backups" mkdir "backups"
if not exist "receipts" mkdir "receipts"
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $dest='backups\ZhezU_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.zip'; Compress-Archive -LiteralPath 'database.txt','receipts' -DestinationPath $dest; Write-Host ('Backup: '+$dest)"
if errorlevel 1 (
  echo Не удалось сделать резервную копию.
) else (
  echo Копия базы и чеков сохранена в папке backups.
)
pause
