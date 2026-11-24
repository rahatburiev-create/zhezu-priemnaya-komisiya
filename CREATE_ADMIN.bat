@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "runtime\node.exe" (
  set "ZHEZU_NODE=%~dp0runtime\node.exe"
) else (
  where node >nul 2>&1
  if errorlevel 1 (
    echo Не найден runtime\node.exe. Распакуйте архив полностью.
    pause
    exit /b 1
  )
  set "ZHEZU_NODE=node"
)
echo Сервер должен быть остановлен. Для остановки нажмите Ctrl+C в окне START.bat.
"%ZHEZU_NODE%" server.js --setup-admin
pause
