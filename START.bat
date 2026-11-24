@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "runtime\node.exe" (
  set "ZHEZU_NODE=%~dp0runtime\node.exe"
) else (
  where node >nul 2>&1
  if errorlevel 1 (
    echo Не найден runtime\node.exe. Распакуйте архив полностью.
    echo Для ручного запуска можно установить Node.js 22 или новее.
    pause
    exit /b 1
  )
  set "ZHEZU_NODE=node"
)
"%ZHEZU_NODE%" server.js --open
pause
