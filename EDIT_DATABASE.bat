@echo off
cd /d "%~dp0"
echo Stop the server before editing the database. Save as UTF-8.
start "" notepad.exe "%~dp0database.txt"
