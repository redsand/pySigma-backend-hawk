@echo off
cd /d "%~dp0"
"C:\Python314\python.exe" weekly_update.py > reports\weekly_last.log 2>&1
