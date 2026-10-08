@echo off
cd /d "%~dp0"
"C:\Python314\python.exe" watch_report.py > reports\watch_last.log 2>&1
