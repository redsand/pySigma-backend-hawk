@echo off
rem Daily Sigma -> HAWK sync. Dry run by default; pass --execute to push.
cd /d "%~dp0"
"C:\Python314\python.exe" daily_sync.py %* > reports\daily_last.log 2>&1
type reports\daily_last.log
