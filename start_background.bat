@echo off
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

if not exist logs mkdir logs

REM Start the website/API in a minimized background window.
start "CyberSentinel Background" /min cmd /c "py app.py >> logs\cybersentinel.log 2>&1"

timeout /t 4 >nul
start "CyberSentinel Website" http://127.0.0.1:5000/

echo CyberSentinel is running in the background.
echo Website: http://127.0.0.1:5000/
echo Health:  http://127.0.0.1:5000/api/v1/health
echo Log:     %ROOT%logs\cybersentinel.log
endlocal
