@echo off
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

REM Start the website/API backend in a separate window so it keeps running.
start "CyberSentinel API" cmd /k "py app.py"

REM Give the server a moment to start.
timeout /t 3 >nul

REM Open the dashboard and extension page to make setup easy.
start "CyberSentinel Website" http://127.0.0.1:5000/
start "Chrome Extension Page" chrome://extensions/

cls
echo =============================================================
 echo CyberSentinel is starting...
 echo.
 echo 1) Website/API dashboard: http://127.0.0.1:5000/
 echo 2) API health check: http://127.0.0.1:5000/api/v1/health
 echo 3) Chrome extensions page: chrome://extensions/
 echo 4) Load the unpacked extension from: %ROOT%
 echo 5) Enable Developer mode and turn on the extension
 echo.
 echo The backend window stays open. Close it only when you want to stop the site.
 echo =============================================================
endlocal
