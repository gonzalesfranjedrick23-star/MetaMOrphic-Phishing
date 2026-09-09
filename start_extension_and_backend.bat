@echo off
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

REM Start backend in a separate window so it keeps running.
start "CyberSentinel Backend" cmd /k "python -m cybersentinel.web.api"

REM Wait briefly for backend to initialize.
timeout /t 3 >nul

REM Open health endpoint and extension page.
start "CyberSentinel Health" http://127.0.0.1:5000/api/v1/health
start "Chrome Extensions" chrome://extensions/

REM Print helpful instructions in this window.
cls
echo =============================================================
echo CyberSentinel startup helper
echo =============================================================
echo.
echo Backend is running in a separate window.
echo Health check: http://127.0.0.1:5000/api/v1/health
echo.
echo Next steps:
echo 1. Open Chrome -> chrome://extensions/
echo 2. Enable Developer mode
 echo 3. Click "Load unpacked"
echo 4. Select this folder:
 echo   %ROOT%
echo 5. Turn the extension on
 echo.
echo The backend window stays open while the service is active.
echo =============================================================
endlocal
