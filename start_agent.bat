@echo off
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

echo =============================================================
echo  CyberSentinel background malware protection (foreground)
echo =============================================================
echo.
echo  This runs the real-time file-protection agent in THIS window.
echo  It is independent of the website, VS Code and Chrome.
echo.
echo  For an always-on Windows Service instead, run an ADMIN prompt:
echo      py -m cybersentinel agent install
echo      py -m cybersentinel agent start
echo  and to remove it later:
echo      py -m cybersentinel agent stop
echo      py -m cybersentinel agent uninstall
echo.
echo  Monitored folders: Downloads, Desktop, Documents, .\monitored
echo  (override with the CYBERSENTINEL_MONITORED_PATHS env var)
echo.
echo  Press Ctrl+C to stop.
echo =============================================================
echo.

py -m cybersentinel agent run

endlocal
