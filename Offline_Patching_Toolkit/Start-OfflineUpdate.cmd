@echo off
setlocal
set "UPDATER_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "UPDATER_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%UPDATER_PS%" -NoProfile -File "%~dp0Run-OfflineMaintenance.ps1" -Launcher
set "UPDATER_RESULT=%ERRORLEVEL%"
if "%UPDATER_RESULT%"=="3010" echo A restart is required. Restart manually and run the tool again.
if "%UPDATER_RESULT%"=="1" echo The run needs attention. Review the local report or the error above. Script policy restrictions must be resolved through IT.
pause
exit /b %UPDATER_RESULT%