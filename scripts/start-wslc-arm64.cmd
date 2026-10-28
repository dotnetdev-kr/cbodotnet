@echo off
setlocal DisableDelayedExpansion
where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo PowerShell 7.3 or later is required. Install PowerShell and run this script again. 1>&2
  exit /b 1
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0Start-WslcSdkSession.ps1" -Architecture arm64 %*
exit /b %errorlevel%
