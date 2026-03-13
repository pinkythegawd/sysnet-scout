@echo off
setlocal
if "%~1"=="" (
  echo =====================================
  echo   SysNet Scout Launcher ^(Windows^)
  echo =====================================
  echo.
  echo Try one of these:
  echo   scout.cmd info --json
  echo   scout.cmd scan-hosts --cidr 192.168.1.0/24 --json
  echo   scout.cmd scan-ports --host 192.168.1.1 --profile web --fingerprint --hints
  echo   scout.cmd risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json
  echo.
  exit /b 0
)
set "UV_EXE=%USERPROFILE%\.local\bin\uv.exe"
if not exist "%UV_EXE%" (
  echo uv.exe not found at "%UV_EXE%"
  echo Install uv first: powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 ^| iex"
  exit /b 1
)
set "PYTHONPATH=src"
"%UV_EXE%" run --python 3.12 -m sysnet_scout %*
exit /b %ERRORLEVEL%
