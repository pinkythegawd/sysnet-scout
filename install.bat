@echo off
setlocal

REM SysNet Scout one-click installer for Windows beginners.
REM Run this file from the project root by double-clicking or from cmd/PowerShell.

cd /d "%~dp0"

echo =====================================
echo   SysNet Scout Windows Installer
echo   by pinkythegawd ^(MikePinku^)
echo =====================================
echo.

set "UV_EXE=%USERPROFILE%\.local\bin\uv.exe"

if not exist "%UV_EXE%" (
  echo [1/4] uv was not found. Installing uv...
  powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://astral.sh/uv/install.ps1 ^| iex"
  if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install uv.
    echo Please run as Administrator or check your internet connection.
    exit /b 1
  )
) else (
  echo [1/4] uv is already installed.
)

set "PATH=%PATH%;%USERPROFILE%\.local\bin"

where uv >nul 2>nul
if errorlevel 1 (
  echo.
  echo [ERROR] uv is still not available in this session.
  echo Try closing and reopening your terminal, then run install.bat again.
  exit /b 1
)

echo [2/4] Installing Python 3.12 ^(managed by uv^)...
uv python install 3.12
if errorlevel 1 (
  echo.
  echo [ERROR] Could not install Python 3.12 with uv.
  exit /b 1
)

echo [3/4] Syncing project environment...
uv sync --python 3.12
if errorlevel 1 (
  echo.
  echo [ERROR] Could not sync project dependencies.
  exit /b 1
)

echo [4/4] Running quick self-test...
set "PYTHONPATH=src"
uv run --python 3.12 -m sysnet_scout info --json >nul
if errorlevel 1 (
  echo.
  echo [ERROR] Installation finished but quick test failed.
  echo Try: scout.cmd info --json
  exit /b 1
)

echo.
echo [SUCCESS] SysNet Scout is ready.
echo.
echo Mission control commands:
echo   scout.cmd info --json
echo   scout.cmd scan-hosts --cidr 192.168.1.0/24 --json
echo   scout.cmd scan-ports --host 192.168.1.1 --profile web --fingerprint --hints
echo   scout.cmd risk-trend --reports reports/ports_day1.json reports/ports_day2.json --json
echo.
exit /b 0
