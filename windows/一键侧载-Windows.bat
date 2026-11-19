@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  ) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%~1'"
  )
  exit /b
)

set "ZEELOAD_OBSERVE_ONLY="
if /i "%~1"=="--observe-only" (
  set "ZEELOAD_OBSERVE_ONLY=1"
  goto :choosepython
)

set "APK=%~1"
if "%APK%"=="" set /p "APK=APK path: "

if not exist "%APK%" (
  echo APK not found: %APK%
  pause
  exit /b 1
)

:choosepython
where python >nul 2>&1
if %errorlevel%==0 goto :runpy
where py >nul 2>&1
if %errorlevel%==0 goto :runpylauncher
echo Python 3.12+ is required. Install it and enable "Add to PATH".
pause
exit /b 1

:runpy
set "ZEELOAD_PYTHON=python"
goto :runlogged

:runpylauncher
set "ZEELOAD_PYTHON=py"

:runlogged
set "ZEELOAD_ENTRY=%~dp0zeeload_app.py"
set "ZEELOAD_APK=%APK%"
set "ZEELOAD_LOGDIR=%~dp0logs"
if "%ZEELOAD_OBSERVE_ONLY%"=="1" set "ZEELOAD_LOGDIR=%~dp0logs\observe"
powershell -NoProfile -Command "$ErrorActionPreference = 'Continue'; $taskUtf8 = New-Object System.Text.UTF8Encoding $false; [Console]::InputEncoding = $taskUtf8; [Console]::OutputEncoding = $taskUtf8; $OutputEncoding = $taskUtf8; $env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'; New-Item -ItemType Directory -Force -Path $env:ZEELOAD_LOGDIR -ErrorAction Stop | Out-Null; $taskLog = Join-Path $env:ZEELOAD_LOGDIR ('bat-run-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log'); Write-Host ('Log: ' + $taskLog); $taskArgs = if ($env:ZEELOAD_OBSERVE_ONLY -eq '1') { @('--observe-only', '--out', $env:ZEELOAD_LOGDIR) } else { @('--apk', $env:ZEELOAD_APK) }; & $env:ZEELOAD_PYTHON -u $env:ZEELOAD_ENTRY @taskArgs 2>&1 | Tee-Object -FilePath $taskLog; $taskExit = $LASTEXITCODE; Write-Host ('Log saved: ' + $taskLog); exit $taskExit"
set "ZEELOAD_EXIT=%errorlevel%"

:done
echo.
echo Exit code: %ZEELOAD_EXIT%
pause
