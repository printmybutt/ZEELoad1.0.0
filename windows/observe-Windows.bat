@echo off
setlocal
chcp 65001 >nul
if not exist "%~dp0一键侧载-Windows.bat" (
  echo Missing launcher: extract the entire project folder first.
  pause
  exit /b 2
)
call "%~dp0一键侧载-Windows.bat" --observe-only
set "ZEELOAD_OBSERVE_EXIT=%errorlevel%"
if not "%ZEELOAD_OBSERVE_EXIT%"=="0" (
  echo Observation launcher failed. Exit code: %ZEELOAD_OBSERVE_EXIT%
  pause
)
exit /b %ZEELOAD_OBSERVE_EXIT%
