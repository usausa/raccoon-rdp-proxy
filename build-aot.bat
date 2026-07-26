@echo off
setlocal

rem ============================================================
rem  Build the Linux NativeAOT single binary (run from Windows).
rem
rem  NativeAOT cannot cross compile from Windows to Linux - it requires a
rem  Linux build host - so the publish itself runs in WSL. This script only
rem  produces the artifact; copy it to the relay host yourself.
rem
rem  One-time setup in the default WSL distro:
rem    wsl --set-default Ubuntu
rem    sudo apt update
rem    sudo apt install -y clang zlib1g-dev
rem    plus the .NET SDK 10 (dotnet --version)
rem  See README.md / README.ja.md for the full setup steps.
rem
rem  NOTE: comments are English only on purpose. cmd.exe reads batch files in
rem  the console code page, so UTF-8 Japanese would be mangled and the mangled
rem  bytes can be parsed as command separators.
rem  The Japanese description lives in README.ja.md instead.
rem
rem  Usage  : build-aot.bat [linux-x64^|linux-arm64]
rem  Output : publish/aot-linux-x64/Raccoon.RdpProxy
rem ============================================================

set RID=%1
if "%RID%"=="" set RID=linux-x64
set OUT=publish/aot-%RID%

cd /d "%~dp0"

where wsl >nul 2>&1
if errorlevel 1 goto :nowsl

rem The publish runs in the DEFAULT distro; wsl maps the current Windows
rem directory automatically, so the output lands back in this repository.
wsl -e bash -lc "command -v dotnet >/dev/null 2>&1"
if errorlevel 1 goto :nodotnet
wsl -e bash -lc "command -v clang >/dev/null 2>&1"
if errorlevel 1 goto :noclang

echo Publishing %RID% NativeAOT binary via WSL...
echo.
wsl -e bash -lc "dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r %RID% -p:PublishAot=true -p:StripSymbols=true -o %OUT%"
if errorlevel 1 goto :failed

if not exist "%OUT:/=\%\Raccoon.RdpProxy" goto :missing

echo.
echo Done: %OUT%/Raccoon.RdpProxy  (NativeAOT / no runtime required)
echo Copy it together with appsettings.json to the relay host.
goto :end

:nowsl
echo [ERROR] wsl not found. NativeAOT needs a Linux build host.
echo Install WSL, then set up the distro as described in README.md.
exit /b 1

:nodotnet
echo [ERROR] the .NET SDK was not found in the default WSL distro.
echo.
echo Check which distro is the default:  wsl --list --verbose
echo Point it at the one with the SDK:   wsl --set-default Ubuntu
exit /b 1

:noclang
echo [ERROR] clang / zlib headers are missing in WSL. NativeAOT needs them to link.
echo.
echo Install them once, then re-run this script:
echo   wsl -e bash -lc "sudo apt update; sudo apt install -y clang zlib1g-dev"
exit /b 1

:missing
echo.
echo [ERROR] the publish reported success but no binary was found in %OUT%.
exit /b 1

:failed
echo.
echo [ERROR] publish failed.
exit /b 1

:end
endlocal
