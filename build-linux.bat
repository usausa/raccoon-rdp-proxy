@echo off
setlocal

rem ============================================================
rem  Build the Linux artifact on Windows only (cross-publish).
rem
rem  Produces a self-contained single-file binary for Linux: the relay host
rem  needs no .NET runtime. Everything runs on Windows - no WSL, no
rem  containers - because this path uses the JIT runtime rather than
rem  NativeAOT. For the smaller/faster NativeAOT binary use build-aot.bat,
rem  which needs a Linux build host (WSL).
rem
rem  This script only produces the artifact; copy it to the relay yourself.
rem
rem  NOTE: comments are English only on purpose. cmd.exe reads batch files in
rem  the console code page, so UTF-8 Japanese would be mangled and the mangled
rem  bytes can be parsed as command separators.
rem  The Japanese description lives in README.ja.md instead.
rem
rem  Usage  : build-linux.bat [linux-x64^|linux-arm64]
rem  Output : publish/linux-x64/Raccoon.RdpProxy
rem ============================================================

set RID=%1
if "%RID%"=="" set RID=linux-x64
set OUT=publish/%RID%

cd /d "%~dp0"

echo Publishing %RID% self-contained single-file binary...
echo.
dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r %RID% ^
  --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true ^
  -o %OUT%
if errorlevel 1 goto :failed

if not exist "%OUT:/=\%\Raccoon.RdpProxy" goto :missing

echo.
echo Done: %OUT%/Raccoon.RdpProxy  (self-contained / no runtime required)
echo Copy it together with appsettings.json to the relay host.
goto :end

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
