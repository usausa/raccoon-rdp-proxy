@echo off
setlocal

rem ============================================================
rem  Build the Linux NativeAOT single binary (run from Windows).
rem
rem  NativeAOT can only be produced on the same OS as the build host,
rem  so this delegates to Linux. It auto-detects what is available,
rem  in the order WSL, docker, podman.
rem
rem  NOTE: comments in this file are English only on purpose. cmd.exe reads
rem  batch files in the console code page, so UTF-8 Japanese would be mangled
rem  and the mangled bytes can be parsed as command separators.
rem  The Japanese description lives in README.ja.md instead.
rem
rem  Usage  : build-aot.bat
rem  Output : publish/aot-linux-x64/Raccoon.RdpProxy
rem ============================================================

set RID=linux-x64
set OUT=publish/aot-%RID%
set PUBLISH=dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r %RID% -p:PublishAot=true -p:StripSymbols=true -o %OUT%

cd /d "%~dp0"

rem --- 1) WSL: fastest, native build when the .NET SDK is present ---
where wsl >nul 2>&1
if errorlevel 1 goto :try_docker
wsl -e bash -lc "command -v dotnet >/dev/null 2>&1"
if errorlevel 1 goto :try_docker

wsl -e bash -lc "command -v clang >/dev/null 2>&1"
if errorlevel 1 goto :noclang

echo Building %RID% NativeAOT binary via WSL...
echo.
wsl -e bash -lc "%PUBLISH%"
if errorlevel 1 goto :failed
goto :done

rem --- 2) docker ---
:try_docker
where docker >nul 2>&1
if errorlevel 1 goto :try_podman
echo Building %RID% NativeAOT binary in a docker container...
echo.
docker run --rm -v "%~dp0.":/src -w /src -v raccoon-rdpproxy-nuget:/root/.nuget/packages ^
  mcr.microsoft.com/dotnet/sdk:10.0 ^
  bash -lc "set -e; apt-get update >/dev/null && apt-get install -y --no-install-recommends clang zlib1g-dev >/dev/null && %PUBLISH%"
if errorlevel 1 goto :failed
goto :done

rem --- 3) podman ---
:try_podman
where podman >nul 2>&1
if errorlevel 1 goto :nolinux
echo Building %RID% NativeAOT binary in a podman container...
echo.
podman run --rm -v "%~dp0.":/src -w /src ^
  mcr.microsoft.com/dotnet/sdk:10.0 ^
  bash -lc "set -e; apt-get update >/dev/null && apt-get install -y --no-install-recommends clang zlib1g-dev >/dev/null && %PUBLISH%"
if errorlevel 1 goto :failed
goto :done

:noclang
rem NativeAOT cannot link without clang and the zlib headers.
echo [ERROR] clang / zlib headers are missing in WSL. NativeAOT needs them to link.
echo.
echo Install them once, then re-run this script:
echo   wsl -e bash -lc "sudo apt update; sudo apt install -y clang zlib1g-dev"
exit /b 1

:nolinux
echo [ERROR] no Linux build environment found (WSL with .NET SDK, docker, or podman).
echo.
echo Set up one of them, or build directly ON a Linux host:
echo   sudo dnf install -y clang zlib-devel     # RHEL family
echo   sudo apt install -y clang zlib1g-dev     # Debian family
echo   %PUBLISH%
exit /b 1

:failed
echo.
echo [ERROR] build failed.
exit /b 1

:done
echo.
echo Done: %OUT%/Raccoon.RdpProxy  (NativeAOT / no runtime required)
echo Copy it to the relay host together with appsettings.json.
endlocal
