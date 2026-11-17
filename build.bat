@echo off
setlocal

rem ============================================================
rem  Build one deployment artifact. Run on Windows.
rem
rem    build.bat windows            ... Publish\Windows   win-x64   NativeAOT
rem    build.bat windows singlefile ... Publish\Windows   win-x64   self-contained single file
rem    build.bat linux singlefile   ... Publish\Linux-x64 linux-x64 self-contained single file
rem
rem  "build.bat linux" without singlefile is refused: NativeAOT cannot cross
rem  compile, so a Linux NativeAOT binary can only be built on a Linux host
rem  with build.sh.
rem
rem  The win-x64 NativeAOT link needs the MSVC toolchain: Visual Studio, or the
rem  Build Tools for Visual Studio with the "Desktop development with C++"
rem  workload (component Microsoft.VisualStudio.Component.VC.Tools.x86.x64).
rem
rem  Each invocation only touches its own output directory, so the targets can
rem  be built one after the other.
rem
rem  The suppressed IL warnings all come from Serilog.Settings.Configuration's
rem  assembly scanning paths (AssemblyFinder.Auto / DllScanningAssemblyFinder).
rem  Program.cs passes the sink assemblies to ConfigurationReaderOptions, so
rem  those paths are never taken and logging works in the published binaries.
rem
rem  NOTE: comments are English only on purpose. cmd.exe reads batch files in
rem  the console code page, so UTF-8 Japanese would be mangled and the mangled
rem  bytes can be parsed as command separators.
rem
rem  Usage  : build.bat ^<windows^|linux^> [singlefile]
rem ============================================================

cd /d "%~dp0"

set TARGET=%1
set MODE=%2
if "%MODE%"=="" set MODE=aot

if /i "%MODE%"=="aot" goto :modeok
if /i "%MODE%"=="singlefile" goto :modeok
echo [ERROR] unknown option "%MODE%".
goto :usage

:modeok
if /i "%TARGET%"=="windows" goto :windows
if /i "%TARGET%"=="linux" goto :linux
echo [ERROR] unknown target "%TARGET%".
goto :usage

:windows
set RID=win-x64
set OUT=Publish\Windows
set BIN=%OUT%\Raccoon.RdpProxy.exe
goto :build

:linux
if /i "%MODE%"=="singlefile" goto :linuxok
echo [ERROR] NativeAOT cannot cross compile from Windows to Linux.
echo Build it on a Linux host with build.sh, or pass singlefile:
echo   build.bat linux singlefile
exit /b 1

:linuxok
set RID=linux-x64
set OUT=Publish\Linux-x64
set BIN=
goto :build

:build
set PROJ=Raccoon.RdpProxy\Raccoon.RdpProxy.csproj
set TFM=net11.0
set NOWARN=--nowarn:"IL2026,IL2104,IL3000,IL3002,IL3053"
set SINGLEFILE=/p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true --self-contained /p:PublishReadyToRun=true /p:PublishTrimmed=true

if exist %OUT% rmdir /s /q %OUT%

dotnet restore %PROJ% || goto :failed

echo.
if /i "%MODE%"=="singlefile" goto :pubsingle

echo Publishing %RID% NativeAOT...
dotnet publish %PROJ% -o %OUT% -c Release -f %TFM% -r %RID% /p:PublishAot=true %NOWARN% || goto :failed
goto :artifact

:pubsingle
echo Publishing %RID% self-contained single file...
dotnet publish %PROJ% -o %OUT% -c Release -f %TFM% -r %RID% %SINGLEFILE% %NOWARN% || goto :failed

:artifact
del /q %OUT%\*.json
copy /y Raccoon.RdpProxy\appsettings.json %OUT%\appsettings.json >nul || goto :failed

rem Smoke test with the network-free self test, when the artifact runs on this host.
if "%BIN%"=="" goto :done
echo.
%BIN% --selftest || goto :failed

:done
echo.
echo Done: %OUT%
goto :end

:usage
echo Usage: build.bat ^<windows^|linux^> [singlefile]
exit /b 1

:failed
echo.
echo [ERROR] build failed.
exit /b 1

:end
endlocal
