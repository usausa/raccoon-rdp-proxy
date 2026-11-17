@echo off
setlocal

rem ============================================================
rem  Release build for CI. Produces both deployment artifacts.
rem
rem    Publish\Windows   ... win-x64   NativeAOT
rem    Publish\Linux-x64 ... linux-x64 self-contained single file
rem
rem  NativeAOT cannot cross compile, so a Windows build host cannot produce the
rem  Linux NativeAOT binary; that artifact uses the self-contained single-file
rem  path instead. For a Linux NativeAOT binary run build-linux-aot.bat, which
rem  needs WSL with dotnet-sdk-11.0, clang and the zlib headers.
rem
rem  The win-x64 NativeAOT link needs the MSVC toolchain (Visual Studio or the
rem  Build Tools with "Desktop development with C++"). Pass "singlefile" to
rem  build the Windows artifact the same way as Linux instead.
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
rem  Usage  : build-release.bat [aot|singlefile]
rem  Output : Publish\Windows, Publish\Linux-x64
rem ============================================================

cd /d "%~dp0"

set WINMODE=%1
if "%WINMODE%"=="" set WINMODE=aot

set SLN=Raccoon.RdpProxy.slnx
set PROJ=Raccoon.RdpProxy\Raccoon.RdpProxy.csproj
set TFM=net11.0
set SINGLEFILE=/p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true --self-contained /p:PublishReadyToRun=true /p:PublishTrimmed=true
set NOWARN=--nowarn:"IL2026,IL2104,IL3000,IL3002,IL3053"

dotnet restore %SLN% || goto :failed
dotnet clean %SLN% -c Release || goto :failed
dotnet build %SLN% -c Release -nodeReuse:false || goto :failed

if exist Publish rmdir /s /q Publish

if /i "%WINMODE%"=="singlefile" goto :winsinglefile

echo.
echo Publishing win-x64 NativeAOT...
dotnet publish %PROJ% -o Publish\Windows -c Release -f %TFM% -r win-x64 /p:PublishAot=true %NOWARN% || goto :failed
goto :linux

:winsinglefile
echo.
echo Publishing win-x64 self-contained single file...
dotnet publish %PROJ% -o Publish\Windows -c Release -f %TFM% -r win-x64 %SINGLEFILE% %NOWARN% || goto :failed

:linux
echo.
echo Publishing linux-x64 self-contained single file...
dotnet publish %PROJ% -o Publish\Linux-x64 -c Release -f %TFM% -r linux-x64 %SINGLEFILE% %NOWARN% || goto :failed

del /q Publish\Windows\*.json
copy /y Raccoon.RdpProxy\appsettings.json Publish\Windows\appsettings.json >nul || goto :failed
del /q Publish\Linux-x64\*.json
copy /y Raccoon.RdpProxy\appsettings.json Publish\Linux-x64\appsettings.json >nul || goto :failed

rem Smoke test the Windows artifact with the network-free self test.
echo.
Publish\Windows\Raccoon.RdpProxy.exe --selftest || goto :failed

echo.
echo Done:
echo   Publish\Windows\Raccoon.RdpProxy.exe
echo   Publish\Linux-x64\Raccoon.RdpProxy
goto :end

:failed
echo.
echo [ERROR] build failed.
exit /b 1

:end
endlocal
