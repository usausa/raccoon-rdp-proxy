@echo off
REM Windows から Linux 向け自己完結・単一バイナリを作る (build-linux.ps1 のラッパ)
REM 使い方: build-linux.bat [linux-x64|linux-arm64]
setlocal
set RID=%1
if "%RID%"=="" set RID=linux-x64
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-linux.ps1" %RID%
