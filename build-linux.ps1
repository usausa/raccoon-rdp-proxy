# Windows から Linux 向け自己完結・単一バイナリを作る
# 使い方: pwsh ./build-linux.ps1 [linux-x64|linux-arm64]
param([string]$Rid = "linux-x64")
$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r $Rid --self-contained true `
        -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
        -o "$PSScriptRoot/publish/$Rid"
    Write-Host "`n完成: publish/$Rid/Raccoon.RdpProxy"
} finally { Pop-Location }
