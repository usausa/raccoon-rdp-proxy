#!/usr/bin/env bash
# Linux/macOS から Linux 向け自己完結・単一バイナリを作る
# 使い方: ./build-linux.sh [linux-x64|linux-arm64]
set -euo pipefail
RID="${1:-linux-x64}"
cd "$(dirname "$0")"
dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r "$RID" --self-contained true \
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true \
    -o "publish/$RID"
echo
echo "完成: publish/$RID/Raccoon.RdpProxy"
