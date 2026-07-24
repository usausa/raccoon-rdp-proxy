#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Linux 上で NativeAOT のネイティブ単一バイナリを生成する。
#  JIT/ランタイム無しで起動が速く・省メモリ・より小さいバイナリになる。
#
#  ※ NativeAOT は「ビルドホストと同一OS/アーキ」でしか作れない。
#    Windows から Linux 向けには生成できないため、これはリレーLinux
#    (または任意の Linux x64) で実行すること。
#
#  要件: Linux x64 + .NET 10 SDK + clang + zlib 開発ヘッダ
#    Debian/Ubuntu:  sudo apt install -y clang zlib1g-dev
#    RHEL/Rocky:     sudo dnf install -y clang zlib-devel
#
#  使い方:  ./build-aot.sh [linux-x64|linux-arm64]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
RID="${1:-linux-x64}"
cd "$(dirname "$0")"

dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r "$RID" \
  -p:PublishAot=true \
  -p:InvariantGlobalization=true \
  -p:StripSymbols=true \
  -o "publish/aot-$RID"

echo
echo "完成: publish/aot-$RID/Raccoon.RdpProxy  (NativeAOT / ランタイム不要)"
ls -la "publish/aot-$RID/Raccoon.RdpProxy" || true
