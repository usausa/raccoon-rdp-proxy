#!/usr/bin/env bash
# ============================================================
#  Build the NativeAOT single binary on Linux (aimed at Rocky Linux / the RHEL family).
#
#  Native AOT cannot cross compile from Windows to Linux, so a Linux build host is
#  required. To drive it from Windows use build-linux-aot.bat instead (same publish,
#  via WSL).
#
#  Prerequisites:
#    Rocky 9   : sudo dnf install -y dotnet-sdk-10.0 clang zlib-devel
#    Rocky 10  : sudo dnf install -y dotnet-sdk-10.0 clang zlib-ng-compat-devel
#    Debian    : sudo apt install -y dotnet-sdk-10.0 clang zlib1g-dev
#
#  This only produces the artifact (deploying to the relay host is manual). The binary
#  needs the glibc of the build host or newer, so build on a distribution that is the
#  same as - or older than - the relay host.
#
#  Usage  : ./build-linux-aot.sh [linux-x64|linux-arm64]
#  Output : publish/aot-linux-x64/Raccoon.RdpProxy
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

# The default RID is the build host architecture. Targeting another architecture needs a
# cross toolchain, so it is refused by default (set ALLOW_CROSS=1 if you have one).
case "$(uname -m)" in
    x86_64)  HOST_RID='linux-x64' ;;
    aarch64) HOST_RID='linux-arm64' ;;
    *)       HOST_RID='' ;;
esac

RID="${1:-${HOST_RID:-linux-x64}}"
OUT="publish/aot-$RID"
BIN="$OUT/Raccoon.RdpProxy"

fail() {
    echo >&2
    echo "[ERROR] $1" >&2
    shift
    for line in "$@"; do
        echo "  $line" >&2
    done
    exit 1
}

# --- Prerequisite checks ---

command -v dotnet >/dev/null 2>&1 || fail \
    'the .NET SDK was not found.' \
    'Rocky Linux : sudo dnf install -y dotnet-sdk-10.0' \
    'or          : curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0'

SDKS="$(dotnet --list-sdks 2>/dev/null || true)"
grep -q '^10\.' <<<"$SDKS" || fail \
    'the .NET SDK 10 was not found.' \
    'Installed SDKs:' \
    "${SDKS:-(none)}" \
    'Rocky Linux : sudo dnf install -y dotnet-sdk-10.0'

command -v clang >/dev/null 2>&1 || fail \
    'clang was not found. NativeAOT needs it to link.' \
    'Rocky Linux : sudo dnf install -y clang'

# zlib is needed at NativeAOT link time (on Rocky 10 zlib-ng replaces zlib and zlib.h comes
# from the compat package).
[ -f /usr/include/zlib.h ] || fail \
    'the zlib headers were not found (/usr/include/zlib.h). NativeAOT needs them to link.' \
    'Rocky 9  : sudo dnf install -y zlib-devel' \
    'Rocky 10 : sudo dnf install -y zlib-ng-compat-devel'

if [ -n "$HOST_RID" ] && [ "$RID" != "$HOST_RID" ] && [ "${ALLOW_CROSS:-}" != '1' ]; then
    fail \
        "cannot build $RID on a $HOST_RID host: NativeAOT needs a cross toolchain for that." \
        "Build $RID on a $RID machine (or a container of that architecture)," \
        'or set ALLOW_CROSS=1 if a cross toolchain and sysroot are already set up.'
fi

# --- Publish ---

echo "Publishing $RID NativeAOT binary..."
echo
dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r "$RID" \
    -p:PublishAot=true -p:StripSymbols=true -o "$OUT"

[ -f "$BIN" ] || fail "the publish reported success but no binary was found in $OUT."

# Smoke test the artifact with the network-free self test to prove it actually runs here.
if [ "$RID" = "$HOST_RID" ]; then
    echo
    "$BIN" --selftest
fi

OS_NAME="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )"

echo
echo "Done: $BIN  (NativeAOT / no runtime required)"
echo "  size     : $(du -h "$BIN" | cut -f1)"
echo "  built on : $OS_NAME  (the binary needs this glibc or newer)"
echo
echo "Copy it together with $OUT/appsettings.json to the relay host."
echo "See README.md / README.ja.md for the systemd steps."
