#!/usr/bin/env bash
# ============================================================
#  Build one deployment artifact. Run on a Linux build host.
#
#    ./build.sh linux              ... Publish/Linux-x64 linux-x64 NativeAOT
#    ./build.sh linux singlefile   ... Publish/Linux-x64 linux-x64 self-contained single file
#    ./build.sh windows singlefile ... Publish/Windows   win-x64   self-contained single file
#
#  "./build.sh windows" without singlefile is refused: NativeAOT cannot cross
#  compile, so a Windows NativeAOT binary can only be built on a Windows host
#  with build.bat.
#
#  Prerequisites for the NativeAOT mode:
#    Rocky 9   : sudo dnf install -y dotnet-sdk-11.0 clang zlib-devel
#    Rocky 10  : sudo dnf install -y dotnet-sdk-11.0 clang zlib-ng-compat-devel
#    Debian    : sudo apt install -y dotnet-sdk-11.0 clang zlib1g-dev
#
#  A NativeAOT binary needs the glibc of its build host or newer, so build on a
#  distribution that is the same as - or older than - the relay host. Building
#  on the relay host itself always satisfies that.
#
#  Each invocation only touches its own output directory, so the targets can be
#  built one after the other.
#
#  The suppressed IL warnings all come from Serilog.Settings.Configuration's
#  assembly scanning paths (AssemblyFinder.Auto / DllScanningAssemblyFinder).
#  Program.cs passes the sink assemblies to ConfigurationReaderOptions, so
#  those paths are never taken and logging works in the published binaries.
#
#  Usage  : ./build.sh <windows|linux> [singlefile]
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

TARGET="${1:-}"
MODE="${2:-aot}"

PROJ='Raccoon.RdpProxy/Raccoon.RdpProxy.csproj'
TFM='net11.0'
NOWARN='--nowarn:IL2026,IL2104,IL3000,IL3002,IL3053'

fail() {
    echo >&2
    echo "[ERROR] $1" >&2
    shift
    for line in "$@"; do
        echo "  $line" >&2
    done
    exit 1
}

usage() {
    echo "Usage: ./build.sh <windows|linux> [singlefile]" >&2
    exit 1
}

case "$MODE" in
    aot | singlefile) ;;
    *) echo "[ERROR] unknown option '$MODE'." >&2; usage ;;
esac

SMOKE='no'
case "$TARGET" in
    linux)
        RID='linux-x64'
        OUT='Publish/Linux-x64'
        SMOKE='yes'
        ;;
    windows)
        if [ "$MODE" = 'aot' ]; then
            fail 'NativeAOT cannot cross compile from Linux to Windows.' \
                'Build it on a Windows host with build.bat, or pass singlefile:' \
                '  ./build.sh windows singlefile'
        fi
        RID='win-x64'
        OUT='Publish/Windows'
        ;;
    *)
        echo "[ERROR] unknown target '$TARGET'." >&2
        usage
        ;;
esac

command -v dotnet >/dev/null 2>&1 || fail \
    'the .NET SDK was not found.' \
    'Rocky Linux : sudo dnf install -y dotnet-sdk-11.0' \
    'Debian      : sudo apt install -y dotnet-sdk-11.0'

SDKS="$(dotnet --list-sdks 2>/dev/null || true)"
grep -q '^11\.' <<<"$SDKS" || fail \
    'the .NET SDK 11 was not found.' \
    'Installed SDKs:' \
    "${SDKS:-(none)}" \
    'Rocky Linux : sudo dnf install -y dotnet-sdk-11.0' \
    'Debian      : sudo apt install -y dotnet-sdk-11.0' \
    'or          : curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 11.0'

if [ "$MODE" = 'aot' ]; then
    command -v clang >/dev/null 2>&1 || fail \
        'clang was not found. NativeAOT needs it to link.' \
        'Rocky Linux : sudo dnf install -y clang' \
        'Debian      : sudo apt install -y clang'

    [ -f /usr/include/zlib.h ] || fail \
        'the zlib headers were not found (/usr/include/zlib.h). NativeAOT needs them to link.' \
        'Rocky 9  : sudo dnf install -y zlib-devel' \
        'Rocky 10 : sudo dnf install -y zlib-ng-compat-devel' \
        'Debian   : sudo apt install -y zlib1g-dev'

    HOST_ARCH="$(uname -m)"
    if [ "$HOST_ARCH" != 'x86_64' ]; then
        fail "cannot build $RID on a $HOST_ARCH host: NativeAOT needs a cross toolchain for that." \
            "Build on an x86_64 host, or run ./build.sh $TARGET singlefile instead."
    fi
fi

rm -rf "$OUT"

dotnet restore "$PROJ"

echo
if [ "$MODE" = 'aot' ]; then
    echo "Publishing $RID NativeAOT..."
    dotnet publish "$PROJ" -o "$OUT" -c Release -f "$TFM" -r "$RID" \
        -p:PublishAot=true -p:StripSymbols=true "$NOWARN"
else
    echo "Publishing $RID self-contained single file..."
    dotnet publish "$PROJ" -o "$OUT" -c Release -f "$TFM" -r "$RID" \
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true --self-contained \
        -p:PublishReadyToRun=true -p:PublishTrimmed=true "$NOWARN"
fi

rm -f "$OUT"/*.json
cp Raccoon.RdpProxy/appsettings.json "$OUT/appsettings.json"

if [ "$SMOKE" = 'yes' ]; then
    echo
    "$OUT/Raccoon.RdpProxy" --selftest
fi

echo
echo "Done: $OUT"
if [ "$MODE" = 'aot' ]; then
    OS_NAME="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )"
    GLIBC="$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$' || echo '?')"
    echo "  built on : $OS_NAME (glibc $GLIBC)"
    echo "  the relay host needs glibc $GLIBC or newer"
fi
