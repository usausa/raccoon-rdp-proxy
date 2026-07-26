# ---- build (ソースから NativeAOT のネイティブバイナリを生成) ----
# ---- build (produce a NativeAOT native binary from source) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
# NativeAOT のリンクに clang と zlib ヘッダが要る。
# NativeAOT linking requires clang and the zlib headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# ルートの MSBuild 設定 (Directory.Build.props/targets, ruleset, editorconfig) とプロジェクト一式。
# The root MSBuild settings (Directory.Build.props/targets, ruleset, editorconfig) and the project itself.
COPY Directory.Build.props Directory.Build.targets Analyzers.ruleset .editorconfig ./
COPY Raccoon.RdpProxy/ ./Raccoon.RdpProxy/
RUN dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r linux-x64 \
    -p:PublishAot=true -p:StripSymbols=true -o /out

# ---- runtime (ネイティブ依存のみの最小イメージ) ----
# ---- runtime (minimal image with native dependencies only) ----
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
COPY --from=build /out/Raccoon.RdpProxy /usr/local/bin/Raccoon.RdpProxy

# 設定と証明書は実行時に /cfg で解決する(資格情報をイメージに焼かない)。
#   /cfg/appsettings.json ... Proxy:Maps(複数ターゲット)・資格情報・ログ設定
#   /cfg/proxy.pfx        ... 無ければ初回起動時に10年物を自動生成して書き出す
#   /cfg/Log/             ... Serilog のログ出力先
# サービスではない(=カレントを固定しない)ので、WORKDIR=/cfg が設定/証明書/ログの基準になる。
# 既定の appsettings.json をイメージに同梱(マウントで上書き可)。
# Config and certificate resolve from /cfg at runtime (credentials are never baked into the image).
#   /cfg/appsettings.json ... Proxy:Maps (multiple targets), credentials, log settings
#   /cfg/proxy.pfx        ... auto-generated (10 years) on first start if absent
#   /cfg/Log/             ... Serilog output directory
# This is not a service (so the current directory is not pinned); WORKDIR=/cfg is the base for config/cert/logs.
# The default appsettings.json ships in the image (override it by mounting over /cfg).
COPY --from=build /out/appsettings.json /cfg/appsettings.json
WORKDIR /cfg
ENTRYPOINT ["/usr/local/bin/Raccoon.RdpProxy"]

# ※ デュアルホーム/source bind のため、必ず host ネットワークで起動すること:
# NOTE: because of dual-homing / source bind, always run with host networking:
#   docker run --rm --network host -v /opt/raccoon-rdpproxy:/cfg raccoon-rdpproxy
