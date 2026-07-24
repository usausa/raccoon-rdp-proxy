# ---- build (ソースから自己完結・単一バイナリを生成) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
# ルートの MSBuild 設定 (Directory.Build.props/targets, ruleset, editorconfig) とプロジェクト一式。
COPY Directory.Build.props Directory.Build.targets Analyzers.ruleset .editorconfig ./
COPY Raccoon.RdpProxy/ ./Raccoon.RdpProxy/
RUN dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r linux-x64 --self-contained true \
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o /out

# ---- runtime (ネイティブ依存のみの最小イメージ) ----
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
COPY --from=build /out/Raccoon.RdpProxy /usr/local/bin/Raccoon.RdpProxy

# 設定と証明書は実行時に /cfg で解決する(資格情報をイメージに焼かない)。
#   /cfg/appsettings.json ... Proxy:Maps(複数ターゲット)・資格情報・ログ設定
#   /cfg/proxy.pfx        ... 無ければ初回起動時に10年物を自動生成して書き出す
#   /cfg/Log/             ... Serilog のログ出力先
# サービスではない(=カレントを固定しない)ので、WORKDIR=/cfg が設定/証明書/ログの基準になる。
# 既定の appsettings.json をイメージに同梱(マウントで上書き可)。
COPY --from=build /out/appsettings.json /cfg/appsettings.json
WORKDIR /cfg
ENTRYPOINT ["/usr/local/bin/Raccoon.RdpProxy"]

# ※ デュアルホーム/source bind のため、必ず host ネットワークで起動すること:
#   docker run --rm --network host -v /opt/raccoon-rdpproxy:/cfg raccoon-rdpproxy
