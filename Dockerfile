# ---- build (produce a NativeAOT native binary from source) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
# NativeAOT linking requires clang and the zlib headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# The root MSBuild settings (Directory.Build.props/targets, ruleset, editorconfig) and the project itself.
COPY Directory.Build.props Directory.Build.targets Analyzers.ruleset .editorconfig ./
COPY Raccoon.RdpProxy/ ./Raccoon.RdpProxy/
RUN dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r linux-x64 \
    -p:PublishAot=true -p:StripSymbols=true -o /out

# ---- runtime (minimal image with native dependencies only) ----
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
COPY --from=build /out/Raccoon.RdpProxy /usr/local/bin/Raccoon.RdpProxy

# Config and certificate resolve from /cfg at runtime (credentials are never baked into the image).
#   /cfg/appsettings.json ... Proxy:Maps (multiple targets), credentials, log settings
#   /cfg/proxy.pfx        ... auto-generated (10 years) on first start if absent
#   /cfg/Log/             ... Serilog output directory
# This is not a service (so the current directory is not pinned); WORKDIR=/cfg is the base for config/cert/logs.
# The default appsettings.json ships in the image (override it by mounting over /cfg).
COPY --from=build /out/appsettings.json /cfg/appsettings.json
WORKDIR /cfg
ENTRYPOINT ["/usr/local/bin/Raccoon.RdpProxy"]

# NOTE: because of dual-homing / source bind, always run with host networking:
#   docker run --rm --network host -v /opt/raccoon-rdpproxy:/cfg raccoon-rdpproxy
