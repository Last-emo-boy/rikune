#===== STAGE =====
# ── de4dot build stage ──
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim AS de4dot-build
ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/de4dot/de4dot.git /tmp/de4dot && \
    cd /tmp/de4dot && \
    dotnet restore de4dot.netcore.sln && \
    dotnet publish de4dot/de4dot.csproj -c Release -f netcoreapp3.1 -r linux-x64 \
      --self-contained -p:PublishSingleFile=false -o /opt/de4dot \
      /nowarn:NETSDK1138 && \
    rm -rf /tmp/de4dot && \
    apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

#===== RUNTIME =====
# ── de4dot (.NET deobfuscator) ──
COPY --from=de4dot-build /opt/de4dot /opt/de4dot
RUN ln -sf /opt/de4dot/de4dot /usr/local/bin/de4dot
ENV DE4DOT_PATH=/opt/de4dot/de4dot
