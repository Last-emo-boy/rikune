#===== STAGE =====
# ── de4dot build stage ──
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim@sha256:306301580fcaa5b445180e759db59309979002d1000669cb4cf58a567d0014bc AS de4dot-build
ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG DE4DOT_COMMIT=b7d5728fc0c82fb0ad758e3a4c0fbb70368a4853
ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -fsSL "https://github.com/de4dot/de4dot/archive/${DE4DOT_COMMIT}.tar.gz" -o /tmp/de4dot.tar.gz && \
    printf '%s  %s\n' 'ad4a276b0e573e131dbf256b8f99c1f8d3cb448ee4d5b87f457b22a9b18af780' /tmp/de4dot.tar.gz | sha256sum -c - && \
    mkdir -p /tmp/de4dot && \
    tar -xzf /tmp/de4dot.tar.gz -C /tmp/de4dot --strip-components=1 && \
    cd /tmp/de4dot && \
    dotnet restore de4dot.netcore.sln && \
    dotnet publish de4dot/de4dot.csproj -c Release -f netcoreapp3.1 -r linux-x64 \
      --self-contained -p:PublishSingleFile=false -o /opt/de4dot \
      /nowarn:NETSDK1138 && \
    rm -rf /tmp/de4dot /tmp/de4dot.tar.gz /var/lib/apt/lists/*

#===== RUNTIME =====
# ── de4dot (.NET deobfuscator) ──
COPY --from=de4dot-build /opt/de4dot /opt/de4dot
RUN ln -sf /opt/de4dot/de4dot /usr/local/bin/de4dot
ENV DE4DOT_PATH=/opt/de4dot/de4dot
