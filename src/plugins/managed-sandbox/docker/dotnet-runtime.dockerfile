#===== ARGS =====
ARG ILSPYCMD_VERSION=9.1.0.7988

#===== STAGE =====
# ── .NET SDK tool staging for ILSpy CLI ──
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim AS dotnet-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG ILSPYCMD_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN dotnet tool install ilspycmd --version "${ILSPYCMD_VERSION}" --tool-path /opt/dotnet-tools && \
    /opt/dotnet-tools/ilspycmd --version >/dev/null

#===== RUNTIME =====
# ── .NET 8 runtime for managed assembly execution ──
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && \
    wget -qO /tmp/packages-microsoft-prod.deb \
      "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" && \
    dpkg -i /tmp/packages-microsoft-prod.deb && rm /tmp/packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends dotnet-runtime-8.0 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=dotnet-tools /opt/dotnet-tools /opt/dotnet-tools
RUN ln -sf /opt/dotnet-tools/ilspycmd /usr/local/bin/ilspycmd && \
    ilspycmd --version >/dev/null
ENV DOTNET_PATH=/usr/bin/dotnet
ENV ILSPYCMD_PATH=/usr/local/bin/ilspycmd
