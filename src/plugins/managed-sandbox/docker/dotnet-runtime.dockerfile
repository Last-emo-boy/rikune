#===== ARGS =====
ARG ILSPYCMD_VERSION=9.1.0.7988

#===== STAGE =====
# ── .NET runtime copied into the final Python image ──
FROM mcr.microsoft.com/dotnet/runtime:8.0-bookworm-slim@sha256:a27922704a14d6d1ce103697aa3efa885902db33651b41a84ad1594fdf5be66e AS dotnet-runtime

# ── .NET SDK tool staging for ILSpy CLI ──
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim@sha256:306301580fcaa5b445180e759db59309979002d1000669cb4cf58a567d0014bc AS dotnet-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG ILSPYCMD_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    mkdir -p /tmp/ilspy-feed && \
    curl -fsSL "https://api.nuget.org/v3-flatcontainer/ilspycmd/${ILSPYCMD_VERSION}/ilspycmd.${ILSPYCMD_VERSION}.nupkg" -o "/tmp/ilspy-feed/ilspycmd.${ILSPYCMD_VERSION}.nupkg" && \
    printf '%s  %s\n' '2b5058f5ccc164c33b7aabf1a5eb0cf3d3a6af6c145aaf58efd3ed891443af7c' "/tmp/ilspy-feed/ilspycmd.${ILSPYCMD_VERSION}.nupkg" | sha256sum -c - && \
    printf '%s\n' '<?xml version="1.0" encoding="utf-8"?>' '<configuration><packageSources><clear /><add key="verified-local" value="/tmp/ilspy-feed" /></packageSources></configuration>' > /tmp/NuGet.Config && \
    dotnet tool install ilspycmd --version "${ILSPYCMD_VERSION}" --tool-path /opt/dotnet-tools --configfile /tmp/NuGet.Config && \
    rm -rf /tmp/ilspy-feed /tmp/NuGet.Config /var/lib/apt/lists/* && \
    /opt/dotnet-tools/ilspycmd --version >/dev/null

#===== RUNTIME =====
# ── .NET 8 runtime for managed assembly execution ──
COPY --from=dotnet-runtime /usr/share/dotnet /usr/share/dotnet
COPY --from=dotnet-tools /opt/dotnet-tools /opt/dotnet-tools
RUN ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet && \
    ln -sf /opt/dotnet-tools/ilspycmd /usr/local/bin/ilspycmd && \
    /usr/bin/dotnet --info >/dev/null && \
    ilspycmd --version >/dev/null
ENV DOTNET_PATH=/usr/bin/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV ILSPYCMD_PATH=/usr/local/bin/ilspycmd
