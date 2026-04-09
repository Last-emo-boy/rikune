#===== ARGS =====
ARG UPX_VERSION=5.1.1

#===== RUNTIME =====
ARG UPX_VERSION

# ── UPX ──
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) upx_asset="upx-${UPX_VERSION}-amd64_linux.tar.xz" ;; \
      arm64) upx_asset="upx-${UPX_VERSION}-arm64_linux.tar.xz" ;; \
      *) echo "Unsupported architecture for bundled UPX release: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${upx_asset}" -o /tmp/upx.tar.xz; \
    mkdir -p /opt/upx; \
    tar -xJf /tmp/upx.tar.xz -C /opt/upx --strip-components=1; \
    ln -sf /opt/upx/upx /usr/local/bin/upx; \
    /usr/local/bin/upx --version >/dev/null
