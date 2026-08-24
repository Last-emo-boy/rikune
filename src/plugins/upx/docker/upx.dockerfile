#===== ARGS =====
ARG UPX_VERSION=5.1.1

#===== RUNTIME =====
ARG UPX_VERSION

# ── UPX ──
RUN set -eux; \
    test "$(dpkg --print-architecture)" = "amd64"; \
    upx_asset="upx-${UPX_VERSION}-amd64_linux.tar.xz"; \
    curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${upx_asset}" -o /tmp/upx.tar.xz; \
    printf '%s  %s\n' '1ff660454227861e00772f743f66b900072116b9dc24f6ee28b97cce88a7828a' /tmp/upx.tar.xz | sha256sum -c -; \
    mkdir -p /opt/upx; \
    tar -xJf /tmp/upx.tar.xz -C /opt/upx --strip-components=1; \
    ln -sf /opt/upx/upx /usr/local/bin/upx; \
    /usr/local/bin/upx --version >/dev/null
