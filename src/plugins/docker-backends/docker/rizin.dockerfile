#===== ARGS =====
ARG RIZIN_VERSION=0.8.2

#===== STAGE =====
# =============================================================================
# Rizin (static binary)
# =============================================================================
FROM debian:bookworm-slim AS core-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG RIZIN_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) rizin_asset="rizin-v${RIZIN_VERSION}-static-x86_64.tar.xz" ;; \
      *) echo "Unsupported architecture for bundled Rizin static release: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/${rizin_asset}" -o /tmp/rizin.tar.xz; \
    mkdir -p /opt/rizin; \
    tar -xJf /tmp/rizin.tar.xz -C /opt/rizin; \
    test -x /opt/rizin/bin/rizin; \
    /opt/rizin/bin/rizin -v >/dev/null

#===== RUNTIME =====
COPY --from=core-tools /opt/rizin /opt/rizin

# ── Rizin symlinks ──
RUN ln -sf /opt/rizin/bin/rizin /usr/local/bin/rizin && \
    ln -sf /opt/rizin/bin/rz-bin /usr/local/bin/rz-bin && \
    ln -sf /opt/rizin/bin/rz-asm /usr/local/bin/rz-asm && \
    ln -sf /opt/rizin/bin/rz-diff /usr/local/bin/rz-diff && \
    ln -sf /opt/rizin/bin/rz-find /usr/local/bin/rz-find && \
    ln -sf /opt/rizin/bin/rz-hash /usr/local/bin/rz-hash
