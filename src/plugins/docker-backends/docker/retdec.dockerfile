#===== ARGS =====
ARG RETDEC_VERSION=5.0

#===== STAGE =====
# =============================================================================
# RetDec decompiler
# =============================================================================
FROM debian:bookworm-slim AS heavy-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG RETDEC_VERSION

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
    curl -fsSL "https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz" -o /tmp/retdec.tar.xz; \
    mkdir -p /opt/retdec; \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec; \
    test -x /opt/retdec/bin/retdec-decompiler; \
    /opt/retdec/bin/retdec-decompiler --help >/dev/null

#===== RUNTIME =====
COPY --from=heavy-tools /opt/retdec /opt/retdec

# ── RetDec symlinks ──
RUN ln -sf /opt/retdec/bin/retdec-decompiler /usr/local/bin/retdec-decompiler && \
    ln -sf /opt/retdec/bin/retdec-fileinfo /usr/local/bin/retdec-fileinfo
