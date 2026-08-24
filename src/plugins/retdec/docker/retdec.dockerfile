#===== ARGS =====
ARG RETDEC_VERSION=5.0

#===== STAGE =====
# =============================================================================
# RetDec decompiler
# =============================================================================
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS heavy-tools

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
    printf '%s  %s\n' 'e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5' /tmp/retdec.tar.xz | sha256sum -c -; \
    mkdir -p /opt/retdec; \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec; \
    test -x /opt/retdec/bin/retdec-decompiler; \
    /opt/retdec/bin/retdec-decompiler --help >/dev/null

#===== RUNTIME =====
COPY --from=heavy-tools /opt/retdec /opt/retdec

# ── RetDec symlinks ──
RUN ln -sf /opt/retdec/bin/retdec-decompiler /usr/local/bin/retdec-decompiler && \
    ln -sf /opt/retdec/bin/retdec-fileinfo /usr/local/bin/retdec-fileinfo
