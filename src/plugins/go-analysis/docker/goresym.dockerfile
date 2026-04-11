#===== ARGS =====
ARG GORESYM_VERSION=3.3

#===== RUNTIME =====
ARG GORESYM_VERSION

# ── GoReSym (Go binary symbol recovery) ──
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) goresym_arch="linux_amd64" ;; \
      arm64) goresym_arch="linux_arm64" ;; \
      *) echo "Unsupported architecture for GoReSym: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VERSION}/GoReSym_${goresym_arch}" -o /usr/local/bin/GoReSym; \
    chmod +x /usr/local/bin/GoReSym
