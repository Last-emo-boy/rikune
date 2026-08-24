#===== ARGS =====
ARG GORESYM_VERSION=3.3

#===== RUNTIME =====
ARG GORESYM_VERSION

# ── GoReSym (Go binary symbol recovery) ──
# v3.3+ ships as GoReSym-linux.zip (single multi-arch binary inside)
RUN set -eux; \
    tmpzip="$(mktemp /tmp/goresym-XXXXXX.zip)"; \
    curl -fsSL "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VERSION}/GoReSym-linux.zip" -o "$tmpzip"; \
    printf '%s  %s\n' '33356896529915cccdb1b2d5d73f8a0b719350136285496b7946036339fbe6fe' "$tmpzip" | sha256sum -c -; \
    unzip -o "$tmpzip" -d /tmp/goresym; \
    install -m 755 /tmp/goresym/GoReSym /usr/local/bin/GoReSym; \
    rm -rf "$tmpzip" /tmp/goresym
