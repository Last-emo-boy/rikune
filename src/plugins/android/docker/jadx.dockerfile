#===== ARGS =====
ARG JADX_VERSION=1.5.1

#===== RUNTIME =====
ARG JADX_VERSION

# ── JADX ──
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip && \
    printf '%s  %s\n' '12fd966431903b8e15c36e5007f19343475be7d8f2a55f082e7a929eeabc937e' /tmp/jadx.zip | sha256sum -c - && \
    mkdir -p /opt/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm -f /tmp/jadx.zip && \
    rm -rf /var/lib/apt/lists/*

# Plugin-specific scripts (co-located with android plugin)
COPY src/plugins/android/scripts/ ./src/plugins/android/scripts/
