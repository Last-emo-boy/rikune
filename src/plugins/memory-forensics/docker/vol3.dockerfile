#===== RUNTIME =====
# ── Volatility 3 (memory forensics framework) ──
RUN mkdir -p /opt/vol3-symbols /tmp/rikune-home/.cache && \
    HOME=/tmp/rikune-home python3 -c "import volatility3; print('✓ volatility3')" && \
    HOME=/tmp/rikune-home /usr/local/bin/vol --help >/dev/null
