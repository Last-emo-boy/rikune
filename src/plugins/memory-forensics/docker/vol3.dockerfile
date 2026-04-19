#===== RUNTIME =====
# ── Volatility 3 (memory forensics framework) ──
RUN pip install --no-cache-dir volatility3 && \
    mkdir -p /opt/vol3-symbols /app/cache/home/.cache && \
    HOME=/app/cache/home python3 -c "import volatility3; print('✓ volatility3')" && \
    HOME=/app/cache/home /usr/local/bin/vol --help >/dev/null
