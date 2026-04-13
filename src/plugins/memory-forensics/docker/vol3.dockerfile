#===== RUNTIME =====
# ── Volatility 3 (memory forensics framework) ──
RUN pip install --no-cache-dir volatility3 && \
    mkdir -p /opt/vol3-symbols && \
    python3 -c "import volatility3; print('✓ volatility3')"
