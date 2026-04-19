#===== RUNTIME =====
# ── Wine (Windows compatibility layer — 64-bit + 32-bit) ──
# wine32 requires i386 multiarch; must add arch before apt-get update
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      wine wine64 wine32:i386 && \
    rm -rf /var/lib/apt/lists/* && \
    wine --version && \
    command -v winedbg >/dev/null 2>&1

# Suppress Wine debug noise in tool output
ENV WINEDEBUG=-all
