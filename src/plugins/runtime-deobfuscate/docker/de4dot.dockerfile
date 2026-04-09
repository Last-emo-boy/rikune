#===== RUNTIME =====
# ── de4dot (.NET deobfuscator) ──
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip && \
    wget -q -O /tmp/de4dot.zip https://github.com/de4dot/de4dot/releases/latest/download/de4dot-net45.zip && \
    unzip -q /tmp/de4dot.zip -d /opt/de4dot && \
    ln -s /opt/de4dot/de4dot.exe /usr/local/bin/de4dot && \
    rm /tmp/de4dot.zip && \
    apt-get purge -y wget unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
ENV DE4DOT_PATH=/opt/de4dot/de4dot.exe
