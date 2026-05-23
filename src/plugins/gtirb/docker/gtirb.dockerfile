#===== RUNTIME =====
RUN python3 -m venv /opt/rikune-venvs/gtirb && \
    /opt/rikune-venvs/gtirb/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/rikune-venvs/gtirb/bin/pip install --no-cache-dir gtirb
