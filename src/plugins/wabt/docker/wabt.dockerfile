#===== ARGS =====
ARG WABT_VERSION=1.0.39

#===== RUNTIME =====
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends wabt; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /opt/wabt/bin; \
    for tool in wasm2wat wasm-objdump wasm-decompile wasm2c wasm-validate; do \
      if command -v "$tool" >/dev/null 2>&1; then ln -sf "$(command -v "$tool")" "/opt/wabt/bin/$tool"; fi; \
    done
