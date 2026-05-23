#===== RUNTIME =====
RUN mkdir -p /opt/rikune-backends/manifold/bin
COPY src/plugins/manifold/workers/manifold-worker.js /opt/rikune-backends/manifold/bin/manifold-worker.js
RUN chmod +x /opt/rikune-backends/manifold/bin/manifold-worker.js
