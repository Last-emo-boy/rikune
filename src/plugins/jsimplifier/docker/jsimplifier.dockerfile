#===== RUNTIME =====
RUN mkdir -p /opt/rikune-backends/jsimplifier/bin
COPY src/plugins/jsimplifier/workers/jsimplifier-worker.js /opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js
RUN chmod +x /opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js
