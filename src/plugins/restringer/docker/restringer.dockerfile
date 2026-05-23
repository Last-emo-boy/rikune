#===== RUNTIME =====
RUN mkdir -p /opt/rikune-backends/restringer/bin
COPY src/plugins/restringer/workers/restringer-worker.js /opt/rikune-backends/restringer/bin/restringer-worker.js
RUN chmod +x /opt/rikune-backends/restringer/bin/restringer-worker.js
