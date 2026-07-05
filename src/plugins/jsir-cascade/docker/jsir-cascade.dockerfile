#===== RUNTIME =====
RUN mkdir -p /opt/rikune-backends/jsir-cascade/bin
COPY src/plugins/jsir-cascade/workers/jsir-cascade-worker.js /opt/rikune-backends/jsir-cascade/bin/jsir-cascade-worker.js
RUN chmod +x /opt/rikune-backends/jsir-cascade/bin/jsir-cascade-worker.js
