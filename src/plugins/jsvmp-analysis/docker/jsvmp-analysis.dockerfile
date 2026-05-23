#===== RUNTIME =====
RUN mkdir -p /opt/rikune-backends/jsvmp-analysis/bin
COPY src/plugins/jsvmp-analysis/workers/jsvmp-worker.js /opt/rikune-backends/jsvmp-analysis/bin/jsvmp-worker.js
RUN chmod +x /opt/rikune-backends/jsvmp-analysis/bin/jsvmp-worker.js
