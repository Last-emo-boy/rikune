#===== STAGE =====
# =============================================================================
# Qiling (isolated unicorn>=2 venv)
# =============================================================================
FROM python-base AS qiling-python

RUN python3 -m venv /opt/qiling-venv && \
    /opt/qiling-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/qiling-venv/bin/pip install --no-cache-dir -r /app/workers/requirements-qiling.txt && \
    /opt/qiling-venv/bin/python -c "import qiling; print('✓ qiling', getattr(qiling, '__version__', 'unknown'))"

#===== RUNTIME =====
COPY --from=qiling-python /opt/qiling-venv /opt/qiling-venv
