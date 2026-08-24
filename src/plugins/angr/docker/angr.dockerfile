#===== STAGE =====
# =============================================================================
# angr (isolated symbolic execution venv)
# =============================================================================
FROM python-base AS angr-python

COPY src/plugins/angr/requirements.lock.txt /tmp/angr-requirements.lock.txt

RUN python3 -m venv /opt/angr-venv && \
    /opt/angr-venv/bin/pip install --no-cache-dir --require-hashes \
      -r /tmp/angr-requirements.lock.txt && \
    /opt/angr-venv/bin/python -c "import angr; print('✓ angr', angr.__version__)"

#===== RUNTIME =====
COPY --from=angr-python /opt/angr-venv /opt/angr-venv
