#===== ARGS =====
ARG ANGR_VERSION=9.2.205

#===== STAGE =====
# =============================================================================
# angr (isolated symbolic execution venv)
# =============================================================================
FROM python-base AS angr-python

ARG ANGR_VERSION

RUN python3 -m venv /opt/angr-venv && \
    /opt/angr-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/angr-venv/bin/pip install --no-cache-dir "angr==${ANGR_VERSION}" && \
    /opt/angr-venv/bin/python -c "import angr; print('✓ angr', angr.__version__)"

#===== RUNTIME =====
COPY --from=angr-python /opt/angr-venv /opt/angr-venv
