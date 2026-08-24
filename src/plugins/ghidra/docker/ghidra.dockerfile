#===== ARGS =====
ARG GHIDRA_VERSION=12.1.3

#===== STAGE =====
# =============================================================================
# Ghidra (JDK + headless analysis)
# =============================================================================
FROM eclipse-temurin:21-jdk@sha256:85f00967bcc624fc19fa9c2cf124ea426a5363898e267141726f31f358c2e14b AS ghidra-stage

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG GHIDRA_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

WORKDIR /opt

RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20260817.zip"; \
    curl -fsSL --connect-timeout 120 --retry 3 --retry-delay 10 -o ghidra.zip "$GHIDRA_URL"; \
    printf '%s  %s\n' '93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54' ghidra.zip | sha256sum -c -; \
    FILE_SIZE=$(wc -c < ghidra.zip); \
    if [ "$FILE_SIZE" -lt 1000000 ]; then \
        echo "ERROR: Ghidra archive too small"; \
        exit 1; \
    fi; \
    unzip -q ghidra.zip; \
    mv ghidra_* ghidra; \
    rm ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/opt/java/openjdk

RUN test -f /opt/ghidra/support/analyzeHeadless

#===== RUNTIME =====
ENV JAVA_HOME=/opt/java/openjdk
ENV JAVA_TOOL_OPTIONS=
ENV PATH="/opt/java/openjdk/bin:${PATH}"

COPY --from=ghidra-stage /opt/java/openjdk /opt/java/openjdk
COPY --from=ghidra-stage /opt/ghidra /opt/ghidra
COPY src/plugins/ghidra/scripts/ ./src/plugins/ghidra/scripts/
