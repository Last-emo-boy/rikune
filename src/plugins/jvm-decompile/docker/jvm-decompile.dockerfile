#===== ARGS =====
ARG CFR_VERSION=0.152

#===== STAGE =====
FROM eclipse-temurin:21-jdk@sha256:85f00967bcc624fc19fa9c2cf124ea426a5363898e267141726f31f358c2e14b AS jvm-decompile-stage

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG CFR_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/cfr; \
    curl -fsSL --connect-timeout 120 --retry 3 --retry-delay 10 \
      -o /opt/cfr/cfr.jar \
      "https://github.com/leibnitz27/cfr/releases/download/${CFR_VERSION}/cfr-${CFR_VERSION}.jar"; \
    printf '%s  %s\n' 'f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2' /opt/cfr/cfr.jar | sha256sum -c -; \
    test "$(wc -c < /opt/cfr/cfr.jar)" -gt 1000000; \
    java -jar /opt/cfr/cfr.jar --version

#===== RUNTIME =====
ENV JAVA_HOME=/opt/java/openjdk
ENV JAVA_PATH=/opt/java/openjdk/bin/java
ENV CFR_JAR=/opt/cfr/cfr.jar
ENV PATH="/opt/java/openjdk/bin:${PATH}"

COPY --from=jvm-decompile-stage /opt/java/openjdk /opt/java/openjdk
COPY --from=jvm-decompile-stage /opt/cfr/cfr.jar /opt/cfr/cfr.jar

RUN "$JAVA_PATH" -jar "$CFR_JAR" --version
