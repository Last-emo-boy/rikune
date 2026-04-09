#===== RUNTIME =====
# ── .NET 8 runtime for managed assembly execution ──
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && \
    wget -qO /tmp/packages-microsoft-prod.deb \
      "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" && \
    dpkg -i /tmp/packages-microsoft-prod.deb && rm /tmp/packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends dotnet-runtime-8.0 && \
    rm -rf /var/lib/apt/lists/*
ENV DOTNET_PATH=/usr/bin/dotnet
