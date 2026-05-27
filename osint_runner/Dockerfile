# Python runtime with pre-built Go binaries
# Binaries are built by: scripts/build-go-tools.sh → osint_runner/bin/
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils musl whatweb chromium whois \
    && rm -rf /var/lib/apt/lists/*

# Install findomain (Rust binary — prebuilt for linux amd64/arm64, distributed as .zip)
RUN apt-get update && apt-get install -y --no-install-recommends unzip && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then \
      FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64.zip"; \
    else \
      FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip"; \
    fi && \
    curl -sL "$FINDOMAIN_URL" -o /tmp/findomain.zip && \
    unzip -o /tmp/findomain.zip -d /tmp/findomain_extract && \
    find /tmp/findomain_extract -name 'findomain*' -type f ! -name '*.zip' -exec cp {} /usr/local/bin/findomain \; && \
    chmod +x /usr/local/bin/findomain && \
    rm -rf /tmp/findomain.zip /tmp/findomain_extract && \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && \
    echo "[osint-runner] Installed findomain (${ARCH})" || \
    echo "[osint-runner] WARNING: findomain download failed"

# Copy pre-built Go binaries (built by scripts/build-go-tools.sh, needs musl)
# Uses bulk copy so the build succeeds even if some binaries are missing.
# Missing tools will fail at runtime, not at build time.
COPY osint_runner/bin/ /tmp/osint-bin/
RUN TOOLS="subfinder dnsx asnmap uncover cloudlist alterx mapcidr chaos shuffledns vulnx amass gau waybackurls trufflehog httpx tlsx gowitness massdns katana"; \
    for tool in $TOOLS; do \
      if [ -f "/tmp/osint-bin/$tool" ]; then \
        cp "/tmp/osint-bin/$tool" "/usr/local/bin/$tool" && chmod +x "/usr/local/bin/$tool"; \
        echo "[osint-runner] Installed $tool"; \
      else \
        echo "[osint-runner] WARNING: $tool binary not found — run scripts/build-go-tools.sh"; \
      fi; \
    done && rm -rf /tmp/osint-bin
# Resolver list from git-tracked file (always available, even on fresh clone)
COPY osint_runner/resolvers.txt            /usr/share/massdns/lists/resolvers.txt

WORKDIR /runner
ENV PYTHONUNBUFFERED=1
ENV CHROME_PATH=/usr/bin/chromium

COPY osint_runner/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt

COPY osint_runner/resolvers.txt    /runner/resolvers.txt
COPY osint_runner/osint_runner.py  /runner/osint_runner.py
COPY osint_runner/validation.py    /runner/validation.py
COPY osint_runner/log_manager.py   /runner/log_manager.py
COPY osint_runner/service_enum.py  /runner/service_enum.py

EXPOSE 8024
CMD ["python", "-u", "/runner/osint_runner.py"]
