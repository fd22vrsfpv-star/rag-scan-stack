# Python runtime with pre-built Go binaries
# Binaries are built by: scripts/build-go-tools.sh → pd_runner/bin/
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils libpcap-dev \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built Go binaries (built by scripts/build-go-tools.sh)
# Uses a wildcard so the build succeeds even if some binaries are missing.
# Missing tools will fail at runtime, not at build time.
COPY pd_runner/bin/ /tmp/pd-bin/
RUN for tool in httpx naabu katana tlsx ffuf; do \
      if [ -f "/tmp/pd-bin/$tool" ]; then \
        cp "/tmp/pd-bin/$tool" "/usr/local/bin/$tool" && chmod +x "/usr/local/bin/$tool"; \
        echo "[pd-runner] Installed $tool"; \
      else \
        echo "[pd-runner] WARNING: $tool binary not found — run scripts/build-go-tools.sh"; \
      fi; \
    done && rm -rf /tmp/pd-bin

WORKDIR /runner
ENV PYTHONUNBUFFERED=1

# Download common wordlists for ffuf
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    curl -sL -o /usr/share/seclists/Discovery/Web-Content/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt || true

COPY pd_runner/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt

COPY pd_runner/pd_runner.py     /runner/pd_runner.py
COPY pd_runner/validation.py    /runner/validation.py
COPY pd_runner/log_manager.py   /runner/log_manager.py

EXPOSE 8023
CMD ["python", "-u", "/runner/pd_runner.py"]
