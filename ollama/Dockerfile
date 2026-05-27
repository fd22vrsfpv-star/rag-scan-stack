wor# Dockerfile
FROM ollama/ollama:latest

# Install curl (and CA certs) using the available package manager
RUN set -eux; \
    if command -v apt-get >/dev/null; then \
      apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null; then \
      apk add --no-cache curl ca-certificates; \
    elif command -v microdnf >/dev/null; then \
      microdnf install -y curl ca-certificates && microdnf clean all; \
    else \
      echo "No supported package manager found to install curl" >&2; exit 1; \
    fi

# Listen on all interfaces (not just 127.0.0.1)
ENV OLLAMA_HOST=0.0.0.0
# Ollama listens on 11434 by default
EXPOSE 11434

# Keep the model/cache dir as a mount point (optional but handy)
VOLUME ["/root/.ollama"]

# Copy entrypoint that ensures required models are present, then serves
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Use custom entrypoint to ensure required models are present
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
