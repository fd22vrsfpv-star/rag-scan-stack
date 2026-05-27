FROM ubuntu:22.04

ARG SLIVER_VERSION=1.7.3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git mingw-w64 build-essential \
    && rm -rf /var/lib/apt/lists/*

# Download Sliver server binary
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then SLIVER_ARCH="amd64"; \
    elif [ "$ARCH" = "arm64" ]; then SLIVER_ARCH="arm64"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -fSL "https://github.com/BishopFox/sliver/releases/download/v${SLIVER_VERSION}/sliver-server_linux-${SLIVER_ARCH}" \
    -o /usr/local/bin/sliver-server && \
    chmod +x /usr/local/bin/sliver-server

# Unpack (first run initializes configs + crypto)
RUN sliver-server unpack --force

# Create dirs for configs
RUN mkdir -p /root/.sliver /root/.sliver-client/configs

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 31337: multiplexed (gRPC + HTTPS C2)
# 10000-10099: SOCKS proxy ports allocated per node
EXPOSE 31337 10000-10099

ENTRYPOINT ["/entrypoint.sh"]
