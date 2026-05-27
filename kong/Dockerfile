# ./kong/Dockerfile
FROM docker.io/library/kong:3.6

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl bash netcat-openbsd iproute2 dnsutils \
 && rm -rf /var/lib/apt/lists/*

# (optional) healthcheck uses Admin API on 7081 if you bound it there
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -fsS http://127.0.0.1:7081/status || exit 1

USER kong

