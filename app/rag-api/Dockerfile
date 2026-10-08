# app/rag-api/Dockerfile
FROM python:3.10-slim

# Install curl for healthcheck, dnsutils for reverse DNS lookups (dig), git for exploitdb updates
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils git \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements FIRST — this layer is cached unless requirements.txt changes
COPY app/rag-api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code AFTER deps — code changes don't re-trigger pip install
COPY app/rag-api/ /app/

# Burp Suite bridge extension — the Jython .py the operator loads into Burp
# Pro (Settings → Tool Options → "Download Burp bridge extension" / Exploit
# Workbench → Tools → "Burp bridge .py"). Shipped here because the rag-api
# build context is the repo root; the pentest-dashboard build context is
# ./dashboard and can't see this directory.
COPY burp-extension/ /app/burp-extension/

# Bake a BUILD-TIME version stamp into the image so it reflects the code the
# image actually contains, independent of the CREATE-TIME `BUILD_VERSION` env
# (docker-compose environment block). A container that was NOT recreated after a
# version bump keeps the OLD env value while running current code; comparing the
# two in the health output makes that staleness visible. Passed via compose
# build.args; defaults to "unknown" when built without the arg.
ARG BUILD_VERSION=unknown
ENV IMAGE_BUILD_VERSION=$BUILD_VERSION

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
