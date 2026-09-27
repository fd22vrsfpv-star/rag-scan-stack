FROM python:3.11-slim

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY autogen-http-mcp-server.py .

# Bake a build-time version stamp (see app/rag-api/Dockerfile) so a container
# not recreated after a version bump reports IMAGE_BUILD_VERSION != BUILD_VERSION.
ARG BUILD_VERSION=unknown
ENV IMAGE_BUILD_VERSION=$BUILD_VERSION

# Expose MCP HTTP port
EXPOSE 8016

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8016/health || exit 1

# Run the HTTP MCP server
CMD ["python", "autogen-http-mcp-server.py"]
