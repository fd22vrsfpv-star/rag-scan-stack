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

# Expose MCP HTTP port
EXPOSE 8016

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8016/health || exit 1

# Run the HTTP MCP server
CMD ["python", "autogen-http-mcp-server.py"]
