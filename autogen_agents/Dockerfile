FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy and make entrypoint executable
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create necessary directories
RUN mkdir -p /app/logs /app/cache

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 8015

# Health check (for FastAPI mode)
HEALTHCHECK --interval=20s --timeout=5s --retries=15 \
    CMD curl -f http://127.0.0.1:8015/health || exit 1

# Use entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default: Run FastAPI server
CMD []
