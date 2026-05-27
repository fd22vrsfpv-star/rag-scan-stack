# Use official Playwright image with Python and browsers pre-installed
FROM mcr.microsoft.com/playwright/python:v1.40.0-focal

# Set working directory
WORKDIR /app

# Install system dependencies (exiftool for metadata extraction)
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    curl \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for reports and screenshots
RUN mkdir -p /reports /screenshots

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8014

# Health check
HEALTHCHECK --interval=20s --timeout=5s --retries=15 \
  CMD curl -f http://127.0.0.1:8014/health || exit 1

# Run the FastAPI application
CMD ["uvicorn", "playwright_scanner:app", "--host", "0.0.0.0", "--port", "8014", "--log-level", "info"]
