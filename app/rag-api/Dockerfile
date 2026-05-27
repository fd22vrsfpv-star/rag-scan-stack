# app/rag-api/Dockerfile
FROM python:3.10-slim

# Install curl for healthcheck, dnsutils for reverse DNS lookups (dig), git for exploitdb updates
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements FIRST — this layer is cached unless requirements.txt changes
COPY app/rag-api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code AFTER deps — code changes don't re-trigger pip install
COPY app/rag-api/ /app/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
