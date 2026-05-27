FROM python:3.12-slim

# Install systemctl and curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemctl curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY host-helper/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY host-helper/host_helper.py /app/host_helper.py

ENV PYTHONUNBUFFERED=1
EXPOSE 8029

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8029/health || exit 1

CMD ["uvicorn", "host_helper:app", "--host", "0.0.0.0", "--port", "8029"]