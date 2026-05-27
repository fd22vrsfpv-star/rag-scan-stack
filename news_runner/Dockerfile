FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY news_runner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY news_runner/main.py .
COPY news_runner/news_agent.py .

EXPOSE 8028

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs http://127.0.0.1:8028/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8028"]
