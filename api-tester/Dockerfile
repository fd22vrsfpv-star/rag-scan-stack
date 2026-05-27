# ── Stage 1: Build frontend ──
FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ──
FROM python:3.12-slim
LABEL maintainer="pentest-tools"
LABEL description="Standalone API Tester — Swagger to Burp Suite"

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy built frontend into /app/static (where main.py expects it)
COPY --from=frontend-build /build/dist/ ./static/

# Data directory for JSON persistence
RUN mkdir -p /data/swagger
VOLUME /data

# Swagger files can also be mounted separately
VOLUME /data/swagger

ENV DATA_DIR=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8090

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8090"]
