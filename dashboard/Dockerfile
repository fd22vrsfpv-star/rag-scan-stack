FROM node:20-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx supervisor curl openssl \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev libcairo2 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Generate self-signed TLS certificate
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/dashboard.key \
      -out /etc/nginx/ssl/dashboard.crt \
      -subj "/C=US/ST=Security/L=Pentest/O=Dashboard/CN=pentest-dashboard"

# BFF dependencies
COPY bff/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy BFF
COPY bff/ /app/bff/

# Copy built frontend
COPY --from=frontend-build /build/dist /app/frontend/dist

# Config
COPY nginx.conf /etc/nginx/sites-enabled/default
RUN sed -i 's|/run/nginx.pid|/tmp/nginx.pid|g' /etc/nginx/nginx.conf || true
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 80 443
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
