FROM python:3.12-slim

# Install curl for healthcheck + docker CLI with compose plugin for mode switching
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin nmap openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY container_logs/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY container_logs/container_logs.py /app/container_logs.py

ENV PYTHONUNBUFFERED=1

EXPOSE 8018

CMD ["uvicorn", "container_logs:app", "--host", "0.0.0.0", "--port", "8018"]
