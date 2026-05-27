FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssh-client autossh netcat-openbsd socat wireguard-tools \
    docker.io docker-compose && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY node_manager/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY node_manager/node_manager.py /app/node_manager.py
COPY node_manager/sliver_client.py /app/sliver_client.py
COPY node_manager/proxy_allocator.py /app/proxy_allocator.py
COPY node_manager/ad_executor.py /app/ad_executor.py
COPY node_manager/ssh_manager.py /app/ssh_manager.py
COPY osint_runner/service_enum_cli.py /app/service_enum_cli.py

ENV PYTHONUNBUFFERED=1
EXPOSE 8027
CMD ["uvicorn", "node_manager:app", "--host", "0.0.0.0", "--port", "8027"]
