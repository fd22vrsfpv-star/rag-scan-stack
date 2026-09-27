FROM nvidia/cuda:12.1.1-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip git curl cmake ninja-build && \
    ln -sf /usr/bin/python3 /usr/bin/python && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install llama.cpp for GGUF conversion
RUN git clone --depth 1 https://github.com/ggerganov/llama.cpp /app/llama.cpp && \
    pip install --no-cache-dir --no-deps gguf

COPY . .

# Bake a build-time version stamp (see app/rag-api/Dockerfile) so a container
# not recreated after a version bump reports IMAGE_BUILD_VERSION != BUILD_VERSION.
ARG BUILD_VERSION=unknown
ENV IMAGE_BUILD_VERSION=$BUILD_VERSION

EXPOSE 8025

CMD ["uvicorn", "training_service:app", "--host", "0.0.0.0", "--port", "8025"]
