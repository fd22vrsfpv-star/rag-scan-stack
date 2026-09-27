FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/embedder/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/embedder/ /app/

# Bake a build-time version stamp (see app/rag-api/Dockerfile) so a container
# not recreated after a version bump reports IMAGE_BUILD_VERSION != BUILD_VERSION.
ARG BUILD_VERSION=unknown
ENV IMAGE_BUILD_VERSION=$BUILD_VERSION

ENV PYTHONUNBUFFERED=1

EXPOSE 8030

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8030"]
