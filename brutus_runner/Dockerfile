# Stage 1: Build Brutus binary (static so it runs on any Linux base)
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

RUN CGO_ENABLED=0 go install github.com/praetorian-inc/brutus/cmd/brutus@latest

# Stage 2: Python runtime
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/brutus /usr/local/bin/brutus

WORKDIR /runner
ENV PYTHONUNBUFFERED=1

COPY brutus_runner/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt

COPY brutus_runner/brutus_runner.py /runner/brutus_runner.py
COPY brutus_runner/validation.py    /runner/validation.py
COPY brutus_runner/log_manager.py   /runner/log_manager.py

EXPOSE 8025
CMD ["python", "-u", "/runner/brutus_runner.py"]
