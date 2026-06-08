# Stage 1: Build Brutus binary (static so it runs on any Linux base)
# brutus@latest currently requires Go >= 1.26. The official golang images pin
# GOTOOLCHAIN=local, so we both bump the base and allow toolchain auto-upgrade
# to stay ahead of future Go-version bumps in upstream brutus.
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

ENV GOTOOLCHAIN=auto

RUN CGO_ENABLED=0 go install github.com/praetorian-inc/brutus/cmd/brutus@latest

# Stage 2: Python runtime
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/brutus /usr/local/bin/brutus

# Kali-style wordlist path compatibility.
#
# docker-compose bind-mounts the host's ./wordlists/ at /wordlists:ro
# (read-only) -- that's where SecLists/rockyou/etc. live, populated by
# ./scripts/install-wordlists.sh.  The KB commands reference Kali's
# canonical /usr/share/wordlists/... paths.  Symlinking the two
# directories means an operator pasting `hydra ... -P
# /usr/share/wordlists/rockyou.txt` from the KB resolves to the same
# file as `/wordlists/rockyou.txt`, and brutus_runner.py's
# `_validate_wordlist_path` accepts both prefixes (see brutus_runner.py).
RUN mkdir -p /usr/share && ln -s /wordlists /usr/share/wordlists

WORKDIR /runner
ENV PYTHONUNBUFFERED=1

COPY brutus_runner/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt

COPY brutus_runner/brutus_runner.py /runner/brutus_runner.py
COPY brutus_runner/validation.py    /runner/validation.py
COPY brutus_runner/log_manager.py   /runner/log_manager.py

EXPOSE 8025
CMD ["python", "-u", "/runner/brutus_runner.py"]
