FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
    perl libnet-ssleay-perl libwhisker2-perl libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub (latest version)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

ENV GOBUSTER_VER=3.6.0
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then GOBUSTER_ARCH="arm64"; else GOBUSTER_ARCH="x86_64"; fi && \
    curl -L -o /tmp/gobuster.tar.gz \
      "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VER}/gobuster_Linux_${GOBUSTER_ARCH}.tar.gz" && \
    tar -C /usr/local/bin -xzf /tmp/gobuster.tar.gz gobuster && \
    chmod +x /usr/local/bin/gobuster && rm -f /tmp/gobuster.tar.gz

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists

WORKDIR /scanner
ENV PYTHONUNBUFFERED=1

COPY web_scanner/requirements.txt /scanner/requirements.txt
RUN pip install --no-cache-dir -r /scanner/requirements.txt

COPY web_scanner /scanner

EXPOSE 8010
CMD ["python","-u","/scanner/web_scan.py","serve"]
