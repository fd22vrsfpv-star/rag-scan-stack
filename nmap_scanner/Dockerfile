FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl nmap wget masscan git tini netcat-openbsd hydra proxychains4 && \
    rm -rf /var/lib/apt/lists/*
# Pin to specific commits for reproducibility (update these as needed)
ARG VULNERS_COMMIT=master
ARG VULSCAN_COMMIT=master
WORKDIR /app

#ENV NMAP_SCRIPTS_DIR=/usr/share/nmap/scripts
# Set environment variables
ENV NMAP_SCRIPTS_DIR=/usr/share/nmap/scripts/vulscan
ENV VULSCAN_REPO=https://github.com/scipag/vulscan.git
ENV VULSCAN_COMMIT=master


COPY nmap_scanner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Make "app" a package and add the runner script
RUN mkdir -p /app/app && touch /app/app/__init__.py
COPY app/run_masscan_nmap.py /app/app/run_masscan_nmap.py

# Minimal API exposing the job
COPY nmap_scanner/nmap-api.py /app/nmap-api.py
COPY nmap_scanner/validation.py /app/validation.py
COPY nmap_scanner/log_manager.py /app/log_manager.py
COPY nmap_scanner/cred_checker.py /app/cred_checker.py
# Install vulscan and vulners NSE scripts for vulnerability scanning
# Clone vulscan repository
RUN set -eux; \
    git clone --depth 1 --branch "${VULSCAN_COMMIT}" ${VULSCAN_REPO} scipag_vulscan; \
    mkdir -p ${NMAP_SCRIPTS_DIR}; \
    cp -r scipag_vulscan/*.nse ${NMAP_SCRIPTS_DIR}/; \
    mkdir -p ${NMAP_SCRIPTS_DIR}/vulscan; \
    cp -r scipag_vulscan/* ${NMAP_SCRIPTS_DIR}/vulscan/; \
    rm -rf scipag_vulscan

# Download vulnerability databases from GitHub (more reliable than computec.ch)
RUN set -eux; \
    cd ${NMAP_SCRIPTS_DIR}/vulscan && \
    for db in cve exploitdb openvas osvdb scipvuldb securityfocus securitytracker xforce; do \
        echo "Downloading ${db}.csv..."; \
        wget -q --timeout=30 "https://raw.githubusercontent.com/scipag/vulscan/master/${db}.csv" -O "${db}.csv" || \
        echo "Warning: Failed to download ${db}.csv, using bundled version"; \
    done && \
    ls -la *.csv

# Install vulners NSE script (queries vulners.com API for CVEs)
RUN set -eux; \
    wget -q "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" \
        -O /usr/share/nmap/scripts/vulners.nse || \
    echo "Warning: vulners.nse download failed"


# Rebuild Nmap script database so the new modules are recognized
RUN nmap --script-updatedb

ENV PYTHONUNBUFFERED=1
EXPOSE 8012
CMD ["uvicorn","nmap-api:app","--host","0.0.0.0","--port","8012"]
