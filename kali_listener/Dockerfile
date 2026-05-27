FROM kalilinux/kali-rolling:latest

# Configure Kali mirror to avoid problematic CDN mirrors
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

# Install required packages - listeners and core tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-traditional \
    socat \
    python3 \
    python3-pip \
    python3-venv \
    libpq-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install pentest tools for reconnaissance and enumeration
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    medusa \
    enum4linux \
    smbclient \
    smbmap \
    nikto \
    whatweb \
    dnsutils \
    ldap-utils \
    snmp \
    onesixtyone \
    redis-tools \
    postgresql-client \
    default-mysql-client \
    ssh-audit \
    netexec \
    impacket-scripts \
    nbtscan \
    rpcbind \
    nfs-common \
    wordlists \
    seclists \
    hashcat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Extract rockyou wordlist (comes compressed)
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Create app directory
WORKDIR /app

# Create symlinks in /app (working directory) for tools that expect users.txt/passwords.txt
RUN ln -sf /usr/share/seclists/Usernames/top-usernames-shortlist.txt /app/users.txt && \
    ln -sf /usr/share/wordlists/rockyou.txt /app/passwords.txt

# Also create a wordlists directory with more options
RUN mkdir -p /app/wordlists && \
    ln -sf /usr/share/wordlists/rockyou.txt /app/wordlists/rockyou.txt && \
    ln -sf /usr/share/seclists/Usernames/top-usernames-shortlist.txt /app/wordlists/users-short.txt && \
    ln -sf /usr/share/seclists/Usernames/Names/names.txt /app/wordlists/users-names.txt && \
    ln -sf /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt /app/wordlists/passwords-10k.txt

# Copy requirements and install
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Copy application
COPY listener_service.py .
COPY log_manager.py .

# Expose API port and listener port range
EXPOSE 8019
EXPOSE 9080-9180

# Run the service
CMD ["python3", "listener_service.py"]
