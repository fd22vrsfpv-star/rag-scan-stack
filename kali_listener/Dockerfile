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

# Tools the KB recommender asks for that were missing from this image.
#
# Every one of these was recommended by scan_recommendations and then skipped at
# dispatch with "'<tool>' missing on kali; install failed". A runtime
# auto-install path exists, but apt inside a running container is slow, flaky and
# lost on the next rebuild — baking them in makes the recommendation queue
# actionable and keeps it that way.
#
# Package names differ from the tool names the recommender emits, which is WHY the
# runtime auto-install failed even for tools that do exist: it apt-installs the
# scanner name verbatim. Each mapping below was verified with apt-cache policy
# against the Kali repo before being added:
#   avahi-browse -> avahi-utils       ntpq / ntpdate -> ntpsec, ntpsec-ntpdate
#   snmp-check   -> snmpcheck         tftp           -> tftp-hpa
#   vncviewer    -> tigervnc-viewer   xspy / xwd     -> x11-apps, x11-utils
RUN apt-get update && apt-get install -y --no-install-recommends \
    avahi-utils \
    crackmapexec \
    dnsenum \
    dnsrecon \
    enum4linux-ng \
    ftp \
    gobuster \
    irssi \
    lftp \
    ntpsec \
    ntpsec-ntpdate \
    nuclei \
    smtp-user-enum \
    snmpcheck \
    sqlmap \
    swaks \
    telnet \
    tftp-hpa \
    tigervnc-viewer \
    x11-apps \
    x11-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# remote-method-guesser (rmg) — java-rmi enumeration, the tool the KB recommends
# for port 1099. Not in the Kali repos, so it comes from its GitHub release as a
# fat jar, which also needs a JRE the image did not have.
#
# Version is PINNED: an unpinned "latest" makes scan results non-reproducible and
# silently changes tool behaviour between rebuilds.
#
# The build FAILS if the download does not produce a usable jar. A soft failure
# would leave an image that reports rmg as installed while every run errors —
# the same silent-success shape this stack has been bitten by repeatedly.
ARG RMG_VERSION=5.1.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /opt/rmg.jar \
      "https://github.com/qtc-de/remote-method-guesser/releases/download/v${RMG_VERSION}/rmg-${RMG_VERSION}-jar-with-dependencies.jar" \
 && printf '#!/bin/sh\nexec java -jar /opt/rmg.jar "$@"\n' > /usr/local/bin/rmg \
 && chmod +x /usr/local/bin/rmg \
 # Verify on OUTPUT, not exit status: rmg --help prints correct usage and then
 # exits 1, like many Java CLIs. Checking $? failed the build on a working
 # install. Grepping for the banner proves the jar, the JRE and the wrapper all
 # work together, which is what we actually want to assert.
 && rmg --help 2>&1 | grep -q "remote-method-guesser" \
 || (echo "ERROR: rmg did not install correctly" && exit 1)

# Deliberately NOT installed here:
#   metasploit-framework (~2GB) — the stack already runs a dedicated `metasploit`
#     container with msfrpcd, which exploit-runner drives over RPC. A second copy
#     inside kali costs ~2GB for no new capability; the 41 metasploit
#     recommendations need ROUTING to that service, not another install.
#   katana — not in the Kali repos, and not needed here: pd-runner already serves
#     /jobs/katana with the binary installed. Recommendations route there.
#     (rmg IS installed above, from its GitHub release — see the pinned block.)

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
