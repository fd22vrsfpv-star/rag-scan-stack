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
    # Declared in knowledge/service_tools.yaml and knowledge/wstg_map.yaml but
    # installed nowhere, so every recommendation naming one was dispatched here
    # and died with "not found" — which surfaces as a failed scan rather than a
    # missing tool. sslscan is the worst of the four: TWO WSTG map entries
    # (WSTG-CRYP weak-transport tests) run `sslscan {target}`, so that whole
    # family could never have produced a result.
    #
    # knowledge/tool_catalogs.json listed ncrack as PRESENT, which is why the
    # validator never rejected it — the catalog was inventoried 2026-08-15,
    # three weeks before these images were rebuilt. Re-run
    # scripts/refresh-tool-catalogs.sh after changing this list.
    ncrack \
    sslscan \
    ffuf \
    feroxbuster \
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
    git \
    pipx \
    crackmapexec \
    dnsenum \
    dnsrecon \
    enum4linux-ng \
    ftp \
    gobuster \
    cewl \
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

# Active Directory attack toolkit (knowledge/ad_attacks.yaml) — baked so AD
# enumeration/attacks are part of LOCAL enumeration, not a manual install step.
# netexec, impacket-scripts, crackmapexec, enum4linux-ng, smbmap, ldap-utils,
# hashcat are already installed above. Installed per-package so an unavailable
# name in a given kali-rolling snapshot warns instead of breaking the build.
RUN apt-get update && for pkg in \
      responder mitm6 certipy certsync kerbrute evil-winrm ldeep lsassy \
      coercer pcredz bloodhound.py bloodyad ; do \
      apt-get install -y --no-install-recommends "$pkg" || echo "WARN: AD tool '$pkg' not in this kali snapshot"; \
    done; \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# AD tools not in apt (this snapshot) — install from PyPI/GitHub, non-fatal per
# tool so a naming/availability drift warns instead of breaking the build. git is
# installed above so the git+ sources resolve.
RUN pip3 install --break-system-packages --no-cache-dir certipy-ad || echo "WARN: certipy-ad failed"; \
    # Kali ships the binary as 'certipy-ad'; ad_attacks.yaml uses 'certipy' — link both.
    { command -v certipy-ad >/dev/null && ln -sf "$(command -v certipy-ad)" /usr/local/bin/certipy; } || true; \
    for url in \
        "git+https://github.com/ShutdownRepo/targetedKerberoast" \
        "git+https://github.com/zblurx/certsync" \
        "git+https://github.com/garrettfoster13/sccmhunter" ; do \
      pip3 install --break-system-packages --no-cache-dir "$url" || echo "WARN: $url failed"; \
    done
# Pcredz is a standalone script (not on PyPI) — clone + wrapper on PATH.
RUN git clone --depth 1 https://github.com/lgandx/PCredz /opt/PCredz 2>/dev/null \
      && pip3 install --break-system-packages --no-cache-dir Cython python-libpcap 2>/dev/null; \
    printf '#!/bin/sh\nexec python3 /opt/PCredz/Pcredz "$@"\n' > /usr/local/bin/pcredz \
      && chmod +x /usr/local/bin/pcredz || echo "WARN: pcredz not installed"
# kerbrute — Go binary release
RUN curl -fsSL -o /usr/local/bin/kerbrute \
      "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
      && chmod +x /usr/local/bin/kerbrute \
      || echo "WARN: kerbrute binary download failed"

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

# SSH client, for reaching hosts whose algorithms nothing modern will negotiate
# by default.
#
# WHY: 192.168.1.150 is an OpenSSH 4.7p1 offering only ssh-rsa and ssh-dss host
# keys. hydra fails at key exchange and netexec's paramiko raises
# `IncompatiblePeer: no acceptable host key`, and neither takes an algorithm
# flag — so the whole SSH post-access checklist was queued and unrunnable. The
# real ssh client does take one, and the correct value is derived from what
# ssh-audit already recorded about the host intersected with `ssh -Q key`:
#
#     ssh -oHostKeyAlgorithms=+ssh-rsa msfadmin@192.168.1.150   # connects
#     ssh msfadmin@192.168.1.150                                 # refuses
#
# sshpass comes with it because ssh cannot take a password non-interactively and
# a credential follow-up has nothing else to offer. It reads the secret from the
# environment (`-e`), never from argv, so the password does not appear in the
# process list of a shared host.
#
# THIS IS GENERAL-PURPOSE REMOTE EXECUTION. It is allow-listed deliberately and
# at the operator's request; every dispatch still passes the scope gate, and the
# stored command is sanitised by _redacted() before it reaches
# tool_executions.command.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client sshpass \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
 # Verify both, on output rather than exit status — `ssh -V` prints to stderr
 # and sshpass exits non-zero with no arguments.
 && ssh -V 2>&1 | grep -q "OpenSSH" \
 && ssh -Q key 2>/dev/null | grep -q "ssh-ed25519" \
 && (sshpass -h 2>&1 | grep -qi "sshpass" || true) \
 && command -v sshpass >/dev/null \
 || (echo "ERROR: ssh/sshpass did not install correctly" && exit 1)

# Offensive service-vector clients (Stage 2 of the vector-coverage feature).
#
# These run KNOWN non-MSF exploitation attempts against a discovered service —
# the catalogue's `attempt` commands (knowledge/service_access_methods.yaml). They
# are DELIBERATELY NOT in the /tools/execute allow-list: an offensive attempt
# carries shell metacharacters and opens/mutates the target, so it dispatches
# through the scope-gated, un-allowlisted /vectors/run (same trust model as
# /access/run), never the read-only enumeration lane.
#
#   rsh-redone-client -> rsh / rlogin  the r-services vector (512/513/514). On
#                 Kali the netkit `rsh-client` package has no install candidate;
#                 `rsh-redone-client` is the maintained replacement and provides
#                 the same /usr/bin/rsh. It resolves the port from /etc/services
#                 (`shell 514`), which netbase provides; the check below fails the
#                 build if it is ever missing rather than letting `rsh` die with
#                 "shell/tcp: unknown service" at runtime.
#   distcc     -> distcc client        distccd CVE-2004-2687 (3632). The client
#                 is installed for the native path; the verified shell path today
#                 is the MSF module (see the catalogue's `msf:` seed).
RUN apt-get update && apt-get install -y --no-install-recommends \
    rsh-redone-client \
    distcc \
    netbase \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
 && command -v rsh >/dev/null \
 && command -v distcc >/dev/null \
 && grep -qE '^shell[[:space:]]+514/tcp' /etc/services \
 || (echo "ERROR: rsh-client/distcc/netbase did not install correctly" && exit 1)

# Deliberately NOT installed here:
#   metasploit-framework (~2GB) — the stack already runs a dedicated `metasploit`
#     container with msfrpcd, which exploit-runner drives over RPC. A second copy
#     inside kali costs ~2GB for no new capability; the 41 metasploit
#     recommendations need ROUTING to that service, not another install.
#   katana — not in the Kali repos, and not needed here: pd-runner already serves
#     /jobs/katana with the binary installed. Recommendations route there.
#     (rmg IS installed above, from its GitHub release — see the pinned block.)

# PayloadsAllTheThings — the payload/bypass reference corpus, baked LOCAL.
#
# WHY: knowledge/seed/wstg.yaml already sends the operator to this repository by
# URL in three places (File Inclusion, Directory Traversal, Server Side Template
# Injection). Those links resolve only from a host with internet egress — which
# an engagement node routed through a pentest proxy may not have, and which a
# dispatched command cannot follow at all. Baking it in turns three dead
# references into files on disk that a command can actually point `-w` at.
#
# Pinned to a commit, not `master`: this is an input to scan commands, and an
# unpinned corpus silently changes what a payload run tests between rebuilds —
# the same reproducibility rule the rmg block above states. Bump deliberately.
#
# --depth 1 on a pinned sha needs fetch, not clone (~23MB of tree vs ~1GB of
# history). The build FAILS if the checkout does not produce the directories the
# WSTG entries name, because an empty /opt/PayloadsAllTheThings would report as
# installed while every payload path under it 404s on disk — the silent-success
# shape this image has been bitten by before.
ARG PAYLOADS_COMMIT=3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
RUN git init /opt/PayloadsAllTheThings \
 && git -C /opt/PayloadsAllTheThings remote add origin \
      https://github.com/swisskyrepo/PayloadsAllTheThings.git \
 && ( git -C /opt/PayloadsAllTheThings fetch --depth 1 origin "${PAYLOADS_COMMIT}" \
      && git -C /opt/PayloadsAllTheThings checkout -q FETCH_HEAD ) \
 || ( echo "WARN: pinned commit unavailable, falling back to master tip" \
      && git -C /opt/PayloadsAllTheThings fetch --depth 1 origin master \
      && git -C /opt/PayloadsAllTheThings checkout -q FETCH_HEAD ) \
 && rm -rf /opt/PayloadsAllTheThings/.git \
 && test -d "/opt/PayloadsAllTheThings/File Inclusion" \
 && test -d "/opt/PayloadsAllTheThings/Directory Traversal" \
 && test -d "/opt/PayloadsAllTheThings/Server Side Template Injection" \
 && test -d "/opt/PayloadsAllTheThings/SQL Injection" \
 && test -d "/opt/PayloadsAllTheThings/XSS Injection" \
 || (echo "ERROR: PayloadsAllTheThings did not check out correctly" && exit 1)

# A stable, space-free path for command templates. The upstream directory names
# contain spaces ("File Inclusion"), which is a quoting hazard in every generated
# command line; these symlinks give the knowledge YAML something safe to name.
#
# MEASURED contents (pinned commit): 142 .md and 67 .txt. The .txt files under
# each topic's Intruders/ directory are the raw lists a `-w` flag can consume
# (File Inclusion 14, SQL Injection 15, Directory Traversal 4); the .md files are
# reference prose and are NOT wordlists. Server Side Template Injection has ZERO
# .txt — it is documentation only, so `ssti` below is a reading path, not a
# fuzzing input. Pointing `-w` at it would feed markdown to ffuf.
RUN mkdir -p /app/payloads \
 && ln -sf "/opt/PayloadsAllTheThings/File Inclusion"                  /app/payloads/lfi \
 && ln -sf "/opt/PayloadsAllTheThings/Directory Traversal"             /app/payloads/traversal \
 && ln -sf "/opt/PayloadsAllTheThings/Server Side Template Injection"  /app/payloads/ssti \
 && ln -sf "/opt/PayloadsAllTheThings/SQL Injection"                   /app/payloads/sqli \
 && ln -sf "/opt/PayloadsAllTheThings/XSS Injection"                   /app/payloads/xss \
 && ln -sf /opt/PayloadsAllTheThings                                   /app/payloads/all \
 # The raw-list directories, named separately so a template can reach a real
 # wordlist without the caller having to know the upstream layout. NOTE the
 # upstream inconsistency, which broke this build once: File Inclusion uses
 # "Intruders" (plural), SQL Injection and Directory Traversal use "Intruder"
 # (singular). The test below is what caught it -- keep it.
 && ln -sf "/opt/PayloadsAllTheThings/File Inclusion/Intruders"        /app/payloads/lfi-lists \
 && ln -sf "/opt/PayloadsAllTheThings/SQL Injection/Intruder"          /app/payloads/sqli-lists \
 && ln -sf "/opt/PayloadsAllTheThings/Directory Traversal/Intruder"    /app/payloads/traversal-lists \
 && test -n "$(find -L /app/payloads/lfi-lists -name '*.txt' 2>/dev/null | head -1)" \
 && test -n "$(find -L /app/payloads/sqli-lists -name '*.txt' 2>/dev/null | head -1)" \
 || (echo "ERROR: payload list directories contain no .txt wordlists" && exit 1)

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
