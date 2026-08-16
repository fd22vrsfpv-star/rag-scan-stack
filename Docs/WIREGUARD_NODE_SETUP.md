# WireGuard Node Setup Guide

This guide covers setting up WireGuard on remote nodes for the RAG Scan Stack.

## Installation Times

**Fresh Installation**: 3-5 minutes
- Package installation: ~3 minutes (includes apt update, WireGuard tools, dante-server)
- Configuration: ~30 seconds
- Interface startup: ~30 seconds  
- SOCKS proxy setup: ~30 seconds
- Connectivity testing: ~30 seconds

**Pre-installed Nodes**: 30-60 seconds
- Configuration: ~30 seconds (skips package installation)
- Interface startup and testing: ~30 seconds

## Pre-Installation Script (Recommended)

To avoid the 3-5 minute installation delay, run this on your remote nodes before adding them to the RAG Scan Stack:

```bash
# Copy the setup script to your remote node
scp scripts/wireguard-node-setup.sh root@your-node:/tmp/

# Run the installation on the remote node
ssh root@your-node "bash /tmp/wireguard-node-setup.sh"
```

This script:
- ✅ Detects the OS (Ubuntu/Debian/CentOS/RHEL/Fedora/Arch)
- ✅ Installs WireGuard tools and dependencies
- ✅ Installs the dante-server SOCKS5 proxy from the distro's package manager
- ✅ Records the resolved service/config names in `/etc/default/wg-rag-socks`
      (Debian ships `danted` + `/etc/danted.conf`, EPEL ships `sockd` +
      `/etc/sockd.conf`) and holds the service down until wg0 has an address
- ✅ Sets up helper commands
- ✅ Enables IP forwarding

## Supported Operating Systems

- ✅ **Ubuntu/Debian** - `apt-get install wireguard-tools`
- ✅ **CentOS/RHEL/Rocky/AlmaLinux** - `dnf/yum install wireguard-tools` (via EPEL)
- ✅ **Fedora** - `dnf install wireguard-tools`
- ✅ **Arch Linux** - `pacman -S wireguard-tools`

## Manual Installation

If you prefer manual installation:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y wireguard-tools iproute2 curl netcat-openbsd

# CentOS/RHEL (enable EPEL first)
sudo dnf install -y epel-release
sudo dnf install -y wireguard-tools iproute curl netcat

# Fedora
sudo dnf install -y wireguard-tools iproute curl netcat

# Arch Linux
sudo pacman -Sy wireguard-tools iproute2 curl netcat

# Install the dante-server SOCKS proxy (Debian/Ubuntu; EPEL ships it as sockd)
sudo apt-get install -y dante-server
```

> **Why dante and not microsocks.** microsocks was previously fetched from
> `github.com/rofl0r/microsocks/releases/download/v1.0.3/microsocks-linux-x86_64`,
> which 404s — that project ships source-only releases. `curl -L -o` without `-f`
> exits 0 on a 404, so the 9-byte "Not Found" body was written to
> `/usr/local/bin/microsocks` and marked executable. dante-server is packaged,
> systemd-managed, logs to syslog, and enforces access control — microsocks
> accepted anyone who could reach its bind address, i.e. an open SOCKS relay on
> an internet-facing node.

`danted` binds its `internal` address at startup, so **wg0 must be up and
carrying its address before the proxy is started**. Bring up WireGuard first,
then write `/etc/danted.conf` and start the service:

```bash
sudo wg-quick up wg0

WG_IP="$(ip -4 -o addr show wg0 | awk '{print $4}' | cut -d/ -f1)"
EXT_IF="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"

sudo tee /etc/danted.conf >/dev/null <<DANTED
logoutput: syslog
internal: $WG_IP port = 1080
external: $EXT_IF
socksmethod: none
clientmethod: none
user.privileged: root
user.unprivileged: nobody

client pass {
    from: 10.66.0.0/24 to: 0.0.0.0/0
    log: connect disconnect error
}
socks pass {
    from: 10.66.0.0/24 to: 0.0.0.0/0
    log: connect disconnect error
}
DANTED

sudo systemctl enable --now danted
```

The `client pass` / `socks pass` rules restrict the proxy to the WireGuard
subnet. Do not widen them to `0.0.0.0/0` on the `from:` side — that turns the
node into an open relay.

## Helper Commands (After Pre-Installation)

The pre-installation script creates a helper command:

```bash
# Start WireGuard and SOCKS proxy
wg-rag-helper start

# Stop services
wg-rag-helper stop

# Check status
wg-rag-helper status

# Restart services
wg-rag-helper restart
```

## Troubleshooting Stuck Installations

If a WireGuard peer gets stuck in "pending" status:

### 1. Reset the Installation
```bash
# Reset specific peer
python3 scripts/reset-wireguard-installation.py reset <peer-id>

# Reset all pending installations
python3 scripts/reset-wireguard-installation.py reset-all-pending

# List all peers and their status
python3 scripts/reset-wireguard-installation.py list
```

### 2. Check Node Connectivity
```bash
# Test SSH access to the node
ssh root@your-node "echo 'SSH working'"

# Check if WireGuard is already installed
ssh root@your-node "which wg && which wg-quick"

# Check for existing WireGuard interfaces
ssh root@your-node "ip link show type wireguard"
```

### 3. Manual Diagnosis
```bash
# Check installation logs on the node
ssh root@your-node "tail -100 /var/log/syslog | grep -i wireguard"

# Check for package manager locks (Ubuntu/Debian)
ssh root@your-node "lsof /var/lib/dpkg/lock*"

# Check the SOCKS proxy installed and why it is not running
ssh root@your-node "command -v danted || command -v sockd || ls -l /usr/sbin/danted"
ssh root@your-node "systemctl status danted --no-pager; journalctl -u danted -n 30 --no-pager"

# Confirm it is actually listening on the WireGuard address (not 0.0.0.0)
ssh root@your-node "ss -ln | grep :1080"
```

## Installation Process Details

The auto-installation process follows these steps:

1. **Package Check** (10s timeout)
   - Checks if WireGuard and dante-server are already installed
   - Skips package installation if already present

2. **Package Installation** (180s timeout)
   - Updates package lists
   - Installs WireGuard tools and dependencies
   - Installs dante-server from the distro's package manager

3. **Configuration Upload** (30s timeout)
   - Uploads WireGuard configuration to `/etc/wireguard/wg0.conf`
   - Sets proper permissions (600)

4. **Interface Startup** (30s timeout)
   - Stops any existing WireGuard interface
   - Starts `wg0` interface with `wg-quick up wg0`
   - Verifies interface is running

5. **SOCKS Proxy Setup** (30s timeout)
   - Writes `/etc/danted.conf` bound to the assigned WireGuard IP, with the
     external interface derived from the default route
   - Restricts `client pass` / `socks pass` to `10.66.0.0/24`
   - `systemctl restart danted` (restart, not start, so a stale instance bound
     to a previous IP is replaced)
   - Verifies the proxy is listening on `<wg_ip>:1080`

6. **Connectivity Testing** (30s timeout)
   - Tests ping to WireGuard server (10.66.0.1)
   - Tests SOCKS proxy connectivity
   - Marks installation as successful

## Network Configuration

**WireGuard Subnet**: `10.66.0.0/24`
**Server IP**: `10.66.0.1` (RAG Scan Stack)
**Client IPs**: `10.66.0.2` - `10.66.0.254` (Remote nodes)
**SOCKS Proxy Port**: `1080` (on each node's WireGuard IP)

## Security Notes

- WireGuard configurations use strong cryptography (Curve25519, ChaCha20, Poly1305)
- Private keys are generated securely and never logged
- SOCKS proxy only binds to the WireGuard interface IP
- All traffic is encrypted end-to-end through the WireGuard tunnel

## Performance Tuning

For high-throughput scanning, consider:

```bash
# Increase network buffer sizes
echo 'net.core.rmem_max = 268435456' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 268435456' >> /etc/sysctl.conf

# Optimize WireGuard keepalive (for NAT traversal)
# This is set automatically in the client config to 25 seconds
```

## Verification

After installation, verify the setup:

```bash
# Check WireGuard status
wg show

# Test SOCKS proxy
curl --socks5 10.66.0.X:1080 http://httpbin.org/ip

# Check tunnel connectivity  
ping 10.66.0.1
```

Where `X` is your node's assigned IP in the 10.66.0.0/24 subnet.