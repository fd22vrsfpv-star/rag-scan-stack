# Standard Node Provisioning Guide

This guide covers the standard provisioning process for RAG Scan Stack nodes to ensure consistent, fast deployments.

## 🚀 **One-Command Provisioning**

**Step 1: Copy provisioning script to your new node**
```bash
scp scripts/provision-standard-node.sh root@YOUR_NODE_IP:/tmp/
```

**Step 2: Run provisioning on the remote node**
```bash
ssh root@YOUR_NODE_IP "bash /tmp/provision-standard-node.sh"
```

**Step 3: Reboot (recommended)**
```bash
ssh root@YOUR_NODE_IP "reboot"
```

## ✅ **What Gets Installed**

### Core System
- ✅ **System updates** - Latest packages
- ✅ **Essential tools** - curl, wget, git, htop, tmux, vim, build tools
- ✅ **Docker** - Latest Docker CE with compose plugin
- ✅ **Security hardening** - SSH config, firewall (UFW/firewalld)

### Networking & Tunneling
- ✅ **WireGuard** - Full WireGuard tools and utilities
- ✅ **microsocks** - SOCKS5 proxy for tunnel routing
- ✅ **Network tools** - nmap, tcpdump, netcat, dnsutils
- ✅ **IP forwarding** - Kernel networking optimizations

### Development Tools
- ✅ **Go** - Latest stable Go compiler
- ✅ **Python 3** - Python with pip and dev tools
- ✅ **Node.js** - Latest LTS Node.js and npm

### RAG Scan Stack Integration
- ✅ **Systemd services** - microsocks service configuration
- ✅ **Helper commands** - `rag-helper` management utility
- ✅ **Security** - Firewall rules for SSH and WireGuard

## ⚡ **Performance Benefits**

| Setup Type | WireGuard Creation Time | Total Setup Time |
|------------|------------------------|------------------|
| **Fresh Ubuntu** | 3-5 minutes | ~15+ minutes |
| **Standard Provisioned** | 30-60 seconds | ~10 minutes once |

**ROI**: One-time 10-minute provisioning = 4+ minutes saved per WireGuard peer creation

## 🛠 **Helper Commands** (Available after provisioning)

```bash
# WireGuard management
rag-helper wg-start      # Start tunnel and SOCKS proxy
rag-helper wg-stop       # Stop tunnel services  
rag-helper wg-status     # Show tunnel status
rag-helper wg-restart    # Restart tunnel services

# System management
rag-helper info          # Show installed software versions
rag-helper update        # Update all system packages
```

## 🌐 **Supported Operating Systems**

- ✅ **Ubuntu** (18.04, 20.04, 22.04, 24.04)
- ✅ **Debian** (10, 11, 12)
- ✅ **CentOS** / **RHEL** (8, 9)
- ✅ **Rocky Linux** / **AlmaLinux** (8, 9)
- ✅ **Fedora** (38, 39, 40)
- ✅ **Arch Linux**

## 🔥 **Quick Deployment Examples**

### Digital Ocean Droplet
```bash
# Create droplet, then provision
doctl compute droplet create rag-node-01 \
  --image ubuntu-22-04-x64 \
  --size s-2vcpu-4gb \
  --region nyc1 \
  --ssh-keys YOUR_SSH_KEY_ID

# Get IP and provision
NODE_IP=$(doctl compute droplet get rag-node-01 --output json | jq -r '.[].networks.v4[] | select(.type=="public") | .ip_address')
scp scripts/provision-standard-node.sh root@$NODE_IP:/tmp/
ssh root@$NODE_IP "bash /tmp/provision-standard-node.sh && reboot"
```

### AWS EC2 Instance
```bash
# Launch instance, then provision
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx

# Get IP and provision (replace ubuntu@ if using different AMI)
NODE_IP=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].[PublicIpAddress]' --output text | head -1)
scp -i ~/.ssh/your-key.pem scripts/provision-standard-node.sh ubuntu@$NODE_IP:/tmp/
ssh -i ~/.ssh/your-key.pem ubuntu@$NODE_IP "sudo bash /tmp/provision-standard-node.sh && sudo reboot"
```

### Linode Instance
```bash
# Create and provision
linode-cli linodes create \
  --type g6-standard-2 \
  --region us-east \
  --image linode/ubuntu22.04 \
  --root_pass 'YOUR_SECURE_PASSWORD'

# Get IP and provision
NODE_IP=$(linode-cli linodes list --text --no-headers | awk '{print $7}' | head -1)
scp scripts/provision-standard-node.sh root@$NODE_IP:/tmp/
ssh root@$NODE_IP "bash /tmp/provision-standard-node.sh && reboot"
```

## 🔒 **Security Features**

### Automatic Hardening
- ✅ SSH password authentication disabled
- ✅ Empty password authentication disabled
- ✅ Firewall configured (SSH + WireGuard only)
- ✅ Protocol 2 SSH only

### Network Security
- ✅ IP forwarding properly configured
- ✅ WireGuard uses strong cryptography
- ✅ SOCKS proxy bound to WireGuard interface only
- ✅ Kernel network optimizations

## 📋 **Verification Checklist**

After provisioning, verify installation:

```bash
# Check core tools
ssh root@YOUR_NODE_IP "rag-helper info"

# Expected output should show:
# ✅ Docker version
# ✅ WireGuard tools  
# ✅ Go, Python, Node.js versions
# ✅ microsocks installed

# Test WireGuard readiness
ssh root@YOUR_NODE_IP "which wg && which wg-quick && which microsocks"
# Should return paths to all three binaries
```

## 🚀 **Integration with RAG Scan Stack**

After provisioning, nodes will:
1. **Connect instantly** - No package installation delay
2. **Start tunnels in 30-60 seconds** - All dependencies pre-installed  
3. **Auto-configure** - RAG Scan Stack handles configuration
4. **Self-heal** - systemd services restart on failure

## 📖 **Best Practices**

### For Production Deployments
1. **Always provision new nodes** before adding to RAG Scan Stack
2. **Reboot after provisioning** to ensure kernel modules load
3. **Test connectivity** before adding to tunnel pool
4. **Document node purposes** (scanning, C2, pivot points)

### For Development/Testing
1. **Use smaller instance sizes** during testing
2. **Snapshot provisioned nodes** for quick deployment
3. **Version tag** your infrastructure for reproducibility

### Security Considerations
1. **Rotate SSH keys** regularly
2. **Monitor node access** via logs
3. **Update regularly** with `rag-helper update`
4. **Firewall review** periodically

## ⚠️ **Troubleshooting**

### Common Issues
```bash
# Permission denied during provisioning
# Fix: Ensure running as root or with sudo

# Package installation fails
# Fix: Check internet connectivity and DNS

# Docker service fails to start
# Fix: Reboot after provisioning to load kernel modules

# WireGuard module not found
# Fix: Reboot or manually load: modprobe wireguard
```

### Verification Commands
```bash
# Test all components
ssh root@NODE_IP "
  docker ps && 
  wg version && 
  microsocks -V && 
  systemctl status docker
"
```

This standard provisioning approach ensures consistent, secure, and fast node deployments for the RAG Scan Stack.