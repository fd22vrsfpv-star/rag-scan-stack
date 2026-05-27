# Auto-Recovery and SSH Protection Guide

This guide covers the enhanced scripts with auto-recovery mechanisms to prevent SSH lockouts during provisioning.

## 🛡️ **Safety Scripts Overview**

| Script | Purpose | Recovery Time | Safety Level |
|--------|---------|---------------|-------------|
| `wireguard-node-setup-safe.sh` | WireGuard only + safety | 5 minutes | High |
| `provision-standard-node-safe.sh` | Full provisioning + safety | 3-10 minutes | Maximum |

## 🔧 **Auto-Recovery Mechanisms**

### **1. Pre-Installation Safeguards**
```bash
# Before making ANY changes:
✅ Backup SSH configuration
✅ Ensure SSH is explicitly allowed in firewall
✅ Install scheduling tools (at, cron)
✅ Create emergency restoration scripts
✅ Schedule failsafe recovery (10 minutes)
```

### **2. Background Auto-Recovery**
```bash
# Runs in background during installation:
✅ Monitors SSH service every 5 minutes
✅ Auto-restores SSH if blocked
✅ Fixes firewall rules if needed
✅ Reschedules itself until completion
```

### **3. Emergency Restoration**
```bash
# Immediate SSH restoration:
✅ emergency-ssh-now - Instant SSH restoration
✅ rag-helper ssh-emergency - User-friendly version
✅ Disables ALL firewalls temporarily
✅ Restarts SSH with safe configuration
```

## 📊 **Safety Features Comparison**

### **Original Scripts** (risky)
- ❌ No SSH protection
- ❌ No auto-recovery
- ❌ Can cause permanent lockouts
- ❌ No monitoring

### **Safe Scripts** (protected)
- ✅ Multiple safety nets
- ✅ Auto-recovery every 5 minutes
- ✅ Emergency restoration commands
- ✅ Comprehensive logging
- ✅ Firewall configuration validation
- ✅ SSH service monitoring

## 🚀 **Usage Examples**

### **Safe WireGuard Installation**
```bash
# Copy and run safe WireGuard script
scp scripts/wireguard-node-setup-safe.sh root@NODE_IP:/tmp/
ssh root@NODE_IP "bash /tmp/wireguard-node-setup-safe.sh"

# Even if SSH breaks, it will auto-recover in 5 minutes!
```

### **Safe Full Provisioning**
```bash
# Copy and run safe provisioning script
scp scripts/provision-standard-node-safe.sh root@NODE_IP:/tmp/
ssh root@NODE_IP "bash /tmp/provision-standard-node-safe.sh"

# Multiple safety nets protect against lockouts
```

### **Emergency SSH Recovery** (if needed)
```bash
# If you lose SSH access, use console to run:
/usr/local/bin/emergency-ssh-now

# Or via helper:
rag-helper ssh-emergency
```

## 🔍 **Monitoring and Diagnostics**

### **Safety Check Commands**
```bash
# Check all safety systems
rag-helper safety-check

# Check specific components
rag-helper wg-status          # WireGuard status
systemctl status ssh          # SSH service
ufw status                    # Firewall status
```

### **Log Files**
```bash
# Installation logs
/tmp/wireguard-install.log     # WireGuard installation
/tmp/provision.log             # Full provisioning
/tmp/auto-recovery.log         # Auto-recovery actions
/tmp/ssh-recovery.log          # SSH recovery actions
```

### **Safety Verification**
```bash
# Verify SSH is accessible
ss -tlnp | grep :22

# Verify firewall rules
ufw status | grep ssh

# Check auto-recovery status
tail /tmp/auto-recovery.log
```

## 🕐 **Recovery Timelines**

### **Auto-Recovery Schedule**
- **Immediate**: Background monitoring starts
- **5 minutes**: First auto-recovery check
- **10 minutes**: Emergency failsafe (scheduled)
- **15 minutes**: Additional safety check (if needed)

### **Manual Recovery**
- **Instant**: `emergency-ssh-now` command
- **30 seconds**: `rag-helper ssh-emergency`
- **Console access**: Always available via cloud provider

## 🛠️ **Technical Details**

### **What Gets Protected**
```bash
# SSH service protection
✅ Service restart monitoring
✅ Port 22 accessibility checks
✅ Configuration validation

# Firewall protection  
✅ UFW rule verification
✅ SSH rule enforcement
✅ Safe configuration sequence

# Auto-recovery mechanisms
✅ Background process monitoring
✅ Scheduled safety checks
✅ Emergency restoration scripts
```

### **How It Works**
1. **Pre-flight checks** ensure SSH is working
2. **Background monitor** watches SSH during installation
3. **Scheduled recovery** runs every 5 minutes
4. **Emergency scripts** provide instant recovery
5. **Completion marker** stops monitoring when done

### **Failure Scenarios Handled**
- ✅ UFW blocks SSH during activation
- ✅ SSH service crashes during package installation
- ✅ Network configuration changes break SSH
- ✅ Firewall rules accidentally remove SSH access
- ✅ Package installation triggers auto-firewall rules

## 📋 **Best Practices**

### **Before Running Scripts**
1. **Test SSH access** to confirm it works
2. **Have console access** ready (cloud provider panel)
3. **Note the node IP** and access method
4. **Set realistic expectations** (5-15 minute installation)

### **During Installation**
1. **Don't panic** if SSH temporarily disconnects
2. **Wait 5 minutes** for auto-recovery
3. **Check logs** via console if needed
4. **Use emergency commands** if necessary

### **After Installation**
1. **Test SSH access** immediately
2. **Run safety check**: `rag-helper safety-check`
3. **Verify WireGuard**: `rag-helper wg-status`
4. **Clean up logs** if desired

## ⚡ **Performance Impact**

### **Resource Usage**
- **CPU**: Minimal (background checks every 5 minutes)
- **Memory**: <10MB for monitoring processes
- **Disk**: <1MB for logs and scripts
- **Network**: No additional network traffic

### **Installation Time**
- **Safe WireGuard**: +30 seconds overhead
- **Safe Provisioning**: +2 minutes overhead
- **Recovery time**: 0-5 minutes if needed

## 🎯 **Migration Guide**

### **From Original Scripts**
```bash
# Replace old script calls with safe versions
# Old:
scp scripts/wireguard-node-setup.sh root@NODE:/tmp/

# New:  
scp scripts/wireguard-node-setup-safe.sh root@NODE:/tmp/
```

### **Existing Installations**
```bash
# Add safety features to existing nodes
scp scripts/wireguard-node-setup-safe.sh root@NODE:/tmp/
ssh root@NODE "
  # Install just the safety components
  bash /tmp/wireguard-node-setup-safe.sh --safety-only
"
```

## 🔥 **Emergency Procedures**

### **If SSH Locks You Out**
1. **Wait 5 minutes** for auto-recovery
2. **Use cloud console** to access the node
3. **Run emergency restoration**: `/usr/local/bin/emergency-ssh-now`
4. **Check logs**: `tail /tmp/auto-recovery.log`

### **If Auto-Recovery Fails**
1. **Access via cloud console**
2. **Disable firewall**: `ufw --force disable`
3. **Restart SSH**: `systemctl restart ssh`
4. **Re-enable safely**: `ufw allow ssh && ufw enable`

This comprehensive auto-recovery system ensures that SSH lockouts become a thing of the past! 🛡️