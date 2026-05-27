# Deployment & Sync Scripts

This directory contains scripts for deploying and syncing your RAG Scan Stack between development and production machines.

## Quick Start

### 1. Initial Configuration (One-Time Setup)

Configure your production machine details:

```bash
./scripts/configure-sync.sh
```

This will prompt you for:
- Production machine username
- Production machine IP/hostname
- Production machine path (default: `/opt/rag-scan-stack`)

It will test the SSH connection and update all sync scripts automatically.

### 2. Choose Your Workflow

#### Option A: Manual Sync (Most Control)

```bash
# Just sync files
./scripts/sync-to-prod.sh

# Sync and restart services
./scripts/sync-to-prod.sh --restart

# Sync, rebuild, and restart
./scripts/sync-to-prod.sh --restart --build
```

#### Option B: Quick Deploy (One Command)

```bash
# Deploy everything (sync + build + restart)
./scripts/quick-deploy.sh

# Deploy only a specific service
./scripts/quick-deploy.sh autogen-agents
```

#### Option C: Auto-Sync (Watch Mode)

```bash
# Watch for changes and auto-sync
./scripts/watch-and-sync.sh

# Watch and auto-restart services
./scripts/watch-and-sync.sh --restart

# Run in background
./scripts/watch-and-sync.sh &

# Stop background process
pkill -f watch-and-sync
```

---

## Script Reference

### `configure-sync.sh`

**Purpose**: One-time configuration of production machine details

**Usage**:
```bash
./scripts/configure-sync.sh
```

**What it does**:
- Prompts for production machine details
- Tests SSH connection
- Updates all sync scripts with your configuration
- Creates backups of original scripts

---

### `sync-to-prod.sh`

**Purpose**: Sync code from development to production

**Usage**:
```bash
./scripts/sync-to-prod.sh [OPTIONS]
```

**Options**:
- `--restart` - Restart Docker services after sync
- `--build` - Rebuild Docker images before restart
- `--help` - Show help message

**Examples**:
```bash
# Just sync files (fastest)
./scripts/sync-to-prod.sh

# Sync and restart services
./scripts/sync-to-prod.sh --restart

# Full deployment: sync, rebuild, restart
./scripts/sync-to-prod.sh --restart --build
```

**What gets synced**:
- All Python code
- Configuration files
- Dockerfiles
- Database init scripts
- Documentation

**What's excluded**:
- `.git/` - Git repository data
- `ollama-data/` - Large model files
- `*_reports/`, `*_logs/` - Output directories
- `*.pyc`, `__pycache__/` - Python cache
- `.env` - Environment secrets

---

### `watch-and-sync.sh`

**Purpose**: Automatically sync files when changes are detected

**Usage**:
```bash
./scripts/watch-and-sync.sh [OPTIONS]
```

**Options**:
- `--restart` - Auto-restart services after each sync
- `--help` - Show help message

**Examples**:
```bash
# Watch and sync only
./scripts/watch-and-sync.sh

# Watch, sync, and auto-restart
./scripts/watch-and-sync.sh --restart

# Run in background
nohup ./scripts/watch-and-sync.sh > /tmp/watch-sync.log 2>&1 &

# Stop watching
pkill -f watch-and-sync
```

**Features**:
- Monitors file changes in real-time
- Debounces rapid changes (waits 3 seconds)
- Ignores temporary files and cache
- Shows which files changed

**Requirements**:
- `inotify-tools` (auto-installed if missing)

---

### `quick-deploy.sh`

**Purpose**: Full deployment in one command (sync + build + restart)

**Usage**:
```bash
./scripts/quick-deploy.sh [service-name]
```

**Examples**:
```bash
# Deploy everything
./scripts/quick-deploy.sh

# Deploy only autogen-agents service
./scripts/quick-deploy.sh autogen-agents

# Deploy only web-scanner
./scripts/quick-deploy.sh web-scanner
```

**What it does**:
1. Syncs all files to production
2. Builds Docker images
3. Restarts services
4. Shows service status

---

### `deploy.sh`

**Purpose**: Initial deployment setup on a new machine

**Usage**:
```bash
./scripts/deploy.sh
```

**What it does**:
- Checks prerequisites (Docker, GPU, etc.)
- Creates Docker network
- Creates required directories
- Sets up configuration files
- Optionally starts services

**When to use**:
- First-time deployment on a new machine
- Setting up a fresh environment

---

## Typical Workflows

### Development Workflow

**In IntelliJ:**
1. Make code changes
2. Save files (Ctrl+S)
3. From terminal, sync to production

**Terminal:**
```bash
# Option 1: Manual sync when ready
./scripts/sync-to-prod.sh --restart

# Option 2: Auto-sync as you work
./scripts/watch-and-sync.sh
```

### Quick Fix Deployment

```bash
# Edit files in IntelliJ
# Then deploy specific service:
./scripts/quick-deploy.sh web-scanner
```

### Full Deployment

```bash
# Complete deployment with rebuild
./scripts/sync-to-prod.sh --restart --build

# Or use quick-deploy
./scripts/quick-deploy.sh
```

### Testing Before Commit

```bash
# Sync to production for testing
./scripts/sync-to-prod.sh --restart

# Test on production
ssh user@prod 'cd /opt/rag-scan-stack && docker compose logs -f service-name'

# If works well, commit and push to git
git add .
git commit -m "Feature: description"
git push origin master
```

---

## SSH Setup

For passwordless sync, set up SSH key authentication:

### On Development Machine:

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy to production machine
ssh-copy-id user@production-ip
```

### Test Connection:

```bash
# Should connect without password
ssh user@production-ip

# Should work without password
./scripts/sync-to-prod.sh
```

---

## Troubleshooting

### "Cannot connect to production machine"

**Problem**: SSH connection fails

**Solution**:
```bash
# Test SSH manually
ssh user@production-ip

# If fails, check:
# 1. Is SSH server running on production?
ssh user@production-ip 'sudo service ssh status'

# 2. Can you ping the machine?
ping production-ip

# 3. Is firewall blocking SSH?
ssh user@production-ip 'sudo ufw status'
```

### "Sync is slow"

**Problem**: Syncing takes a long time

**Solution**:
```bash
# Check what's being synced
rsync -avn --stats source/ dest/

# Ensure large files are excluded
# Check .gitignore patterns in sync-to-prod.sh
```

### "Services won't restart"

**Problem**: Services fail after sync

**Solution**:
```bash
# Check service logs on production
ssh user@prod 'cd /opt/rag-scan-stack && docker compose logs -f'

# Check if files were synced correctly
ssh user@prod 'ls -la /opt/rag-scan-stack'

# Try manual restart
ssh user@prod 'cd /opt/rag-scan-stack && docker compose down && docker compose up -d --build'
```

### "Watch script not working"

**Problem**: Changes aren't being detected

**Solution**:
```bash
# Install inotify-tools
sudo apt install inotify-tools

# Test inotify manually
inotifywait -m /utils/agents

# Check system limits
cat /proc/sys/fs/inotify/max_user_watches

# Increase if needed
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Best Practices

### 1. Use Git for Important Changes

Sync scripts are great for rapid testing, but use git for production deployments:

```bash
# Development cycle:
./scripts/sync-to-prod.sh --restart  # Test changes

# When tested and working:
git add .
git commit -m "Description"
git push origin master

# On production:
git pull origin master
docker compose up -d --build
```

### 2. Sync Before Rebuilding

```bash
# More efficient: sync first, then rebuild
./scripts/sync-to-prod.sh
ssh user@prod 'cd /opt/rag-scan-stack && docker compose build changed-service'
ssh user@prod 'cd /opt/rag-scan-stack && docker compose up -d --no-deps changed-service'
```

### 3. Test Locally First

```bash
# Test on dev machine before syncing
docker compose up -d --build service-name
docker compose logs -f service-name

# If works, then sync
./scripts/sync-to-prod.sh --restart
```

### 4. Use Watch Mode During Active Development

```bash
# Start watch mode in a separate terminal
./scripts/watch-and-sync.sh

# Now edit in IntelliJ - changes sync automatically
# Stop with Ctrl+C when done
```

---

## Environment Variables

You can override default settings with environment variables:

```bash
# Override target details
TARGET_USER=admin TARGET_HOST=10.0.0.50 ./scripts/sync-to-prod.sh

# Use different path
TARGET_PATH=/home/user/rag-stack ./scripts/sync-to-prod.sh
```

---

## Integration with IntelliJ

### Create Run Configurations

**Run → Edit Configurations → Shell Script**

**Sync to Production:**
- Name: "Sync to Prod"
- Script: `/utils/agents/scripts/sync-to-prod.sh`
- Arguments: `--restart`

**Quick Deploy:**
- Name: "Quick Deploy"
- Script: `/utils/agents/scripts/quick-deploy.sh`

**Start Watch Mode:**
- Name: "Watch and Sync"
- Script: `/utils/agents/scripts/watch-and-sync.sh`

Now you can deploy with one click in IntelliJ!

---

## Performance Tips

### 1. Exclude Unnecessary Files

Edit the `--exclude` patterns in `sync-to-prod.sh` to skip files you don't need.

### 2. Use Compression for Large Files

```bash
# Enable compression (slower but less bandwidth)
rsync -avz --compress-level=9 ...
```

### 3. Sync Only Changed Files

rsync automatically only transfers changed files - no need to sync everything each time.

### 4. Use Local Network

Ensure both machines are on the same local network for fastest transfer speeds.

---

## Security Notes

### SSH Key Authentication

Always use SSH keys instead of passwords for automated scripts.

### Don't Sync Secrets

The scripts exclude `.env` files by default. Never sync:
- `.env` files
- SSH keys
- Database credentials
- API keys

### Review Excludes

Check the `--exclude` patterns in scripts to ensure sensitive files aren't synced.

---

## Additional Resources

- **Main Deployment Guide**: See `/utils/agents/DEPLOYMENT.md`
- **Quick Start Guide**: See `/utils/agents/QUICKSTART-DEPLOYMENT.md`
- **Docker Compose**: See `/utils/agents/docker-compose.yml`

---

**Last Updated**: 2025-11-04
