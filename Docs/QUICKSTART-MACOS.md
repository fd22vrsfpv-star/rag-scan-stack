# RAG Scan Stack - macOS Quickstart Guide

This guide walks you through setting up the RAG Scan Stack on macOS using Docker.

## Prerequisites

- macOS 12 (Monterey) or later
- At least 16GB RAM (32GB recommended)
- 50GB+ free disk space
- Admin access to your machine

---

## Step 1: Install Homebrew

If you don't have Homebrew installed, open **Terminal** and run:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow the prompts. After installation, run the commands shown to add Homebrew to your PATH (usually adding to `~/.zprofile`).

### Verify Homebrew:

```bash
brew --version
```

---

## Step 2: Install Docker

You have two options: **Docker Desktop** (easier) or **Colima** (lighter, free).

### Option A: Docker Desktop (Recommended for beginners)

1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop/

2. Open the `.dmg` file and drag Docker to Applications

3. Launch Docker from Applications

4. Complete the setup wizard and sign in (or skip)

5. Go to **Settings** (gear icon) → **Resources**:
   - **CPUs**: 4+ cores
   - **Memory**: 8GB minimum (12GB+ recommended)
   - **Swap**: 2GB
   - **Disk image size**: 60GB+

6. Configure **File Sharing** (Settings → Resources → File Sharing):
   - Ensure your home directory is listed (e.g., `/Users/yourusername`)
   - If you clone the repo elsewhere, add that path
   - The stack mounts local directories for logs, reports, and data

7. Click **Apply & Restart**

### Option B: Colima (Lightweight alternative)

Colima is a free, open-source Docker runtime for macOS:

```bash
# Install Colima and Docker CLI
brew install colima docker docker-compose

# Start Colima with resources and home directory mounted
colima start --cpu 4 --memory 8 --disk 60 --mount $HOME:w

# Verify it's running
colima status
```

To configure Colima resources later:

```bash
# Stop, reconfigure, and restart
colima stop
colima start --cpu 4 --memory 12 --disk 80 --mount $HOME:w
```

> **Note:** The `--mount $HOME:w` flag shares your home directory with write access, required for the stack's volume mounts (logs, reports, data).

### Verify Docker is working:

```bash
docker --version
docker compose version
docker run hello-world
```

---

## Step 3: Install Git (if needed)

macOS includes Git, but you can install the latest version:

```bash
# Check if Git is installed
git --version

# If not installed or you want the latest:
brew install git
```

---

## Step 4: Clone the Repository

```bash
# Navigate to your preferred directory
cd ~

# Clone the repository
git clone https://github.com/raptordoug/rag_scan_stack.git

# Enter the directory
cd rag_scan_stack
```

---

## Step 5: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Generate secure credentials (recommended)
./generate-credentials.sh

# Or manually edit .env with your preferred settings
nano .env
# (or use: open -e .env  to open in TextEdit)
```

Key settings to review in `.env`:

```bash
# API Key for services
API_KEY=your-secure-api-key

# Database credentials
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-secure-password

# Ollama model (adjust based on your RAM)
OLLAMA_MODEL=qwen2.5:14b   # Use qwen2.5:7b for less RAM
```

---

## Step 6: Install and Run Ollama Natively

On macOS, Ollama runs better natively (outside Docker) with direct access to Apple Silicon GPU acceleration.

```bash
# Install Ollama
brew install ollama

# Start Ollama service (runs in background)
brew services start ollama

# Or run manually in a terminal
ollama serve

# Pull the required models
ollama pull qwen2.5:14b       # Main LLM (use qwen2.5:7b for less RAM)
ollama pull nomic-embed-text  # Embedding model
```

### Verify Ollama is running:

```bash
ollama list
curl http://localhost:11434/api/tags
```

> **Note:** The Docker containers will connect to your native Ollama via `host.docker.internal:11434`.

---

## Step 7: Create Docker Network

The stack uses an external Docker network. Create it first:

```bash
docker network create agents_net
```

---

## Step 8: Start the Stack

```bash
# Use the macOS-specific compose file
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d

# Watch the logs to see startup progress
docker compose logs -f
```

Press `Ctrl+C` to exit logs (containers keep running).

### Verify services are running:

```bash
docker compose ps
```

You should see all containers with "Up" status (except ollama and ollama-init, which are disabled on macOS).

---

## Step 9: Access the Services

Open your browser and navigate to:

| Service | URL | Description |
|---------|-----|-------------|
| RAG API | http://localhost:8000 | Main API |
| Open WebUI | http://localhost:3000 | Chat interface |
| Nmap Scanner | http://localhost:8012 | Port scanning API |
| Web Scanner | http://localhost:8010 | Web vulnerability scanning |
| Nuclei | http://localhost:8011 | CVE scanning |
| Scan Recommender | http://localhost:8013 | Tool recommendations |

### Test the API:

```bash
curl http://localhost:8000/health
```

---

## Step 10: Run Your First Scan

### Option A: Using curl

```bash
# Start a full port scan (replace with your target IP)
curl -X POST "http://localhost:8012/jobs/full-scan" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.100"]}'

# Check scan status (use the job_id from the response)
curl "http://localhost:8012/jobs/YOUR_JOB_ID"
```

### Option B: Using the Autogen Agents

```bash
# Start an interactive pentest session
curl -X POST "http://localhost:8015/sessions/start" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "scope": "full"}'
```

---

## Common Issues & Solutions

### "Cannot connect to the Docker daemon"

**If Docker isn't running:**

```bash
# Docker Desktop - launch from Applications
open -a Docker

# Colima
colima start
```

**If Docker Desktop is running but you still get this error:**

The Docker socket may not be linked. Check and fix it:

```bash
# Check if the socket exists
ls -la ~/.docker/run/docker.sock

# If it exists, link it to the standard location
sudo ln -sf ~/.docker/run/docker.sock /var/run/docker.sock
```

Or in Docker Desktop: **Settings** → **Advanced** → Enable "Allow the default Docker socket to be used"

**If using Colima**, set the Docker host:

```bash
# Add to ~/.zshrc
echo 'export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"' >> ~/.zshrc
source ~/.zshrc
```

> **Note:** Docker Desktop 4.15+ is recommended. Older versions (4.6 and earlier) have socket issues on newer macOS. Update via `brew install --cask docker` or download from https://www.docker.com/products/docker-desktop/

### Out of memory errors

Increase Docker memory allocation:

**Docker Desktop:** Settings → Resources → Memory → Increase to 12GB+

**Colima:**
```bash
colima stop
colima start --cpu 4 --memory 12
```

Or use a smaller Ollama model in `.env`:
```bash
OLLAMA_MODEL=qwen2.5:7b
```

### Port already in use

```bash
# Find what's using the port
lsof -i :8000

# Kill the process (replace PID)
kill -9 <PID>

# Or stop all containers and restart
docker compose down
docker compose up -d
```

### Port 5000 conflict (AirPlay Receiver)

macOS Monterey and later use port 5000 for AirPlay Receiver. The stack's kali-listener has been moved to ports 9080-9180 to avoid this conflict.

If you still see port 5000 issues with other services, you can disable AirPlay Receiver:

1. Open **System Settings** (or System Preferences)
2. Go to **General** → **AirDrop & Handoff**
3. Disable **AirPlay Receiver**

Or leave it enabled since the stack no longer uses port 5000.

### Containers keep restarting

Check logs for the failing container:

```bash
docker compose logs nmap_scanner
```

Common causes:
- Insufficient memory (increase Docker resources)
- Port conflicts (check with `lsof`)
- Missing environment variables (check `.env`)

### Apple Silicon (M1/M2/M3) specific issues

Most images support ARM64, but if you encounter issues:

```bash
# Force x86 emulation for a specific service (slower)
# Add to docker-compose.yml under the service:
platform: linux/amd64
```

### DNS resolution issues

If containers can't resolve hostnames:

```bash
# Restart Docker
# Docker Desktop: Quit and relaunch
# Colima:
colima restart
```

---

## Useful Commands

```bash
# View all container logs
docker compose logs -f

# View specific service logs
docker compose logs -f nmap_scanner

# Restart a specific service
docker compose restart nmap_scanner

# Stop all services
docker compose down

# Stop and remove all data (fresh start)
docker compose down -v

# Update to latest version
git pull
docker compose build --no-cache
docker compose up -d

# Check resource usage
docker stats
```

### Colima-specific commands

```bash
# Check Colima status
colima status

# SSH into the Colima VM
colima ssh

# Stop Colima (stops all containers)
colima stop

# Delete Colima VM (removes all data)
colima delete
```

---

## Setting Up a Test Target (Metasploitable2)

For testing, you can run vulnerable targets:

### Option 1: UTM or VirtualBox VM

1. Download Metasploitable2: https://sourceforge.net/projects/metasploitable/
2. For Apple Silicon Macs, use **UTM** (free): https://mac.getutm.app/
3. For Intel Macs, use **VirtualBox**: https://www.virtualbox.org/
4. Import the VM and set network to "Bridged"
5. Note the VM's IP address after boot (`ifconfig` in the VM)

### Option 2: Docker (Limited but quick)

```bash
# Run DVWA (Damn Vulnerable Web Application)
docker run -d -p 8080:80 vulnerables/web-dvwa

# Access at http://localhost:8080
# Default login: admin / password
```

### Option 3: VulnHub VMs

Download pre-built vulnerable VMs from https://www.vulnhub.com/

---

## Network Configuration for Scanning

### Find your local IP

```bash
# Get your Mac's IP address
ipconfig getifaddr en0
```

### Ensure target is reachable

```bash
ping 192.168.1.100
```

### Scanning VMs on the same network

1. Set VM network to "Bridged Adapter" or "Bridged" mode
2. The VM will get an IP on your local network
3. Find the VM's IP with `ifconfig` (inside the VM)

### Docker network for container-to-container scanning

```bash
# Containers on the same Docker network can reach each other by name
docker network ls
docker network inspect agents_net
```

---

## Performance Tips

1. **Use an SSD** - Docker performs much better on SSD storage

2. **Allocate enough memory** - 12GB+ recommended for running Ollama models

3. **Close unnecessary apps** - Free up RAM for Docker

4. **Use Colima on older Macs** - It's lighter than Docker Desktop

5. **Monitor with Activity Monitor** - Watch for memory pressure

6. **Consider cloud deployment** - For heavy scanning, deploy to a Linux server

---

## Next Steps

- Read the [API Documentation](API_ENDPOINTS.md)
- Explore the [Command Flow](COMMAND_FLOW.md)
- Check out [Deployment Options](DEPLOYMENT.md)

---

## Getting Help

- GitHub Issues: https://github.com/raptordoug/rag_scan_stack/issues
- Check logs: `docker compose logs -f`
- Service health: `curl http://localhost:8000/health`
