# RAG Scan Stack - Windows Quickstart Guide

This guide walks you through setting up the RAG Scan Stack on Windows using WSL2 and Docker Desktop.

## Prerequisites

- Windows 10 (version 2004+) or Windows 11
- At least 16GB RAM (32GB recommended)
- 50GB+ free disk space
- Admin access to your machine

---

## Step 1: Install WSL2

Open **PowerShell as Administrator** and run:

```powershell
# Install WSL with Ubuntu (default)
wsl --install

# Restart your computer when prompted
```

After restart, Ubuntu will finish installing. Set up your Linux username and password when prompted.

### Verify WSL2 is running:

```powershell
wsl --list --verbose
```

You should see Ubuntu with VERSION 2.

### (Optional) Set WSL2 as default:

```powershell
wsl --set-default-version 2
```

---

## Step 2: Configure WSL2 Resources

Create or edit `%UserProfile%\.wslconfig` (e.g., `C:\Users\YourName\.wslconfig`):

```ini
[wsl2]
memory=8GB
processors=4
swap=2GB
localhostForwarding=true
```

Restart WSL for changes to take effect:

```powershell
wsl --shutdown
```

---

## Step 3: Install Docker Desktop

1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop/

2. Run the installer and ensure these options are checked:
   - **Use WSL 2 based engine**
   - **Add shortcut to desktop**

3. After installation, open Docker Desktop and go to:
   - **Settings** → **General** → Enable "Use the WSL 2 based engine"
   - **Settings** → **Resources** → **WSL Integration** → Enable integration with your Ubuntu distro

4. Apply and restart Docker Desktop

### Verify Docker is working:

Open Ubuntu (WSL) terminal and run:

```bash
docker --version
docker-compose --version
```

---

## Step 4: Clone the Repository

In your Ubuntu (WSL) terminal:

```bash
# Navigate to your home directory
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
```

Key settings to review in `.env`:

```bash
# API Key for services
API_KEY=your-secure-api-key

# Database credentials
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-secure-password

# Ollama model (adjust based on your RAM).
# Default: gemma4:31b -- matches docker-compose.yml's :- default so
# every service in the stack picks up the same model.  Switch to a
# smaller model (gemma4:9b or qwen3:4b) on machines with < 32 GB.
OLLAMA_MODEL=gemma4:31b
```

---

## Step 6: Start the Stack

```bash
# Pull and build all containers (first run takes 10-20 minutes)
docker-compose up -d

# Watch the logs to see startup progress
docker-compose logs -f
```

Press `Ctrl+C` to exit logs (containers keep running).

### Verify services are running:

```bash
docker-compose ps
```

You should see all containers with "Up" status.

---

## Step 7: Access the Services

From Windows, open your browser and navigate to:

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
# From WSL terminal
curl http://localhost:8000/health

# Or from Windows PowerShell
Invoke-RestMethod http://localhost:8000/health
```

---

## Step 8: Run Your First Scan

### Option A: Using curl (WSL terminal)

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

### Docker containers won't start

```bash
# Check if Docker is running
docker info

# If not, start Docker Desktop from Windows
# Then restart WSL
wsl --shutdown
```

### Out of memory errors

Edit `.wslconfig` to allocate more memory, or use a smaller Ollama
model.  The stack's default is `gemma4:31b` (~20 GB).  On 16 GB hosts:

```bash
# Edit .env and change to a smaller variant:
OLLAMA_MODEL=gemma4:9b        # ~6 GB, gemma family
# or
OLLAMA_MODEL=qwen3:4b         # ~3 GB, lighter still
```
Remember to also `ollama pull <model>` so the daemon has it.

### Port already in use

Check what's using the port:

```bash
# In WSL
sudo lsof -i :8000

# Or stop conflicting services
docker-compose down
```

### Cannot connect to services from Windows

Ensure `localhostForwarding=true` is set in `.wslconfig` and WSL was restarted.

### Slow performance

1. Store the repo in WSL filesystem (not `/mnt/c/`)
2. Increase WSL memory in `.wslconfig`
3. Ensure Docker Desktop has enough resources allocated

---

## Useful Commands

```bash
# View all container logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f nmap_scanner

# Restart a specific service
docker-compose restart nmap_scanner

# Stop all services
docker-compose down

# Stop and remove all data (fresh start)
docker-compose down -v

# Update to latest version
git pull
docker-compose build --no-cache
docker-compose up -d
```

---

## Setting Up a Test Target (Metasploitable2)

For testing, you can run Metasploitable2 as a vulnerable target:

### Option 1: VirtualBox VM

1. Download Metasploitable2: https://sourceforge.net/projects/metasploitable/
2. Import into VirtualBox
3. Set network to "Bridged Adapter"
4. Note the VM's IP address after boot

### Option 2: Docker (Limited)

```bash
# Run a vulnerable web app for testing
docker run -d -p 8080:80 vulnerables/web-dvwa
```

---

## Network Configuration for Scanning

To scan machines on your local network from WSL:

1. **Find your network interface** in WSL:
   ```bash
   ip addr show eth0
   ```

2. **Ensure your target is reachable**:
   ```bash
   ping 192.168.1.100
   ```

3. **If scanning VMs**, ensure they're on the same network (bridged mode).

---

## Next Steps

- Read the [API Documentation](API_ENDPOINTS.md)
- Explore the [Command Flow](COMMAND_FLOW.md)
- Check out [Deployment Options](DEPLOYMENT.md)

---

## Getting Help

- GitHub Issues: https://github.com/raptordoug/rag_scan_stack/issues
- Check logs: `docker-compose logs -f`
- Service health: `curl http://localhost:8000/health`
