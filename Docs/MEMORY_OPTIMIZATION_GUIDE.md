# Memory Optimization Guide

**System**: 32GB RAM + 16GB VRAM (NVIDIA GPU)
**Current**: WSL limited to 13GB RAM, Ollama not using GPU

## Problem Analysis

### Current Resource Usage
- **WSL Allocation**: 13GB (only 40% of available 32GB)
- **Ollama**: 4.3GB RAM (should use VRAM instead)
- **Kong**: 845MB (can be optimized)
- **Other containers**: ~2GB combined

### Why Memory Pressure Occurs
1. WSL2 is artificially limited to 13GB
2. Ollama loads models into RAM instead of VRAM
3. No GPU passthrough configured for Docker

---

## Solution 1: Increase WSL2 Memory Allocation

### Step 1: Create/Update .wslconfig

From **Windows** (not WSL), create/edit: `C:\Users\<YourUsername>\.wslconfig`

```ini
[wsl2]
# Allocate 24GB RAM (75% of 32GB, leaving 8GB for Windows)
memory=24GB

# Allocate 8GB swap
swap=8GB

# Use all CPU cores
processors=12

# Disable firewall for better performance
firewall=false

# Auto-reclaim memory when idle
[experimental]
autoMemoryReclaim=gradual
```

### Step 2: Restart WSL

From **Windows PowerShell (as Administrator)**:
```powershell
wsl --shutdown
```

Then restart your WSL terminal.

### Expected Result
- WSL will now have 24GB RAM available
- Docker containers can use up to 24GB

---

## Solution 2: Enable GPU for Ollama (Use VRAM)

### Check if GPU is Available

From WSL:
```bash
nvidia-smi
```

If you see GPU info, you have GPU passthrough. If not, you need WSL GPU drivers.

### Option A: WSL Has GPU Access

Update docker-compose.yml for Ollama:

```yaml
ollama:
  image: ollama/ollama:latest
  container_name: ollama
  ports:
    - "11435:11434"
  volumes:
    - ollama-models:/root/.ollama
  networks:
    - agents_net
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
  environment:
    - OLLAMA_HOST=0.0.0.0:11434
    - OLLAMA_NUM_GPU=1              # Use 1 GPU
    - OLLAMA_GPU_LAYERS=999         # Load all layers to GPU
    - OLLAMA_VRAM_HEADROOM=2048     # Reserve 2GB VRAM headroom
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
    interval: 30s
    timeout: 10s
    retries: 3
```

### Option B: No GPU Access (Software Only)

Reduce Ollama memory footprint:

```yaml
ollama:
  image: ollama/ollama:latest
  container_name: ollama
  ports:
    - "11435:11434"
  volumes:
    - ollama-models:/root/.ollama
  networks:
    - agents_net
  environment:
    - OLLAMA_HOST=0.0.0.0:11434
    - OLLAMA_MAX_LOADED_MODELS=1    # Only keep 1 model in memory
    - OLLAMA_MAX_VRAM=0              # Disable VRAM (force CPU)
    - OLLAMA_NUM_PARALLEL=1          # Reduce parallel requests
  deploy:
    resources:
      limits:
        memory: 8G                   # Limit Ollama to 8GB RAM
  restart: unless-stopped
```

---

## Solution 3: Optimize Kong Gateway

Kong is using 845MB. Reduce it:

```yaml
kong:
  image: kong:3.6
  container_name: kong
  ports:
    - "7080:7080"
    - "127.0.0.1:7081:7081"
  environment:
    KONG_DATABASE: "off"
    KONG_DECLARATIVE_CONFIG: /kong/kong.yml
    KONG_PROXY_LISTEN: "0.0.0.0:7080"
    KONG_ADMIN_LISTEN: "127.0.0.1:7081"
    KONG_NGINX_WORKER_PROCESSES: "2"      # Reduce from default 4
    KONG_MEM_CACHE_SIZE: "64m"            # Reduce cache size
    KONG_NGINX_HTTP_LUA_SHARED_DICT: "kong_db_cache 32m"
  deploy:
    resources:
      limits:
        memory: 512M                      # Limit Kong to 512MB
  volumes:
    - ./kong/kong.yml:/kong/kong.yml:ro
  networks:
    - agents_net
  restart: unless-stopped
```

---

## Solution 4: Set Memory Limits on All Containers

Add resource limits to docker-compose.yml:

```yaml
services:
  # Large services
  ollama:
    deploy:
      resources:
        limits:
          memory: 8G
        reservations:
          memory: 4G

  kong:
    deploy:
      resources:
        limits:
          memory: 512M

  librechat:
    deploy:
      resources:
        limits:
          memory: 512M

  # Small services (backend tools)
  nmap_scanner:
    deploy:
      resources:
        limits:
          memory: 256M

  # Repeat for other services...
```

---

## Solution 5: Reduce Ollama Model Size

### Current Models
- qwen2.5:32b - **~20GB** (too large)
- qwen2.5:14b - **~9GB**
- llama3.1:8b - **~4.7GB** ✅ Best for 16GB VRAM

### Recommendations

**If using GPU (16GB VRAM)**:
- Keep: llama3.1:8b (4.7GB)
- Keep: qwen2.5:14b (9GB) - fits in VRAM
- Remove: qwen2.5:32b (20GB) - too large

**Remove large model**:
```bash
docker exec ollama ollama rm qwen2.5:32b
```

**If using CPU only**:
- Keep only: llama3.1:8b (best tool calling, smallest footprint)

```bash
docker exec ollama ollama rm qwen2.5:14b
docker exec ollama ollama rm qwen2.5:32b
```

---

## Solution 6: Enable Docker BuildKit with Better Caching

Reduce memory during builds by enabling BuildKit:

Create/edit `~/.docker/daemon.json`:

```json
{
  "features": {
    "buildkit": true
  },
  "builder": {
    "gc": {
      "enabled": true,
      "defaultKeepStorage": "10GB"
    }
  }
}
```

---

## Implementation Priority

### High Priority (Do First)
1. ✅ **Increase WSL memory to 24GB** (.wslconfig)
2. ✅ **Enable GPU for Ollama** (if GPU available)
3. ✅ **Remove qwen2.5:32b model** (20GB)

### Medium Priority
4. 🔶 **Add memory limits to containers**
5. 🔶 **Optimize Kong to 512MB**

### Low Priority
6. 🔷 **Enable BuildKit caching**

---

## Step-by-Step Quick Fix

### 1. Update .wslconfig (From Windows)

Create `C:\Users\<YourUsername>\.wslconfig`:
```ini
[wsl2]
memory=24GB
swap=8GB
processors=12
```

### 2. Shutdown WSL (From Windows PowerShell as Admin)
```powershell
wsl --shutdown
```

### 3. Restart WSL and Verify
```bash
free -h
# Should now show ~24GB total
```

### 4. Remove Large Model
```bash
docker exec ollama ollama rm qwen2.5:32b
```

### 5. Check if GPU is Available
```bash
nvidia-smi
# If this works, you have GPU access
```

### 6. Update Ollama Config (if GPU available)

Edit `/opt/rag_scan_stack/docker-compose.yml` and add GPU config to ollama service.

### 7. Restart Stack
```bash
cd /opt/rag_scan_stack
docker-compose restart ollama
```

---

## Expected Results After Optimization

### Before
- WSL RAM: 13GB (limited)
- Ollama: 4.3GB RAM
- Kong: 845MB RAM
- Total pressure: High
- Swap usage: 2.3GB

### After
- WSL RAM: 24GB (available)
- Ollama: 4.3GB VRAM (or 2GB RAM with limits)
- Kong: 300-400MB RAM
- Total pressure: Low
- Swap usage: <500MB

---

## Monitoring Commands

### Check WSL Memory
```bash
free -h
```

### Check Container Memory
```bash
docker stats --no-stream
```

### Check Ollama GPU Usage
```bash
docker exec ollama nvidia-smi
```

### Check Loaded Models
```bash
curl http://localhost:11435/api/tags
```

### Unload All Models (Free Memory)
```bash
# Unload qwen2.5:32b
curl -X POST http://localhost:11435/api/generate \
  -d '{"model": "qwen2.5:32b", "keep_alive": 0}'

# Unload qwen2.5:14b
curl -X POST http://localhost:11435/api/generate \
  -d '{"model": "qwen2.5:14b", "keep_alive": 0}'
```

---

## Troubleshooting

### WSL Still Shows 13GB After .wslconfig Update

**Solution**: Make sure you ran `wsl --shutdown` from Windows PowerShell as Administrator, not from WSL terminal.

### Ollama Not Using GPU

**Check**:
```bash
docker exec ollama nvidia-smi
```

If error, you need to:
1. Install NVIDIA drivers for WSL2
2. Install nvidia-docker2 in WSL
3. Restart Docker daemon

### Out of Memory Errors After Limits

**Solution**: Increase limits in docker-compose.yml or remove models:
```bash
docker exec ollama ollama rm qwen2.5:32b
```

---

**Last Updated**: 2026-02-20
