# RAG Scan Stack - Quick Deployment Guide

**Target**: Deploy from WSL development environment to Docker on another machine with GPU support

## Prerequisites Checklist

- [ ] Target machine has Docker Engine 20.10+ installed
- [ ] Target machine has Docker Compose v2+ installed
- [ ] Target machine has NVIDIA GPU + nvidia-container-toolkit (optional but recommended)
- [ ] Git installed on target machine
- [ ] At least 32GB RAM and 50GB free disk space

---

## Quick Deployment Steps

### 1. On Development Machine (WSL)

```bash
# Navigate to project
cd /utils/agents

# Commit and push changes
git add .
git commit -m "Prepared for production deployment"
git push origin master

# Optional: Backup Ollama models to avoid re-downloading (~8-10GB)
tar -czf ollama-models.tar.gz ollama-data/

# Transfer to target (if backing up models)
scp ollama-models.tar.gz user@target-machine:/tmp/
```

### 2. On Target Machine

```bash
# Clone repository
git clone <your-repo-url> /opt/rag-scan-stack
cd /opt/rag-scan-stack

# Optional: Extract Ollama models backup
tar -xzf /tmp/ollama-models.tar.gz

# RECOMMENDED: Single-command setup (Go tools + credentials + build + start + DB)
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or step-by-step:
# ./scripts/build-go-tools.sh   # compile Go security tools (~10-15 min)
# ./generate-credentials.sh     # generate .env
# ./scripts/deploy.sh           # network, dirs, kong, build, start
# ./scripts/ensure_db_schema.sh # verify DB tables
```

The unified setup script handles:
- Checking prerequisites (Docker, Compose, GPU)
- Building Go security tools (skips if already built)
- Generating secure credentials (.env)
- Creating Docker network and directories
- Building all Docker images
- Starting services
- Applying database schema
- Running health checks

### 3. Post-Deployment

```bash
# Generate secure credentials
openssl rand -hex 32  # For API_KEY
openssl rand -hex 32  # For ZAP_API_KEY

# Update .env with credentials
nano .env

# Update Kong configuration
nano kong/kong.yml
# Replace all "REPLACE_WITH_YOUR_API_KEY" with your actual API key

# Start services
docker compose up -d --build

# Monitor startup
docker compose logs -f

# Check service status
docker compose ps
```

### 4. Verify Deployment

```bash
# Check all services are healthy
docker compose ps | grep "healthy"

# Test API gateway
curl http://localhost:7080/docs

# Test individual services
curl http://localhost:8000/health  # RAG API
curl http://localhost:11434/api/tags  # Ollama

# Verify Ollama models
docker exec -it ollama ollama list
```

---

## File Transfer Methods

### Method 1: Git Repository (Recommended)

**Best for**: Code and configuration files

```bash
# On development machine
git push origin master

# On target machine
git clone <repo-url> /opt/rag-scan-stack
```

### Method 2: SCP (for Ollama models)

**Best for**: Large binary files (Ollama models)

```bash
# From development machine to target
scp ollama-models.tar.gz user@target:/tmp/

# Or entire project directory (excluding models)
rsync -avz --exclude 'ollama-data' /utils/agents/ user@target:/opt/rag-scan-stack/
```

### Method 3: USB Drive

**Best for**: Air-gapped or offline deployments

```bash
# On development machine
cd /utils/agents
tar -czf rag-stack-complete.tar.gz .

# Copy to USB, then on target machine
tar -xzf /media/usb/rag-stack-complete.tar.gz -C /opt/rag-scan-stack/
```

---

## Configuration Quick Reference

### Required Configuration Files

| File | Purpose | Action Required |
|------|---------|----------------|
| `.env` | Environment variables | Copy from `.env.production.example`, update credentials |
| `kong/kong.yml` | API gateway config (generated, gitignored) | Copy from `kong/kong.yml.template`, update API keys |
| `docker-compose.yml` | Service definitions | Already updated with portable paths |

### Key Configuration Changes

```bash
# .env
API_KEY=<your-32-char-hex>
ZAP_API_KEY=<your-32-char-hex>
POSTGRES_PASSWORD=<strong-password>
DB_DSN=postgresql://app:<password>@rag-postgres:5432/scans

# kong/kong.yml
# Replace all instances of "REPLACE_WITH_YOUR_API_KEY" with your API_KEY
sed -i 's/REPLACE_WITH_YOUR_API_KEY/<your-api-key>/g' kong/kong.yml
```

---

## Minimal Manual Deployment

If you prefer to skip the automated script:

```bash
# 1. Create network
docker network create agents_net

# 2. Create directories
mkdir -p nmap_out web_reports nuclei_reports \
         playwright_screenshots playwright_reports \
         autogen_logs autogen_cache ollama-data

# 3. Configure
cp .env.production.example .env
cp kong/kong.yml.template kong/kong.yml
# Edit both files with your credentials

# 4. Start
docker compose up -d --build
```

---

## Service Access After Deployment

| Service | URL | Authentication |
|---------|-----|----------------|
| API Gateway | http://target:7080 | Via Kong config |
| Swagger Docs | http://target:7080/docs | None |
| RAG API | http://target:8000 | x-api-key header |
| Ollama | http://target:11434 | None |
| ZAP Proxy | http://target:8090 | ZAP_API_KEY |

---

## Troubleshooting Quick Fixes

### Services won't start
```bash
# Check network exists
docker network ls | grep agents_net

# Create if missing
docker network create agents_net

# Restart services
docker compose restart
```

### Ollama GPU not detected
```bash
# Check GPU
nvidia-smi

# Check Docker GPU access
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi

# If fails, check nvidia-container-toolkit
sudo apt install nvidia-container-toolkit
sudo systemctl restart docker
```

### Models not loading
```bash
# Manually pull models
docker exec -it ollama ollama pull nomic-embed-text
docker exec -it ollama ollama pull interstellarninja/hermes-3-llama-3.1-8b-tools
```

### Database connection errors
```bash
# Check PostgreSQL
docker compose ps rag-postgres
docker compose logs rag-postgres

# Verify credentials match in .env
grep DB_DSN .env
```

### Out of memory
```bash
# Check memory usage
docker stats

# Reduce concurrency in .env
NUCLEI_CONCURRENCY=25
NMAP_PORT_BATCH=50

# Restart
docker compose restart
```

---

## Key Changes Made for Portability

1. **Ollama volume path**: Changed from `/mnt/c/Users/rapto/.ollama` to `./ollama-data`
2. **Production templates**: Created `.env.production.example` and `kong/kong.yml.template`
3. **Deployment script**: Automated setup at `scripts/deploy.sh`
4. **Documentation**: Complete deployment guide in `DEPLOYMENT.md`

---

## What Gets Transferred

### Via Git (Code & Config)
- Docker Compose configuration
- Service Dockerfiles
- Database initialization scripts
- Configuration templates
- Deployment scripts

### Manually Transfer (Optional)
- Ollama models (`ollama-data/` - ~10GB)
  - Saves download time
  - Not required if you can download on target

### Created on Target
- Named volumes (rag-pgdata, nuclei-templates, searchsploit-data)
- Output directories (scans, reports, logs)
- Docker network (agents_net)

---

## Estimated Deployment Time

| Phase | Time | Notes |
|-------|------|-------|
| Prerequisites check | 5 min | If already installed |
| Network/directory setup | 2 min | Automated |
| Configuration | 10 min | Manual credential updates |
| Docker build | 15-20 min | First time only |
| Service startup | 5-10 min | Health checks |
| Model download | 20-30 min | If not transferred |
| **Total** | **45-75 min** | Excluding model transfer |

With pre-transferred Ollama models: **30-45 minutes**

---

## Next Steps After Deployment

1. **Verify all services are healthy**: `docker compose ps`
2. **Run test scan**: Access Swagger docs at http://target:7080/docs
3. **Set up monitoring**: Consider adding Prometheus/Grafana
4. **Configure backups**: Automate PostgreSQL backups
5. **Harden security**: Review firewall rules, enable SSL
6. **Document customizations**: Note any environment-specific changes

---

For detailed information, see [DEPLOYMENT.md](./DEPLOYMENT.md)
