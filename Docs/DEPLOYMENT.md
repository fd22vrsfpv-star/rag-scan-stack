# RAG Scan Stack - Deployment Guide

This guide walks you through deploying the RAG Scan Stack from your development environment (WSL) to a production Docker environment on another machine.

## Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Pre-Deployment Preparation](#pre-deployment-preparation)
- [Deployment Methods](#deployment-methods)
- [Post-Deployment Configuration](#post-deployment-configuration)
- [Verification & Testing](#verification--testing)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

---

## Overview

The RAG Scan Stack is a comprehensive penetration testing platform with 16+ microservices including:

- **AI/LLM Services**: Ollama with GPU support for model inference
- **Network Scanning**: Nmap, Masscan
- **Web Security**: Gobuster, OWASP ZAP, Playwright
- **Vulnerability Scanning**: Nuclei
- **AI Orchestration**: AutoGen multi-agent system
- **API Gateway**: Kong for unified access
- **Database**: PostgreSQL with pgvector for RAG capabilities

---

## System Requirements

### Minimum Requirements

- **CPU**: 8+ cores (recommended)
- **RAM**: 32GB+ (recommended)
  - Ollama LLM: 8-16GB
  - PostgreSQL: 2-4GB
  - Playwright browsers: 2GB per instance
  - Other services: 4-8GB
- **Storage**: 50GB+ available
  - Docker images: ~20GB
  - Ollama models: ~10GB
  - Database: grows with scan data
  - Scan outputs: variable
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+) or Windows with WSL2

### Optional (Recommended for Performance)

- **GPU**: NVIDIA GPU with 8GB+ VRAM for faster LLM inference
- **NVIDIA Container Toolkit**: Required for GPU support in Docker

### Required Software

- Docker Engine 20.10+
- Docker Compose v2.0+
- Git (for cloning repository)
- nvidia-container-toolkit (if using GPU)

---

## Pre-Deployment Preparation

### On Your Development Machine (WSL)

#### 1. Commit Your Changes

```bash
cd /utils/agents

# Review modified files
git status

# Commit changes
git add docker-compose.yml .env.production.example kong/kong.yml.production.example scripts/deploy.sh
git commit -m "Prepare for production deployment"

# Push to repository
git push origin master
```

#### 2. Backup Ollama Models (Optional but Recommended)

If you've already downloaded Ollama models (~8-10GB) and want to avoid re-downloading on the target machine:

```bash
# Check if models exist
ls -lh /mnt/c/Users/rapto/.ollama/models 2>/dev/null || ls -lh ./ollama-data/models 2>/dev/null

# If models exist, compress them
cd /utils/agents
tar -czf ollama-models-backup.tar.gz ollama-data/

# Transfer to target machine
scp ollama-models-backup.tar.gz user@target-machine:/newloc/to/destination/
```

#### 3. Document Your Configuration

Make note of any custom configurations:
- Custom environment variables
- Modified scanner settings
- Network configurations
- Firewall rules

---

## Deployment Methods

### Method 1: Automated Deployment (Recommended)

This is the easiest method using the provided deployment script.

#### On Target Machine

```bash
# 1. Clone the repository
git clone <your-repo-url> /opt/rag-scan-stack
cd /opt/rag-scan-stack

# 2. (Optional) Extract Ollama models if transferred
# If you transferred ollama-models-backup.tar.gz:
tar -xzf ollama-models-backup.tar.gz

# 3. Run the deployment script
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

The script will:
- Check all prerequisites (Docker, GPU, etc.)
- Create Docker network
- Create required directories
- Set up configuration files
- Optionally start services

Follow the on-screen prompts to complete the setup.

---

### Method 2: Manual Deployment

If you prefer manual control over the deployment process:

#### Step 1: Install Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose v2
sudo apt install docker-compose-plugin

# Log out and back in for group changes to take effect

# Verify installation
docker --version
docker compose version
```

#### Step 2: Install NVIDIA Container Toolkit (Optional)

Only if you have an NVIDIA GPU and want GPU acceleration:

```bash
# Add NVIDIA package repositories
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | \
  sudo tee /etc/apt/sources.list.d/nvidia-docker.list

# Install nvidia-container-toolkit
sudo apt update
sudo apt install -y nvidia-container-toolkit

# Restart Docker
sudo systemctl restart docker

# Verify
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi
```

#### Step 3: Clone Repository

```bash
git clone <your-repo-url> /opt/rag-scan-stack
cd /opt/rag-scan-stack
```

#### Step 4: Create Docker Network

```bash
docker network create agents_net
```

#### Step 5: Create Required Directories

```bash
mkdir -p nmap_out web_reports nuclei_reports \
         playwright_screenshots playwright_reports \
         autogen_logs autogen_cache ollama-data
```

#### Step 6: Configure Environment

```bash
# Copy environment template
cp .env.production.example .env

# Generate secure credentials
API_KEY=$(openssl rand -hex 32)
ZAP_API_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Edit .env and update:
# - API_KEY
# - ZAP_API_KEY
# - POSTGRES_USER and POSTGRES_PASSWORD
# - DB_DSN (update with new password)
nano .env
```

#### Step 7: Configure Kong

```bash
# Copy Kong template
cp kong/kong.yml.production.example kong/kong.yml

# Replace API key (use the same API_KEY from .env)
sed -i "s/REPLACE_WITH_YOUR_API_KEY/${API_KEY}/g" kong/kong.yml
sed -i "s/change-me/${API_KEY}/g" kong/kong.yml
```

#### Step 8: Extract Ollama Models (Optional)

If you transferred the models backup:

```bash
tar -xzf ollama-models-backup.tar.gz
```

#### Step 9: Build and Start Services

```bash
# Build all services
docker compose build

# Start services in detached mode
docker compose up -d

# Monitor startup logs
docker compose logs -f
```

---

## Post-Deployment Configuration

### 1. Verify Services Are Running

```bash
# Check service status
docker compose ps

# All services should show "running" or "healthy"
```

### 2. Check Service Health

```bash
# Check individual service health
docker compose ps | grep "healthy"

# View logs for any failing services
docker compose logs <service-name>
```

### 3. Verify Ollama Models

```bash
# Connect to Ollama container
docker exec -it ollama ollama list

# Should show:
# - nomic-embed-text
# - interstellarninja/hermes-3-llama-3.1-8b-tools
```

If models are missing:

```bash
# Pull models manually
docker exec -it ollama ollama pull nomic-embed-text
docker exec -it ollama ollama pull interstellarninja/hermes-3-llama-3.1-8b-tools
```

### 4. Verify Database Initialization

```bash
# Connect to database
docker exec -it rag-postgres psql -U app -d scans

# List tables
\dt

# Should show tables like: assets, ports, scans, findings, etc.

# Exit
\q
```

### 5. Test API Endpoints

```bash
# Get your API_KEY from .env
API_KEY=$(grep "^API_KEY=" .env | cut -d'=' -f2)

# Test RAG API health
curl -H "x-api-key: $API_KEY" http://localhost:8000/health

# Test through Kong gateway
curl http://localhost:7080/docs

# Test Ollama
curl http://localhost:11434/api/tags
```

---

## Verification & Testing

### Service Port Mapping

Verify each service is accessible:

| Service | Port | Test URL |
|---------|------|----------|
| Kong Gateway | 7080 | http://localhost:7080/docs |
| RAG API | 8000 | http://localhost:8000/health |
| LLM Query | 8002 | http://localhost:8002/healthz |
| Web Scanner | 8010 | http://localhost:8010/health |
| Nuclei Runner | 8011 | http://localhost:8011/health |
| Nmap Scanner | 8012 | http://localhost:8012/health |
| Scan Recommender | 8013 | http://localhost:8013/health |
| Playwright | 8014 | http://localhost:8014/health |
| AutoGen Agents | 8015 | http://localhost:8015/health |
| ZAP Proxy | 8090 | http://localhost:8090/ |
| Ollama | 11434 | http://localhost:11434/api/tags |

### Run a Test Scan

```bash
# Get your API_KEY
API_KEY=$(grep "^API_KEY=" .env | cut -d'=' -f2)

# Test a simple scan via Kong gateway
curl -X POST http://localhost:7080/rag-api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "scan_type": "quick"}'
```

---

## Troubleshooting

### Common Issues

#### 1. Services Not Starting

**Symptom**: Services show "Exited" or "Restarting"

**Solutions**:

```bash
# Check logs
docker compose logs <service-name>

# Common causes:
# - Network not created: docker network create agents_net
# - Port conflicts: Check if ports are already in use
# - Missing dependencies: Check depends_on in docker-compose.yml
```

#### 2. Ollama Model Download Failures

**Symptom**: ollama-init service fails, models not available

**Solutions**:

```bash
# Manually pull models
docker exec -it ollama ollama pull nomic-embed-text
docker exec -it ollama ollama pull interstellarninja/hermes-3-llama-3.1-8b-tools

# Check available disk space
df -h

# Check network connectivity
docker exec -it ollama ping -c 3 ollama.ai
```

#### 3. GPU Not Detected

**Symptom**: Ollama runs but very slow, no GPU acceleration

**Solutions**:

```bash
# Verify GPU is available
nvidia-smi

# Check Docker can access GPU
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi

# If fails, reinstall nvidia-container-toolkit
sudo apt install --reinstall nvidia-container-toolkit
sudo systemctl restart docker
```

#### 4. Database Connection Errors

**Symptom**: Services can't connect to database

**Solutions**:

```bash
# Check PostgreSQL is running
docker compose ps rag-postgres

# Check database logs
docker compose logs rag-postgres

# Verify DB_DSN in .env matches credentials
# Format: postgresql://user:password@rag-postgres:5432/scans

# Test connection manually
docker exec -it rag-postgres psql -U app -d scans
```

#### 5. API Authentication Failures

**Symptom**: 401/403 errors when calling APIs

**Solutions**:

```bash
# Ensure API keys match between .env and kong/kong.yml
grep "^API_KEY=" .env
grep "x-api-key:" kong/kong.yml

# Update Kong config and restart
docker compose restart kong
```

#### 6. Out of Memory Errors

**Symptom**: Services crashing, "OOMKilled" status

**Solutions**:

```bash
# Check memory usage
docker stats

# Increase Docker memory limit (Docker Desktop)
# Or reduce service concurrency in .env:
# NUCLEI_CONCURRENCY=25
# NMAP_PORT_BATCH=50

# Restart services
docker compose restart
```

---

## Maintenance

### Updating the Stack

```bash
# Pull latest code
cd /opt/rag-scan-stack
git pull origin master

# Rebuild and restart services
docker compose down
docker compose up -d --build
```

### Backup Database

```bash
# Backup PostgreSQL data
docker exec rag-postgres pg_dump -U app scans > backup_$(date +%Y%m%d).sql

# Or backup the entire volume
docker run --rm -v rag-scan-stack_rag-pgdata:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/pgdata_backup_$(date +%Y%m%d).tar.gz /data
```

### Update Nuclei Templates

```bash
# Nuclei templates auto-update if NUCLEI_AUTO_UPDATE=1
# To manually update:
docker exec nuclei-runner nuclei -update-templates
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f <service-name>

# Last 100 lines
docker compose logs --tail=100 <service-name>
```

### Restart Services

```bash
# Restart all services
docker compose restart

# Restart specific service
docker compose restart <service-name>

# Stop all services
docker compose down

# Start all services
docker compose up -d
```

### Clean Up

```bash
# Remove stopped containers
docker compose down

# Remove containers and volumes (WARNING: deletes data)
docker compose down -v

# Clean up unused images
docker image prune -a

# Clean up unused volumes
docker volume prune
```

---

## Security Recommendations

### Production Hardening

1. **Change All Default Credentials**
   - Update API_KEY, ZAP_API_KEY, POSTGRES_PASSWORD
   - Use strong, randomly generated keys

2. **Firewall Configuration**
   ```bash
   # Only expose Kong gateway externally
   # Block direct access to service ports (8000-8015)
   sudo ufw allow 7080/tcp  # Kong HTTP
   sudo ufw enable
   ```

3. **Enable SSL/TLS**
   - Configure Kong with SSL certificates
   - Use Let's Encrypt for free certificates
   - Update KONG_PROXY_LISTEN to include SSL

4. **Regular Updates**
   - Keep Docker and system packages updated
   - Regularly update Nuclei templates
   - Monitor security advisories for dependencies

5. **Monitor Logs**
   - Set up centralized logging (ELK, Grafana)
   - Monitor for suspicious activity
   - Set up alerts for service failures

6. **Backup Strategy**
   - Automate database backups
   - Store backups offsite
   - Test restore procedures regularly

---

## Additional Resources

- **Docker Documentation**: https://docs.docker.com/
- **Docker Compose**: https://docs.docker.com/compose/
- **NVIDIA Container Toolkit**: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/
- **Kong Gateway**: https://docs.konghq.com/
- **Ollama**: https://ollama.ai/

---

## Support

For issues specific to this deployment:

1. Check logs: `docker compose logs -f`
2. Review this troubleshooting guide
3. Check service health: `docker compose ps`
4. Verify configurations in `.env` and `kong/kong.yml`

For upstream project issues, refer to individual project documentation.

---

**Last Updated**: 2025-11-03
