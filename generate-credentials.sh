#!/bin/bash
# Secure Credential Generation Script for RAG Scan Stack
# This script generates strong random credentials and creates a .env file

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     RAG Scan Stack - Secure Credential Generator          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if .env already exists
if [ -f .env ]; then
    echo "⚠️  WARNING: .env file already exists!"
    read -p "Do you want to OVERWRITE it? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "❌ Aborted. No changes made."
        exit 1
    fi
    # Backup existing .env
    cp .env ".env.backup.$(date +%Y%m%d_%H%M%S)"
    echo "✓ Created backup of existing .env"
fi

echo ""
echo "🔐 Generating secure credentials..."
echo ""

# Generate secure random credentials
API_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZAP_API_KEY=$(openssl rand -hex 32)
KONG_ADMIN_TOKEN=$(openssl rand -hex 32)

# Database role passwords
N8N_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
EXPLOITDB_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
SCANS_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)

# Service credentials
CHISEL_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
MSF_RPC_PASS=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
VLLM_API_KEY=$(openssl rand -hex 32)

# Display generated credentials (will be saved to .env)
echo "Generated Credentials:"
echo "─────────────────────────────────────────────────────────────"
echo "API_KEY: ${API_KEY:0:16}... (64 chars)"
echo "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:0:12}... (32 chars)"
echo "ZAP_API_KEY: ${ZAP_API_KEY:0:16}... (64 chars)"
echo "KONG_ADMIN_TOKEN: ${KONG_ADMIN_TOKEN:0:16}... (64 chars)"
echo "CHISEL_PASSWORD: ${CHISEL_PASSWORD:0:12}... (24 chars)"
echo "MSF_RPC_PASS: ${MSF_RPC_PASS:0:12}... (24 chars)"
echo "VLLM_API_KEY: ${VLLM_API_KEY:0:16}... (64 chars)"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Create .env file
cat > .env << EOF
# ==========================================
# RAG SCAN STACK - SECURE CONFIGURATION
# ==========================================
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# ⚠️  SECURITY WARNING: Keep this file secure!
# - Do NOT commit to version control
# - Restrict file permissions: chmod 600 .env
# - Backup securely in encrypted storage
# ==========================================

# ==========================================
# CRITICAL SECURITY CREDENTIALS
# ==========================================

# Main API Key - Used by all services to authenticate with RAG API
API_KEY=${API_KEY}

# PostgreSQL Root Credentials
POSTGRES_USER=app
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=scans
POSTGRES_HOST=rag-postgres
POSTGRES_PORT=5432

# Constructed DSN (uses above variables)
DB_DSN=postgresql://app:${POSTGRES_PASSWORD}@rag-postgres:5432/scans

# Database Role Passwords (for multi-database setup)
N8N_PASSWORD=${N8N_PASSWORD}
EXPLOITDB_PASSWORD=${EXPLOITDB_PASSWORD}
SCANS_PASSWORD=${SCANS_PASSWORD}
EDB_RW_PASSWORD=${EXPLOITDB_PASSWORD}

# ZAP (OWASP ZAP Proxy) API Key
ZAP_API_KEY=${ZAP_API_KEY}
ZAP_ADDR=zap
ZAP_PORT=8090

# Kong API Gateway Admin Token
KONG_ADMIN_TOKEN=${KONG_ADMIN_TOKEN}

# Chisel Tunnel Credentials
CHISEL_USER=pentest
CHISEL_PASSWORD=${CHISEL_PASSWORD}

# Metasploit RPC Credentials
MSF_RPC_USER=msf
MSF_RPC_PASS=${MSF_RPC_PASS}
MSF_RPC_HOST=metasploit
MSF_RPC_PORT=55553
MSF_LHOST=
MSF_LPORT=4444

# ==========================================
# AI/RAG CONFIGURATION
# ==========================================

# Embedding model for RAG (Retrieval Augmented Generation)
EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2

# LLM Backend: "ollama" (default), "vllm", or "azure"
LLM_BACKEND=ollama

# Ollama LLM Model
OLLAMA_MODEL=qwen2.5:32b
OLLAMA_URL=http://ollama:11434
OLLAMA_TIMEOUT=300

# vLLM (when LLM_BACKEND=vllm)
VLLM_URL=http://vllm:8000
VLLM_MODEL=mistralai/Mistral-7B-Instruct-v0.3
VLLM_API_KEY=${VLLM_API_KEY}

# Azure AI Foundry / Azure OpenAI (when LLM_BACKEND=azure)
AZURE_API_KEY=
AZURE_ENDPOINT=
AZURE_MODEL=gpt-4o
AZURE_API_VERSION=2024-08-01-preview
AZURE_EMBED_MODEL=

# Autogen agent auto-execute safe tools (1=enabled, 0=disabled)
AUTO_EXECUTE_SAFE=1

# ==========================================
# NMAP SCANNER CONFIGURATION
# ==========================================

# Number of ports to batch in each scan operation
NMAP_PORT_BATCH=100

# Output directory for nmap results (inside container)
NMAP_OUT_DIR=/app/nmap_out

# Enable service/version detection (1=enabled, 0=disabled)
NMAP_SERVICE_DETECTION=1

# Version detection intensity (0-9, higher = more aggressive)
NMAP_VERSION_INTENSITY=9

# NSE scripts to run (comma-separated)
NMAP_SCRIPTS=banner,http-title,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,vulscan/vulscan.nse

# Nmap scanner service URL
NMAP_SCANNER_URL=http://nmap_scanner:8012

# ==========================================
# WEB SCANNER CONFIGURATION
# ==========================================

# Wordlist for directory/file brute forcing
WORDLIST=/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt

# Ports to scan for web services (comma-separated)
WEB_PORTS=80,443,8080,8443,8000,8888,3000,5000

# Extended port range for deep scans
DEEP_SCAN_PORTS=1001-65535

# Scheme hint: auto, http, https
SCHEME_HINT=auto

# Report directory
REPORT_DIR=/reports

# ==========================================
# NUCLEI VULNERABILITY SCANNER
# ==========================================

# Severity levels to scan for (comma-separated)
NUCLEI_SEVERITY=medium,high,critical

# Number of concurrent requests
NUCLEI_CONCURRENCY=50

# Rate limit (requests per minute)
NUCLEI_RATELIMIT=150

# Timeout per request (seconds)
NUCLEI_TIMEOUT=10

# Number of retries for failed requests
NUCLEI_RETRIES=1

# Auto-update templates on startup (1=enabled, 0=disabled)
NUCLEI_AUTO_UPDATE=1

# Nuclei templates directory
NUCLEI_TEMPLATES=/opt/nuclei-templates

# ==========================================
# PLAYWRIGHT BROWSER SCANNER
# ==========================================

# Browser engine: chromium, firefox, or webkit
BROWSER_TYPE=chromium

# Viewport dimensions for screenshots
VIEWPORT_WIDTH=1920
VIEWPORT_HEIGHT=1080

# Custom user agent string
USER_AGENT=Mozilla/5.0 (Playwright Security Scanner)

# Enable ZAP integration for browser traffic proxying
USE_ZAP=true

# Run browser in headless mode (recommended for production)
HEADLESS=true

# Screenshot format: png or jpeg
SCREENSHOT_FORMAT=png

# ==========================================
# SERVICE URLs (Internal Docker Network)
# ==========================================

# RAG API
RAG_API_URL=http://rag-api:8000
API_BASE=http://rag-api:8000

# Scanner Services
WEB_SCANNER_URL=http://web-scanner:8010
NUCLEI_URL=http://nuclei-runner:8011
NMAP_URL=http://nmap_scanner:8012
SCAN_RECOMMENDER_URL=https://scan-recommender:8013
PLAYWRIGHT_URL=http://playwright-scanner:8014
AUTOGEN_URL=http://autogen-agents:8015
EXPLOIT_RUNNER_URL=http://exploit-runner:8017
PD_RUNNER_URL=http://pd-runner:8023
OSINT_RUNNER_URL=http://osint-runner:8024
BRUTUS_RUNNER_URL=http://brutus-runner:8025
NODE_MANAGER_URL=http://node-manager:8027

# ==========================================
# OSINT / EXTERNAL API KEYS
# ==========================================

# Shodan (https://account.shodan.io)
SHODAN_API_KEY=

# Censys (https://search.censys.io/account/api)
CENSYS_API_ID=
CENSYS_API_SECRET=

# ProjectDiscovery Cloud Platform
PDCP_API_KEY=

# ==========================================
# SSH TUNNEL CONFIGURATION
# ==========================================
# Start: docker compose --profile ssh-tunnel up -d ssh-tunnel

SSH_REMOTE_HOST=
SSH_REMOTE_USER=root
SSH_REMOTE_PORT=22
SSH_MODE=dynamic
SSH_SOCKS_PORT=1080
SSH_REVERSE_BIND=0.0.0.0:9999
SSH_REVERSE_TARGET=pentest-dashboard:80
SSH_LOCAL_PORT=3389
SSH_LOCAL_TARGET=127.0.0.1:3389
SSH_KEY_PATH=./ssh-keys
SSH_KEY_NAME=id_rsa
SSH_TUNNEL_NAME=ssh-tunnel
SSH_EXTRA_OPTS=

# ==========================================
# RUNTIME CONFIGURATION
# ==========================================

# Timezone - all containers use this
TZ=America/New_York

# Enable debug logging for scan operations
SCAN_DEBUG=true

# Python path
PYTHONPATH=/app

# User/Group IDs for file permissions
GID=1000
UID=1000

# ==========================================
# EXPLOITDB ETL CONFIGURATION
# ==========================================

# ExploitDB database connection (read-write user)
PG_DSN=postgres://edb_rw:${EXPLOITDB_PASSWORD}@rag-postgres:5432/exploits

# SearchSploit JSON file location
SEARCHSPLOIT_JSON=/var/lib/searchsploit/searchsploit.json

# ==========================================
# OPEN WEBUI (optional)
# ==========================================

# OLLAMA_BASE_URL=http://ollama:11434
# OPENAI_API_BASE_URL=
# OPENAI_API_KEY=

# W&B for GRPO training (optional)
WANDB_API_KEY=

# ==========================================
# END OF CONFIGURATION
# ==========================================
EOF

# Set secure permissions
chmod 600 .env

echo "✓ .env file created successfully!"
echo ""
echo "📝 Next Steps:"
echo "─────────────────────────────────────────────────────────────"
echo "1. Review the generated .env file"
echo "2. Update database initialization with new passwords:"
echo "   ./update-database-credentials.sh"
echo "3. Update Kong configuration with new API_KEY:"
echo "   ./update-kong-config.sh"
echo "4. Restart all services:"
echo "   docker-compose down && docker-compose up -d"
echo ""
echo "⚠️  IMPORTANT: Backup your .env file securely!"
echo "   - Store in encrypted password manager"
echo "   - Keep separate backup offline"
echo "   - Never commit to version control"
echo "─────────────────────────────────────────────────────────────"
echo ""
echo "✓ Credential generation complete!"
