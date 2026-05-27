#!/usr/bin/env bash
#
# update.sh — Pull latest code, rebuild containers, apply DB schema, start services
#
# Usage:
#   ./scripts/update.sh           # Full update
#   ./scripts/update.sh --quick   # Skip rebuild (just restart with new code)
#   ./scripts/update.sh --no-llm  # Skip LLM model pull
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

QUICK=false
SKIP_LLM=false
DO_PRUNE=false
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=true ;;
        --no-llm) SKIP_LLM=true ;;
        --prune) DO_PRUNE=true ;;
        --help|-h)
            echo "Usage: $0 [--quick] [--no-llm] [--prune]"
            echo "  --quick   Skip docker compose build (faster, uses existing images)"
            echo "  --no-llm  Skip pulling/activating LLM model"
            echo "  --prune   Clean up unused Docker images and build cache after update"
            exit 0
            ;;
    esac
done

echo "============================================================"
echo "  RAG Scan Stack — Update"
echo "  $(date)"
echo "============================================================"
echo ""

# 1. Pull latest code
echo "[1/7] Pulling latest code..."
if git pull 2>&1 | tee /tmp/update_git_pull.log | tail -3; then
    CHANGES=$(grep -c "files changed\|file changed" /tmp/update_git_pull.log 2>/dev/null || echo "0")
    if echo "$CHANGES" | grep -q "0"; then
        echo "  Already up to date."
    else
        echo "  Code updated."
    fi
else
    echo "  WARNING: git pull failed — continuing with current code"
fi
echo ""

# 2. Generate TLS certs if missing
echo "[2/7] Checking TLS certificates..."
if [ -f "$PROJECT_ROOT/certs/server.crt" ] && [ -f "$PROJECT_ROOT/certs/server.key" ]; then
    echo "  Certificates exist."
    # Ensure key is readable by containers
    chmod 644 "$PROJECT_ROOT/certs/server.key" 2>/dev/null || true
else
    echo "  Generating self-signed TLS certificates..."
    "$SCRIPT_DIR/generate-certs.sh"
fi
echo ""

# 3. Build containers
if [ "$QUICK" = true ]; then
    echo "[3/7] Skipping build (--quick mode)"
else
    echo "[3/7] Building containers (this may take a few minutes)..."
    if docker compose build 2>&1 | grep -E "Built|ERROR|error" | head -30; then
        echo "  Build complete."
    else
        echo "  Build complete (no output = all cached)."
    fi
fi
echo ""

# 4. Start services
echo "[4/7] Starting services..."
docker compose up -d 2>&1 | grep -v "Running\|Exited\|Waiting" | tail -20
echo ""

# 5. Wait for core services to be healthy
echo "[5/7] Waiting for services to be healthy..."
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    # Check if rag-api is healthy (the main dependency)
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' rag-api 2>/dev/null || echo "starting")
    if [ "$HEALTH" = "healthy" ]; then
        echo "  Core services healthy after ${ELAPSED}s"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "  Waiting... (${ELAPSED}s, rag-api: ${HEALTH})"
done
if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "  WARNING: Timed out waiting for healthy status. Services may still be starting."
fi
echo ""

# 6. Apply database schema
echo "[6/7] Applying database schema updates..."
if [ -f "$SCRIPT_DIR/ensure_db_schema.sh" ]; then
    "$SCRIPT_DIR/ensure_db_schema.sh" 2>&1 | grep -E "table count|critical|✓|✗|✅|❌" | head -10
else
    echo "  Schema script not found — skipping"
fi
echo ""

# 7. Pull and activate LLM model
if [ "$SKIP_LLM" = true ]; then
    echo "[7/7] Skipping LLM model (--no-llm)"
else
    echo "[7/7] Checking LLM model..."
    # Read configured model from .env
    OLLAMA_MODEL=$(grep "^OLLAMA_MODEL=" .env 2>/dev/null | cut -d= -f2 || echo "gemma4:26b")
    if [ -z "$OLLAMA_MODEL" ]; then
        OLLAMA_MODEL="gemma4:26b"
    fi

    # Check if ollama is running
    if docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
        # Check if model exists
        if docker exec ollama ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
            echo "  Model $OLLAMA_MODEL already available."
        else
            echo "  Pulling $OLLAMA_MODEL (this may take a while)..."
            docker exec ollama ollama pull "$OLLAMA_MODEL" 2>&1 | grep -E "success|pulling|Error" | tail -3
        fi

        # Set as active
        API_PORT=$(docker port rag-api 2>/dev/null | grep 8000 | head -1 | cut -d: -f2 || echo "8000")
        API_KEY=$(grep "^API_KEY=" .env 2>/dev/null | cut -d= -f2 || echo "changeme")
        curl -sk "https://localhost:${API_PORT}/settings/config/ollama_active_model" \
            -X PUT -H "Content-Type: application/json" -H "x-api-key: ${API_KEY}" \
            -d "{\"value\": \"${OLLAMA_MODEL}\"}" >/dev/null 2>&1 && \
            echo "  Active model set to $OLLAMA_MODEL" || \
            echo "  Could not set active model via API (set manually in UI)"
    else
        echo "  Ollama not running — skipping model pull (start with: docker compose up -d ollama)"
    fi
fi
echo ""

# Summary
echo "============================================================"
echo "  Update complete!"
echo "============================================================"
echo ""

# Quick health check
DASHBOARD_PORT=$(docker port pentest-dashboard 2>/dev/null | grep 443 | head -1 | cut -d: -f2 || echo "3002")
echo "  Dashboard:  https://localhost:${DASHBOARD_PORT}"
echo "  API:        https://localhost:8000/docs"
echo ""

# Show service status
HEALTHY=$(docker ps --format '{{.Status}}' | grep -c "healthy" || echo "0")
TOTAL=$(docker ps --format '{{.Names}}' | wc -l)
echo "  Containers: ${TOTAL} running, ${HEALTHY} healthy"
echo ""

# Show any unhealthy
UNHEALTHY=$(docker ps --format '{{.Names}} {{.Status}}' | grep -v healthy | grep -v Exited | grep -v "health:" | grep -v "^$" || true)
if [ -n "$UNHEALTHY" ]; then
    echo "  Note: Some containers without healthcheck or still starting:"
    echo "$UNHEALTHY" | head -5 | sed 's/^/    /'
fi

# Docker disk usage check + cleanup
DOCKER_USAGE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)
RECLAIMABLE=$(docker system df --format '{{.Reclaimable}}' 2>/dev/null | head -1)

# Parse reclaimable size into GB for comparison
RECLAIM_GB=0
if echo "$RECLAIMABLE" | grep -q "GB"; then
    RECLAIM_GB=$(echo "$RECLAIMABLE" | grep -oP '[\d.]+' | head -1 | cut -d. -f1)
fi

if [ "$DO_PRUNE" = true ]; then
    echo ""
    echo "============================================================"
    echo "  Docker Cleanup"
    echo "============================================================"
    echo ""
    echo "  Removing unused images..."
    docker image prune -f 2>&1 | tail -2
    echo "  Removing dangling build cache..."
    docker builder prune -f --filter 'until=168h' 2>&1 | tail -2
    echo ""
    docker system df 2>&1 | head -5
elif [ "$RECLAIM_GB" -gt 20 ] 2>/dev/null; then
    echo ""
    echo "  ⚠️  Docker is using significant disk space:"
    docker system df 2>&1 | head -5 | sed 's/^/     /'
    echo ""
    echo "  ${RECLAIMABLE} can be reclaimed. Run with --prune to clean up:"
    echo "    ./scripts/update.sh --prune"
    echo ""
fi

# WSL2 network info
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  WSL2 Network Info"
    echo "============================================================"

    WSL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "  WSL2 IP:      ${WSL_IP:-unknown}"

    # Try to detect Windows host IP
    WIN_IP=$(ip route show default 2>/dev/null | awk '{print $3}' || echo "unknown")
    echo "  Windows Host: ${WIN_IP}"

    echo ""
    echo "  IMPORTANT after WSL restart:"
    echo "  ────────────────────────────"
    echo "  1. WSL2 IP changes on every restart. If you have external tools"
    echo "     (Burp Suite, browsers) pointing to the old WSL IP, update them."
    echo ""
    echo "  2. Port forwards break — re-run any netsh port proxy rules:"
    echo "     (Admin PowerShell on Windows)"
    echo ""

    # Show any existing port proxy rules that may need updating
    echo "     # Update all port forwards to new WSL IP:"
    echo "     \$wslIp = (wsl hostname -I).Trim().Split(' ')[0]"
    echo "     echo \"WSL2 IP: \$wslIp\""
    echo ""

    # Show SOCKS ports that need forwarding for Burp
    SOCKS_PORTS=$(docker port node-manager 2>/dev/null | grep -oP '^\d+' | sort -u | head -10)
    if [ -n "$SOCKS_PORTS" ]; then
        echo "     # SOCKS tunnel ports (for Burp on remote machine):"
        for p in $SOCKS_PORTS; do
            [ "$p" = "8027" ] && continue  # skip node-manager API port
            echo "     netsh interface portproxy add v4tov4 listenport=$p listenaddress=0.0.0.0 connectport=$p connectaddress=\$wslIp"
        done
        echo ""
    fi

    echo "     # Dashboard HTTPS:"
    echo "     netsh interface portproxy add v4tov4 listenport=${DASHBOARD_PORT} listenaddress=0.0.0.0 connectport=${DASHBOARD_PORT} connectaddress=\$wslIp"
    echo ""

    echo "  3. Check these settings in the dashboard if IP changed:"
    echo "     - Reports > Proxy Replay > Docker Host IP field"
    echo "     - Reports > Proxy Replay > Burp Proxy URL"
    echo "     - Settings > Burp Suite REST API > BURP_API_URL"
    echo ""
    echo "  4. Verify Docker is running:"
    echo "     docker ps | head -5"
    echo ""
    echo "  5. If containers won't start, try:"
    echo "     docker compose down && docker compose up -d"
    echo ""
    echo "  6. If DB connection fails after restart:"
    echo "     docker compose restart rag-postgres"
    echo "     sleep 5"
    echo "     ./scripts/ensure_db_schema.sh"
    echo ""
    echo "  Quick health check:"
    echo "     curl -sk https://localhost:${DASHBOARD_PORT}/api/health | python3 -m json.tool"
    echo ""
    echo "  Optional profiles (not started by default):"
    echo "     docker compose --profile vault    up -d   # HashiCorp Vault for secrets"
    echo "     docker compose --profile gpu      up -d   # local LLMs (ollama, embedder-gpu)"
    echo "     docker compose --profile optional up -d   # OpenWebUI, vLLM, Kong, Swagger UI"
    echo ""
    echo "  Verify recent changes landed:"
    echo "     ./scripts/post-install-check.sh"
fi
