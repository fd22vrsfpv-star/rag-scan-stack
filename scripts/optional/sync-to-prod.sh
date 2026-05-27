#!/bin/bash
# Sync code from development WSL to production WSL machine
# Usage: ./scripts/sync-to-prod.sh [--restart] [--build]

set -e

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================

# Production machine details
TARGET_USER="root"                   # Username on production machine
TARGET_HOST="192.168.1.135"          # IP or hostname of production machine
TARGET_PATH="/opt/rag-scan-stack"    # Path on production machine

# SSH Key (optional - leave empty to use default or SSH config)
SSH_KEY=""                           # Example: ~/.ssh/id_ed25519_rag
SSH_OPTS=""                          # Additional SSH options

# Build SSH options if key is specified
if [ ! -z "$SSH_KEY" ]; then
    SSH_OPTS="-i $SSH_KEY -o IdentitiesOnly=yes"
fi

# Source path (auto-detected, but you can override)
SOURCE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ============================================
# SCRIPT START
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
RESTART_SERVICES=false
BUILD_SERVICES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --restart)
            RESTART_SERVICES=true
            shift
            ;;
        --build)
            BUILD_SERVICES=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --restart    Restart Docker services after sync"
            echo "  --build      Rebuild Docker images before restart"
            echo "  --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Just sync files"
            echo "  $0 --restart          # Sync and restart services"
            echo "  $0 --restart --build  # Sync, rebuild, and restart"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Banner
echo "========================================"
echo "  Sync to Production"
echo "========================================"
echo ""

# Configuration check
log_info "Configuration:"
echo "  Source: $SOURCE_PATH"
echo "  Target: $TARGET_USER@$TARGET_HOST:$TARGET_PATH"
echo ""

if [ "$TARGET_USER" = "your_username" ] || [ "$TARGET_HOST" = "192.168.1.100" ]; then
    log_error "Please update TARGET_USER and TARGET_HOST in the script!"
    log_info "Edit: scripts/sync-to-prod.sh"
    exit 1
fi

# Test SSH connection
log_info "Testing SSH connection..."
if ! ssh $SSH_OPTS -o BatchMode=yes -o ConnectTimeout=5 $TARGET_USER@$TARGET_HOST "echo 2>&1" > /dev/null; then
    log_error "Cannot connect to $TARGET_USER@$TARGET_HOST"
    log_info "Make sure SSH is configured and you can connect without password"
    log_info "Try: ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST"
    exit 1
fi
log_success "SSH connection OK"

# Check if target directory exists
log_info "Checking target directory..."
if ! ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST "[ -d $TARGET_PATH ]"; then
    log_warning "Target directory $TARGET_PATH does not exist"
    read -p "Create it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST "mkdir -p $TARGET_PATH"
        log_success "Created $TARGET_PATH"
    else
        log_error "Cannot sync to non-existent directory"
        exit 1
    fi
fi
log_success "Target directory OK"

# Perform sync
echo ""
log_info "Syncing files..."
log_warning "This may take a few minutes depending on file size and network speed"
echo ""

rsync -avz --progress \
  -e "ssh $SSH_OPTS" \
  --exclude '.git/' \
  --exclude '.idea/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '*.pyo' \
  --exclude '.env' \
  --exclude 'ollama-data/' \
  --exclude 'nmap_out/' \
  --exclude 'web_reports/' \
  --exclude 'nuclei_reports/' \
  --exclude 'playwright_screenshots/' \
  --exclude 'playwright_reports/' \
  --exclude 'autogen_logs/' \
  --exclude 'autogen_cache/' \
  --exclude '*.log' \
  --exclude 'n8n/.n8n/' \
  --exclude 'n8n/database.sqlite' \
  --exclude '*.sqlite' \
  --exclude '.claude/' \
  --exclude '.mcp.json' \
  --exclude 'claude_desktop_config*.json' \
  --exclude '*:Zone.Identifier' \
  --exclude 'C:\Users\*' \
  "$SOURCE_PATH/" \
  "$TARGET_USER@$TARGET_HOST:$TARGET_PATH/"

if [ $? -eq 0 ]; then
    log_success "Files synced successfully!"
else
    log_error "Sync failed!"
    exit 1
fi

# Restart services if requested
if [ "$RESTART_SERVICES" = true ]; then
    echo ""
    log_info "Restarting Docker services on production..."

    # Determine if we need to use sudo
    DOCKER_CMD="cd $TARGET_PATH && docker compose"
    if [ "$TARGET_USER" != "root" ]; then
        log_info "Non-root user detected, using sudo..."
        DOCKER_CMD="cd $TARGET_PATH && sudo docker compose"
    fi

    if [ "$BUILD_SERVICES" = true ]; then
        log_info "Building Docker images..."
        ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST "$DOCKER_CMD up -d --build"
    else
        log_info "Restarting without rebuild..."
        ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST "$DOCKER_CMD up -d"
    fi

    if [ $? -eq 0 ]; then
        log_success "Services restarted!"
        echo ""
        log_info "Checking service status..."
        ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST "$DOCKER_CMD ps"
    else
        log_error "Failed to restart services"
        exit 1
    fi
else
    echo ""
    log_info "To restart services on production, run:"
    if [ "$TARGET_USER" != "root" ]; then
        echo "  ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST 'cd $TARGET_PATH && sudo docker compose up -d --build'"
    else
        echo "  ssh $SSH_OPTS $TARGET_USER@$TARGET_HOST 'cd $TARGET_PATH && docker compose up -d --build'"
    fi
fi

echo ""
log_success "Sync complete!"
