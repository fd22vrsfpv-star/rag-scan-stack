#!/bin/bash
# Quick deployment to production - sync and restart in one command
# Usage: ./scripts/quick-deploy.sh [service-name]

set -e

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================

TARGET_USER="root"
TARGET_HOST="192.168.1.135"
TARGET_PATH="/opt/rag-scan-stack"

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

SERVICE_NAME=""

# Parse arguments
if [ $# -eq 1 ]; then
    SERVICE_NAME=$1
    log_info "Will deploy only: $SERVICE_NAME"
elif [ $# -gt 1 ]; then
    log_error "Usage: $0 [service-name]"
    exit 1
fi

# Configuration check
if [ "$TARGET_USER" = "your_username" ] || [ "$TARGET_HOST" = "192.168.1.100" ]; then
    log_error "Please update TARGET_USER and TARGET_HOST in the script!"
    log_info "Edit: scripts/quick-deploy.sh"
    exit 1
fi

echo "========================================"
echo "  Quick Deploy to Production"
echo "========================================"
echo ""

# Step 1: Sync files
log_info "Step 1/3: Syncing files..."
./scripts/sync-to-prod.sh
echo ""

# Step 2: Build
log_info "Step 2/3: Building Docker images..."
if [ -z "$SERVICE_NAME" ]; then
    ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose build"
else
    ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose build $SERVICE_NAME"
fi
echo ""

# Step 3: Restart
log_info "Step 3/3: Restarting services..."
if [ -z "$SERVICE_NAME" ]; then
    ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose up -d"
else
    ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose up -d --no-deps $SERVICE_NAME"
fi
echo ""

# Show status
log_success "Deployment complete!"
echo ""
log_info "Service status:"
ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose ps"

echo ""
log_info "View logs:"
if [ -z "$SERVICE_NAME" ]; then
    echo "  ssh $TARGET_USER@$TARGET_HOST 'cd $TARGET_PATH && docker compose logs -f'"
else
    echo "  ssh $TARGET_USER@$TARGET_HOST 'cd $TARGET_PATH && docker compose logs -f $SERVICE_NAME'"
fi
