#!/bin/bash
# Configure sync scripts with production machine details
# This makes it easy to set up the target machine once

set -e

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  Configure Sync Scripts"
echo "========================================"
echo ""
log_info "This will configure your production machine details for sync scripts"
echo ""

# Get production machine details
read -p "Production machine username: " TARGET_USER
read -p "Production machine IP/hostname: " TARGET_HOST
read -p "Production machine path [/opt/rag-scan-stack]: " TARGET_PATH
TARGET_PATH=${TARGET_PATH:-/opt/rag-scan-stack}

echo ""
log_info "Configuration:"
echo "  User: $TARGET_USER"
echo "  Host: $TARGET_HOST"
echo "  Path: $TARGET_PATH"
echo ""

read -p "Is this correct? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warning "Configuration cancelled"
    exit 0
fi

# Test SSH connection
log_info "Testing SSH connection..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 $TARGET_USER@$TARGET_HOST "echo 2>&1" > /dev/null; then
    log_warning "Cannot connect to $TARGET_USER@$TARGET_HOST without password"
    log_info "You may need to set up SSH key authentication"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
else
    log_success "SSH connection OK!"
fi

# Update scripts
log_info "Updating sync scripts..."

SCRIPTS=(
    "sync-to-prod.sh"
    "watch-and-sync.sh"
    "quick-deploy.sh"
)

for script in "${SCRIPTS[@]}"; do
    SCRIPT_PATH="$SCRIPT_DIR/$script"

    if [ ! -f "$SCRIPT_PATH" ]; then
        log_warning "Script not found: $script"
        continue
    fi

    # Create backup
    cp "$SCRIPT_PATH" "$SCRIPT_PATH.backup"

    # Update configuration
    sed -i.bak "s/^TARGET_USER=.*/TARGET_USER=\"$TARGET_USER\"/" "$SCRIPT_PATH"
    sed -i.bak "s/^TARGET_HOST=.*/TARGET_HOST=\"$TARGET_HOST\"/" "$SCRIPT_PATH"
    sed -i.bak "s|^TARGET_PATH=.*|TARGET_PATH=\"$TARGET_PATH\"|" "$SCRIPT_PATH"
    rm -f "${SCRIPT_PATH}.bak"

    log_success "Updated: $script"
done

echo ""
log_success "Configuration complete!"
echo ""
log_info "You can now use:"
echo "  ./scripts/sync-to-prod.sh          - Sync files to production"
echo "  ./scripts/sync-to-prod.sh --restart - Sync and restart services"
echo "  ./scripts/watch-and-sync.sh        - Auto-sync on file changes"
echo "  ./scripts/quick-deploy.sh          - Full deployment (sync + build + restart)"
echo ""
log_info "Backups saved with .backup extension"
