#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TUNNEL_MANAGER_DIR="${PROJECT_ROOT}/tunnel-manager"

log_info "Building and installing Tunnel Manager..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    log_error "Go is not installed. Please install Go 1.21+ first."
    log_error "Visit: https://golang.org/doc/install"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
MIN_VERSION="1.21"
if [ "$(printf '%s\n' "$MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
    log_error "Go version $GO_VERSION is too old. Please install Go $MIN_VERSION or later."
    exit 1
fi

log_success "Go version: $GO_VERSION"

# Check for required system dependencies
log_info "Checking system dependencies..."

missing_deps=()

if ! command -v autossh &> /dev/null; then
    missing_deps+=("autossh")
fi

if ! command -v ssh &> /dev/null; then
    missing_deps+=("openssh-client")
fi

if ! command -v wg &> /dev/null; then
    log_warning "WireGuard tools not found - WireGuard functionality will be limited"
    log_info "Install with: sudo apt install wireguard-tools"
fi

if [ ${#missing_deps[@]} -ne 0 ]; then
    log_error "Missing required dependencies: ${missing_deps[*]}"
    log_error "Install with: sudo apt install ${missing_deps[*]}"
    exit 1
fi

log_success "System dependencies check passed"

# Build the tunnel manager
log_info "Building tunnel manager..."
cd "${TUNNEL_MANAGER_DIR}"

# Download dependencies
log_info "Downloading Go dependencies..."
go mod download

# Build for Linux (including WSL2)
log_info "Compiling tunnel manager binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o tunnel-manager .

if [ ! -f "tunnel-manager" ]; then
    log_error "Build failed - binary not found"
    exit 1
fi

log_success "Build completed successfully"

# Install binary
log_info "Installing tunnel manager binary..."
sudo cp tunnel-manager /usr/local/bin/tunnel-manager
sudo chmod +x /usr/local/bin/tunnel-manager
sudo chown root:root /usr/local/bin/tunnel-manager

# Create directories
log_info "Creating configuration directories..."
sudo mkdir -p /etc/tunnel-manager/ssh-keys
sudo mkdir -p /etc/tunnel-manager/wireguard
sudo mkdir -p /var/lib/tunnel-manager
sudo mkdir -p /var/log/tunnel-manager

# Set permissions
sudo chmod 700 /etc/tunnel-manager/ssh-keys
sudo chmod 755 /etc/tunnel-manager/wireguard
sudo chmod 755 /var/lib/tunnel-manager

# Copy SSH keys from existing location if they exist
if [ -d "${PROJECT_ROOT}/ssh-keys" ]; then
    log_info "Copying SSH keys..."
    sudo cp -r "${PROJECT_ROOT}/ssh-keys"/* /etc/tunnel-manager/ssh-keys/ 2>/dev/null || true
    sudo chmod 600 /etc/tunnel-manager/ssh-keys/* 2>/dev/null || true
fi

# Install configuration file if it doesn't exist
if [ ! -f "/etc/tunnel-manager/config.yaml" ]; then
    log_info "Installing default configuration..."
    sudo cp config.yaml.example /etc/tunnel-manager/config.yaml

    # Update database URL from .env if available
    if [ -f "${PROJECT_ROOT}/.env" ]; then
        DB_DSN=$(grep "^DB_DSN=" "${PROJECT_ROOT}/.env" | cut -d'=' -f2-)
        if [ -n "$DB_DSN" ]; then
            sudo sed -i "s|database_url: .*|database_url: \"$DB_DSN\"|" /etc/tunnel-manager/config.yaml
            log_info "Updated database URL from .env file"
        fi
    fi
else
    log_info "Configuration file already exists, skipping"
fi

# Install systemd service
log_info "Installing systemd service..."
sudo cp tunnel-manager.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable but don't start yet
sudo systemctl enable tunnel-manager

log_success "Tunnel manager installed successfully!"

# Show status
echo ""
echo "=========================================="
echo "  Installation Complete"
echo "=========================================="
echo ""
log_success "Binary installed: /usr/local/bin/tunnel-manager"
log_success "Configuration: /etc/tunnel-manager/config.yaml"
log_success "SSH keys: /etc/tunnel-manager/ssh-keys/"
log_success "Service enabled: tunnel-manager.service"
echo ""
echo "Next steps:"
echo ""
echo "1. ${YELLOW}Review configuration:${NC}"
echo "   sudo nano /etc/tunnel-manager/config.yaml"
echo ""
echo "2. ${YELLOW}Copy SSH keys:${NC}"
echo "   sudo cp your_key.pem /etc/tunnel-manager/ssh-keys/"
echo ""
echo "3. ${YELLOW}Start the service:${NC}"
echo "   sudo systemctl start tunnel-manager"
echo ""
echo "4. ${YELLOW}Check service status:${NC}"
echo "   sudo systemctl status tunnel-manager"
echo ""
echo "5. ${YELLOW}Check API health:${NC}"
echo "   curl http://localhost:8027/health"
echo ""
echo "6. ${YELLOW}View logs:${NC}"
echo "   sudo journalctl -u tunnel-manager -f"
echo ""
echo "=========================================="

# Clean up build artifacts
cd "${TUNNEL_MANAGER_DIR}"
rm -f tunnel-manager

log_info "Build artifacts cleaned up"
log_success "Installation script completed successfully!"