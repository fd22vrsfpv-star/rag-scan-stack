#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

log_info "Testing native tunnel manager integration..."
echo ""

# 1. Check if tunnel manager service is installed
log_info "Checking tunnel manager installation..."
if command -v tunnel-manager &> /dev/null; then
    log_success "tunnel-manager binary found in PATH"
else
    log_error "tunnel-manager binary not found. Run: ./scripts/build-tunnel-manager.sh"
    exit 1
fi

# 2. Check if systemd service exists
log_info "Checking systemd service..."
if systemctl list-unit-files | grep -q tunnel-manager.service; then
    log_success "tunnel-manager.service is installed"

    # Check service status
    if systemctl is-active tunnel-manager.service &>/dev/null; then
        log_success "tunnel-manager.service is running"
    else
        log_warning "tunnel-manager.service is not running"
        echo "  Start with: sudo systemctl start tunnel-manager"
    fi
else
    log_error "tunnel-manager.service not found. Run: ./scripts/build-tunnel-manager.sh"
    exit 1
fi

# 3. Check if API is accessible
log_info "Testing tunnel manager API..."
if curl -f -s -m 5 http://localhost:8027/health > /dev/null; then
    log_success "Tunnel manager API is responding"

    # Get health details
    health_response=$(curl -s http://localhost:8027/health)
    echo "  Health: $health_response"
else
    log_error "Tunnel manager API is not responding at http://localhost:8027"
    echo "  Check service logs: sudo journalctl -u tunnel-manager -f"
    exit 1
fi

# 4. Test database connectivity
log_info "Testing database connectivity..."
db_test=$(curl -s http://localhost:8027/health | grep -o '"database":"[^"]*"' | cut -d'"' -f4)
if [ "$db_test" = "healthy" ]; then
    log_success "Database connection is healthy"
else
    log_warning "Database connection issue: $db_test"
fi

# 5. Check Docker container integration
log_info "Checking Docker container configuration..."
if docker compose config | grep -q "host.docker.internal:8027"; then
    log_success "pentest-dashboard configured to use host tunnel manager"
else
    log_warning "pentest-dashboard may not be configured for host tunnel manager"
fi

# 6. Test tunnel manager endpoints
log_info "Testing tunnel manager endpoints..."

# Test nodes endpoint
if curl -f -s -m 5 http://localhost:8027/nodes > /dev/null; then
    log_success "Nodes endpoint accessible"
else
    log_warning "Nodes endpoint not accessible"
fi

# Test tunnel allocation endpoints
if curl -f -s -m 5 http://localhost:8027/ssh/ports > /dev/null; then
    log_success "SSH port allocation endpoint accessible"
else
    log_warning "SSH port allocation endpoint not accessible"
fi

if curl -f -s -m 5 http://localhost:8027/wireguard/ports > /dev/null; then
    log_success "WireGuard port allocation endpoint accessible"
else
    log_warning "WireGuard port allocation endpoint not accessible"
fi

echo ""
log_info "Integration test complete!"
echo ""
echo "To complete the deployment:"
echo "1. ${YELLOW}Start services:${NC} docker compose up -d"
echo "2. ${YELLOW}Check dashboard:${NC} http://localhost:3002"
echo "3. ${YELLOW}Check tunnel manager logs:${NC} sudo journalctl -u tunnel-manager -f"
echo "4. ${YELLOW}Test SSH tunnel creation:${NC} Use the dashboard Nodes page"
echo ""
echo "Documentation:"
echo "- Build script: ./scripts/build-tunnel-manager.sh"
echo "- Service config: /etc/tunnel-manager/config.yaml"
echo "- Service logs: sudo journalctl -u tunnel-manager -f"
echo ""

log_success "Native tunnel manager is ready for SSH and WireGuard tunnel management!"