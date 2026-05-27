#!/bin/bash
set -e

# RAG Scan Stack - Deployment Script
# This script handles both initial setup and ongoing deployments
#
# Usage:
#   ./scripts/deploy.sh                    # Initial setup
#   ./scripts/deploy.sh --version 2026.05.13-05  # Deploy with version update
#   ./scripts/deploy.sh --rebuild          # Force rebuild without version change
#   ./scripts/deploy.sh --quick            # Quick restart without rebuild

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Parse command line arguments
NEW_VERSION=""
FORCE_REBUILD=false
QUICK_DEPLOY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            NEW_VERSION="$2"
            shift 2
            ;;
        --rebuild)
            FORCE_REBUILD=true
            shift
            ;;
        --quick)
            QUICK_DEPLOY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --version VERSION    Update version and rebuild"
            echo "  --rebuild           Force rebuild without version change"
            echo "  --quick             Quick restart without rebuild"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

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

# Function to update version across all files
update_version() {
    local version=$1
    log_info "Updating version to: $version"

    # Update .env
    if [ -f "$PROJECT_ROOT/.env" ]; then
        sed -i.bak "s/^BUILD_VERSION=.*/BUILD_VERSION=$version/" "$PROJECT_ROOT/.env"
        log_success "Updated .env"
    else
        log_error ".env not found"
        exit 1
    fi

    # Update package.json
    if [ -f "$PROJECT_ROOT/dashboard/frontend/package.json" ]; then
        sed -i.bak "s/\"version\": \".*\"/\"version\": \"$version\"/" "$PROJECT_ROOT/dashboard/frontend/package.json"
        log_success "Updated package.json"
    else
        log_error "package.json not found"
        exit 1
    fi

    # Update constants.ts
    if [ -f "$PROJECT_ROOT/dashboard/frontend/src/lib/constants.ts" ]; then
        sed -i.bak "s/BUILD_VERSION = '.*'/BUILD_VERSION = '$version'/" "$PROJECT_ROOT/dashboard/frontend/src/lib/constants.ts"
        log_success "Updated constants.ts"
    else
        log_error "constants.ts not found"
        exit 1
    fi
}

# Function to build frontend
build_frontend() {
    log_info "Building frontend..."
    cd "$PROJECT_ROOT/dashboard/frontend"
    if [ -f "package.json" ]; then
        npm run build
        log_success "Frontend built successfully"
    else
        log_error "Frontend package.json not found"
        exit 1
    fi
    cd "$PROJECT_ROOT"
}

# Function to fix ETL import paths
fix_etl_imports() {
    log_info "Checking ETL import paths..."
    if [ -f "$PROJECT_ROOT/scripts/fix-etl-imports.sh" ]; then
        $PROJECT_ROOT/scripts/fix-etl-imports.sh > /dev/null 2>&1
        log_success "ETL import paths verified"
    else
        log_warning "ETL import fix script not found"
    fi
}

# Banner
echo "=========================================="
echo "  RAG Scan Stack - Deployment"
echo "=========================================="
if [ ! -z "$NEW_VERSION" ]; then
    echo "  Mode: Version Update ($NEW_VERSION)"
elif [ "$FORCE_REBUILD" = true ]; then
    echo "  Mode: Force Rebuild"
elif [ "$QUICK_DEPLOY" = true ]; then
    echo "  Mode: Quick Restart"
else
    echo "  Mode: Initial Setup"
fi
echo ""

# Check if running from correct directory
if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    log_error "docker-compose.yml not found in $PROJECT_ROOT"
    log_error "Please run this script from the project root or scripts directory"
    exit 1
fi

cd "$PROJECT_ROOT"

# Step 1: Check prerequisites
log_info "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    log_error "Visit: https://docs.docker.com/engine/install/"
    exit 1
fi
log_success "Docker found: $(docker --version)"

# Check Docker Compose
if ! command -v docker compose version &> /dev/null; then
    log_error "Docker Compose v2 is not installed."
    log_error "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi
log_success "Docker Compose found: $(docker compose version)"

# Check for NVIDIA GPU (optional)
if command -v nvidia-smi &> /dev/null; then
    log_success "NVIDIA GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader | head -n1)"

    # Check for nvidia-container-toolkit
    if docker info 2>/dev/null | grep -q "Runtimes.*nvidia"; then
        log_success "NVIDIA Container Toolkit is installed"
    else
        log_warning "NVIDIA GPU detected but nvidia-container-toolkit not found"
        log_warning "Ollama will run in CPU-only mode (slower)"
        log_info "To install: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"
    fi
else
    log_warning "No NVIDIA GPU detected. Ollama will run in CPU-only mode (slower)"
fi

echo ""

# Step 2: Create Docker network
log_info "Creating Docker network 'agents_net'..."
if docker network inspect agents_net &> /dev/null; then
    log_success "Network 'agents_net' already exists"
else
    docker network create agents_net
    log_success "Network 'agents_net' created"
fi

echo ""

# Step 3: Create required directories
log_info "Creating required directories..."

DIRS=(
    "nmap_out"
    "web_reports"
    "nuclei_reports"
    "playwright_screenshots"
    "playwright_reports"
    "autogen_logs"
    "autogen_cache"
    "ollama-data"
    "db_init"
    "etl"
)

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log_success "Created directory: $dir"
    else
        log_info "Directory already exists: $dir"
    fi
done

echo ""

# Step 4: Setup environment configuration
log_info "Setting up environment configuration..."

if [ -f ".env" ]; then
    log_warning ".env file already exists"
    read -p "Do you want to backup and replace it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mv .env .env.backup.$(date +%Y%m%d_%H%M%S)
        log_success "Existing .env backed up"
    else
        log_info "Keeping existing .env file"
    fi
fi

if [ ! -f ".env" ]; then
    if [ -f ".env.production.example" ]; then
        cp .env.production.example .env
        log_success "Created .env from .env.production.example"
        log_warning "IMPORTANT: Edit .env and update all credentials marked with ***CHANGE THIS***"
    else
        log_error ".env.production.example not found"
        exit 1
    fi
fi

echo ""

# Step 5: Setup Kong configuration
log_info "Setting up Kong API Gateway configuration..."

if [ ! -d "kong" ]; then
    log_error "kong directory not found"
    exit 1
fi

if [ -f "kong/kong.yml" ]; then
    log_info "kong/kong.yml already exists"
else
    if [ -f "kong/kong.yml.production.example" ]; then
        cp kong/kong.yml.production.example kong/kong.yml
        log_success "Created kong/kong.yml from template"
    else
        log_warning "kong/kong.yml.production.example not found, using existing kong/kong.yml"
    fi
fi

# Prompt for API key update
echo ""
log_warning "Kong configuration requires API key update"
read -p "Enter your API key (or press Enter to set it later): " API_KEY

if [ ! -z "$API_KEY" ]; then
    # Update API key in .env
    if grep -q "^API_KEY=" .env; then
        sed -i.bak "s/^API_KEY=.*/API_KEY=$API_KEY/" .env
        log_success "Updated API_KEY in .env"
    fi

    # Update API key in kong.yml
    if [ -f "kong/kong.yml" ]; then
        sed -i.bak "s/REPLACE_WITH_YOUR_API_KEY/$API_KEY/g" kong/kong.yml
        sed -i.bak "s/change-me/$API_KEY/g" kong/kong.yml
        log_success "Updated API keys in kong/kong.yml"
    fi
else
    log_warning "Remember to manually update API keys in .env and kong/kong.yml"
fi

echo ""

# Step 6: Check for Ollama models
log_info "Checking Ollama models directory..."

if [ -d "ollama-data" ] && [ "$(ls -A ollama-data)" ]; then
    log_success "Ollama models directory exists and contains data"
    log_info "Models will be available immediately on startup"
else
    log_warning "Ollama models directory is empty"
    log_info "Models will be downloaded on first startup (~8-10GB)"
    log_info "Required models: nomic-embed-text, interstellarninja/hermes-3-llama-3.1-8b-tools"
fi

echo ""

# Step 7: Summary and next steps
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
log_success "All prerequisites checked and directories created"
echo ""
echo "Next steps:"
echo ""
echo "1. ${YELLOW}Update credentials${NC} (if not done yet):"
echo "   - Edit .env and change all passwords/API keys"
echo "   - Edit kong/kong.yml and replace API keys"
echo ""
echo "2. ${YELLOW}Generate secure credentials:${NC}"
echo "   API_KEY:         openssl rand -hex 32"
echo "   ZAP_API_KEY:     openssl rand -hex 32"
echo "   POSTGRES_PASSWORD: openssl rand -base64 32"
echo ""
echo "3. ${YELLOW}Build and start services:${NC}"
echo "   docker compose up -d --build"
echo ""
echo "4. ${YELLOW}Monitor startup:${NC}"
echo "   docker compose logs -f"
echo ""
echo "5. ${YELLOW}Check service health:${NC}"
echo "   docker compose ps"
echo ""
echo "6. ${YELLOW}Access the API Gateway:${NC}"
echo "   http://localhost:7080/docs"
echo ""
echo "=========================================="
echo ""

# Deployment Logic
if [ "$QUICK_DEPLOY" = true ]; then
    log_info "Quick deployment - restarting services..."
    docker compose restart
    log_success "Services restarted!"
elif [ ! -z "$NEW_VERSION" ] || [ "$FORCE_REBUILD" = true ]; then
    # Version update or forced rebuild
    if [ ! -z "$NEW_VERSION" ]; then
        update_version "$NEW_VERSION"
    fi

    build_frontend
    fix_etl_imports

    log_info "Rebuilding and restarting services..."
    docker compose build --no-cache pentest-dashboard
    docker compose up -d

    log_success "Deployment complete with rebuild!"
else
    # Initial setup - ask if user wants to start
    read -p "Do you want to build and start the services now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Building and starting services..."
        docker compose up -d --build

        echo ""
        log_success "Services started!"
    else
        log_info "Setup complete. Run 'docker compose up -d --build' when ready."
        echo ""
        exit 0
    fi
fi

echo ""
log_info "Waiting for services to become healthy..."
sleep 10

docker compose ps

echo ""
log_info "Deployment complete!"
log_info "To view logs: docker compose logs -f"
log_info "To stop services: docker compose down"

echo ""
