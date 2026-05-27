#!/bin/bash

# RAG Scan Stack Screenshot Capture Runner
# Installs dependencies and captures presentation screenshots

set -e

echo "📸 RAG Scan Stack Screenshot Capture Setup"
echo "=========================================="

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

# Check if Python 3.8+ is available
check_python() {
    log_info "Checking Python version..."

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        log_success "Found Python $PYTHON_VERSION"

        # Check if version is 3.8+
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            PYTHON_CMD="python3"
            return 0
        else
            log_error "Python 3.8+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        log_error "Python 3 not found. Please install Python 3.8+"
        return 1
    fi
}

# Install required packages
install_dependencies() {
    log_info "Installing Python dependencies..."

    # Check if pip is available
    if ! $PYTHON_CMD -m pip --version &> /dev/null; then
        log_error "pip not available. Please install pip for Python 3"
        return 1
    fi

    # Install playwright and httpx
    log_info "Installing playwright and httpx..."
    $PYTHON_CMD -m pip install --user playwright httpx

    # Install playwright browsers
    log_info "Installing playwright browsers (this may take a few minutes)..."
    $PYTHON_CMD -m playwright install chromium

    log_success "Dependencies installed successfully"
}

# Check if RAG Scan Stack is running
check_platform() {
    log_info "Checking if RAG Scan Stack is accessible..."

    # Test if dashboard is reachable
    if curl -k -s --max-time 10 https://localhost:3002/api/health > /dev/null 2>&1; then
        log_success "Platform is accessible at https://localhost:3002"
        return 0
    else
        log_warning "Platform is not accessible. Trying to start services..."

        # Try to start services if docker-compose.yml exists
        if [ -f "../docker-compose.yml" ]; then
            log_info "Starting RAG Scan Stack services..."
            cd ..
            docker compose up -d
            cd presentation-materials

            # Wait for services to start
            log_info "Waiting for services to start (30 seconds)..."
            sleep 30

            # Test again
            if curl -k -s --max-time 10 https://localhost:3002/api/health > /dev/null 2>&1; then
                log_success "Platform started successfully"
                return 0
            else
                log_error "Platform still not accessible after startup attempt"
                return 1
            fi
        else
            log_error "Platform not accessible and docker-compose.yml not found"
            return 1
        fi
    fi
}

# Run screenshot capture
run_capture() {
    log_info "Starting screenshot capture..."

    # Make script executable
    chmod +x capture-screenshots.py

    # Run the screenshot capture script
    $PYTHON_CMD capture-screenshots.py

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log_success "Screenshot capture completed successfully!"

        # Show captured files
        if [ -d "screenshots" ]; then
            log_info "Captured screenshots:"
            find screenshots -name "*.png" | sort | while read -r file; do
                echo "  📷 $file"
            done

            # Show file sizes
            total_size=$(du -sh screenshots 2>/dev/null | cut -f1)
            file_count=$(find screenshots -name "*.png" | wc -l)
            log_success "Total: $file_count screenshots, $total_size"
        fi

    else
        log_error "Screenshot capture failed with exit code $exit_code"
        return $exit_code
    fi
}

# Show next steps
show_next_steps() {
    echo ""
    echo "🎉 Screenshot capture complete!"
    echo ""
    echo "📋 Next steps:"
    echo "  1. Review screenshots in the 'screenshots/' directory"
    echo "  2. Edit presentation markdown files to reference actual screenshots"
    echo "  3. Convert to presentation format:"
    echo "     pandoc 01-user-guide-features.md -o user-guide.pptx"
    echo "     pandoc 02-management-health.md -o management.pptx"
    echo "     pandoc 03-architecture-overview.md -o architecture.pptx"
    echo ""
    echo "📁 Screenshot index created: screenshots/index.md"
    echo ""
}

# Main execution
main() {
    # Change to script directory
    cd "$(dirname "$0")"

    # Check Python
    if ! check_python; then
        log_error "Python check failed"
        exit 1
    fi

    # Install dependencies
    if ! install_dependencies; then
        log_error "Dependency installation failed"
        exit 1
    fi

    # Check platform availability
    if ! check_platform; then
        log_error "Platform check failed"
        log_info "Please ensure RAG Scan Stack is running:"
        log_info "  cd .. && docker compose up -d"
        exit 1
    fi

    # Run screenshot capture
    if run_capture; then
        show_next_steps
        exit 0
    else
        log_error "Screenshot capture failed"
        exit 1
    fi
}

# Handle interruption
trap 'echo -e "\n\n⏹️  Screenshot capture interrupted"; exit 1' INT

# Run main function
main "$@"