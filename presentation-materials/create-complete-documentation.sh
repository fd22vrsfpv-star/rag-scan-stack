#!/bin/bash
#
# Complete RAG Scan Stack Documentation Generation
# Captures all screenshots and generates comprehensive PDFs
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "📄 RAG Scan Stack - Complete Documentation Generator"
echo "===================================================="

# Check if dashboard is running
log_info "Checking dashboard availability..."

dashboard_running=false
for port in 3001 3002 8080; do
    if curl -s -f "http://localhost:$port" >/dev/null 2>&1 || curl -s -k -f "https://localhost:$port" >/dev/null 2>&1; then
        log_success "Dashboard accessible on port $port"
        dashboard_running=true
        break
    fi
done

if [ "$dashboard_running" = false ]; then
    log_warning "Dashboard not accessible on standard ports"
    log_info "Attempting to start dashboard..."

    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose up -d pentest-dashboard
        log_info "Waiting for dashboard to start..."
        sleep 30
    else
        log_error "Docker Compose not found. Please start the dashboard manually:"
        log_error "  docker compose up -d pentest-dashboard"
        exit 1
    fi
fi

# Step 1: Generate comprehensive presentation materials
log_info "Step 1: Generating comprehensive presentation materials..."
python3 update-presentations-comprehensive.py

# Step 2: Capture all screenshots
log_info "Step 2: Capturing comprehensive screenshots..."
log_warning "This will open a browser window and take screenshots automatically"
log_warning "Please do not interact with the browser during capture"
echo "Press Enter to continue or Ctrl+C to abort..."
read -r

python3 comprehensive-screenshot-capture.py

# Step 3: Check screenshot capture results
log_info "Step 3: Verifying screenshot capture..."

if [ -d "screenshots-complete" ]; then
    screenshot_count=$(find screenshots-complete -name "*.png" | wc -l)
    log_success "Captured $screenshot_count screenshots"

    # List screenshots by category
    for category in screenshots-complete/*/; do
        if [ -d "$category" ]; then
            category_name=$(basename "$category")
            count=$(ls -1 "$category"*.png 2>/dev/null | wc -l)
            log_info "  📁 $category_name: $count screenshots"
        fi
    done
else
    log_error "Screenshot directory not found"
    exit 1
fi

# Step 4: Create clean versions for PDF
log_info "Step 4: Preparing PDF-compatible versions..."

# Create clean directory
mkdir -p presentation-complete-clean

# Clean Unicode characters from comprehensive materials
python3 -c "
import re

def clean_unicode(content):
    # Replace emojis and Unicode with text
    replacements = {
        '✅': '[SUCCESS]', '❌': '[ERROR]', '⚠️': '[WARNING]',
        '📄': '[DOCUMENT]', '🔍': '[SEARCH]', '📊': '[CHART]',
        '🎯': '[TARGET]', '📈': '[GRAPH]', '🔧': '[TOOL]',
        '⚡': '[FAST]', '🚀': '[LAUNCH]', '💡': '[IDEA]',
        '🌐': '[NETWORK]', '📋': '[LIST]', '🎨': '[DESIGN]'
    }

    for emoji, replacement in replacements.items():
        content = content.replace(emoji, replacement)

    # Remove problematic characters
    content = content.encode('ascii', errors='ignore').decode('ascii')
    return content

# Clean both files
for filename in ['01-complete-user-guide.md', '02-complete-architecture.md']:
    try:
        with open(f'presentation-complete/{filename}', 'r') as f:
            content = f.read()

        cleaned = clean_unicode(content)

        with open(f'presentation-complete-clean/{filename}', 'w') as f:
            f.write(cleaned)

        print(f'Cleaned: {filename}')
    except FileNotFoundError:
        print(f'File not found: {filename}')
"

# Step 5: Convert to PDF
log_info "Step 5: Converting to PDF..."

# Check for pandoc
if ! command -v pandoc >/dev/null 2>&1; then
    log_error "Pandoc not found. Please install pandoc:"
    log_error "  Ubuntu/Debian: sudo apt install pandoc texlive-latex-base"
    log_error "  macOS: brew install pandoc basictex"
    exit 1
fi

# Create PDFs directory
mkdir -p pdfs-complete

# Convert comprehensive guides to PDF
for file in presentation-complete-clean/*.md; do
    if [ -f "$file" ]; then
        filename=$(basename "$file" .md)
        output_file="pdfs-complete/${filename}.pdf"

        log_info "Converting $filename to PDF..."

        pandoc "$file" \
            --from markdown \
            --to pdf \
            --output "$output_file" \
            --pdf-engine=pdflatex \
            --variable=geometry:margin=1in \
            --variable=fontsize:11pt \
            --table-of-contents \
            --number-sections \
            --variable=title:"RAG Scan Stack Documentation" \
            2>/dev/null || {
                log_warning "Advanced PDF conversion failed, trying simple version..."
                pandoc "$file" \
                    --from markdown \
                    --to pdf \
                    --output "$output_file" \
                    --table-of-contents \
                    --number-sections
            }

        if [ -f "$output_file" ]; then
            file_size=$(du -h "$output_file" | cut -f1)
            log_success "Created: $output_file ($file_size)"
        else
            log_error "Failed to create: $output_file"
        fi
    fi
done

# Create combined PDF
log_info "Creating combined comprehensive guide..."

cat presentation-complete-clean/*.md > presentation-complete-clean/complete-combined.md

pandoc presentation-complete-clean/complete-combined.md \
    --from markdown \
    --to pdf \
    --output pdfs-complete/RAG-Scan-Stack-Complete-Documentation.pdf \
    --pdf-engine=pdflatex \
    --variable=geometry:margin=1in \
    --variable=fontsize:10pt \
    --table-of-contents \
    --toc-depth=3 \
    --number-sections \
    --variable=title:"RAG Scan Stack - Complete Platform Documentation" \
    2>/dev/null || {
        log_warning "Advanced combined PDF failed, trying simple version..."
        pandoc presentation-complete-clean/complete-combined.md \
            --from markdown \
            --to pdf \
            --output pdfs-complete/RAG-Scan-Stack-Complete-Documentation.pdf \
            --table-of-contents \
            --number-sections
    }

# Step 6: Show results
log_success "Documentation generation complete!"

echo ""
log_info "Generated Documentation:"
echo "========================="

if [ -d "pdfs-complete" ]; then
    cd pdfs-complete
    for file in *.pdf; do
        if [ -f "$file" ]; then
            size=$(du -h "$file" | cut -f1)
            echo "📄 $file ($size)"
        fi
    done
    cd ..
fi

echo ""
log_info "Documentation Structure:"
echo "📁 screenshots-complete/    - All feature screenshots (organized by category)"
echo "📁 presentation-complete/   - Markdown source with screenshots"
echo "📁 presentation-complete-clean/  - PDF-ready versions"
echo "📁 pdfs-complete/           - Final PDF documentation"

echo ""
log_info "Usage Recommendations:"
echo "🎯 Executive Overview: Use individual PDFs for focused discussions"
echo "📚 Technical Reference: Use complete combined PDF for comprehensive documentation"
echo "🖼️  Screenshot Archive: Access screenshots-complete/ for individual images"

echo ""
log_success "RAG Scan Stack documentation ready for distribution!"