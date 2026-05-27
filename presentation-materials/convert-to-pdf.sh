#!/bin/bash

# Convert RAG Scan Stack presentation materials to PDF
# Supports both individual PDFs and combined presentation

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

echo "📄 RAG Scan Stack - PDF Conversion Tool"
echo "======================================"

# Check if pandoc is installed
check_pandoc() {
    log_info "Checking for pandoc..."

    if command -v pandoc &> /dev/null; then
        PANDOC_VERSION=$(pandoc --version | head -n1)
        log_success "Found $PANDOC_VERSION"
        return 0
    else
        log_error "Pandoc not found. Installing..."

        # Try to install pandoc
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y pandoc texlive-latex-base texlive-fonts-recommended texlive-extra-utils texlive-latex-extra
        elif command -v dnf &> /dev/null; then
            dnf install -y pandoc texlive-latex-base texlive-fonts-recommended
        elif command -v brew &> /dev/null; then
            brew install pandoc basictex
        else
            log_error "Cannot install pandoc automatically. Please install manually:"
            log_error "  Ubuntu/Debian: sudo apt-get install pandoc texlive-latex-base texlive-fonts-recommended"
            log_error "  macOS: brew install pandoc basictex"
            return 1
        fi

        if command -v pandoc &> /dev/null; then
            log_success "Pandoc installed successfully"
            return 0
        else
            return 1
        fi
    fi
}

# Convert individual markdown file to PDF
convert_single_pdf() {
    local input_file="$1"
    local output_file="$2"
    local title="$3"

    log_info "Converting $input_file to $output_file..."

    # Create pandoc command with professional styling
    pandoc "$input_file" \
        --from markdown \
        --to pdf \
        --output "$output_file" \
        --pdf-engine=pdflatex \
        --variable=geometry:margin=1in \
        --variable=fontsize:11pt \
        --variable=documentclass:article \
        --variable=title:"$title" \
        --variable=author:"RAG Scan Stack" \
        --variable=date:"$(date '+%B %d, %Y')" \
        --table-of-contents \
        --toc-depth=2 \
        --number-sections \
        --highlight-style=github \
        --include-in-header=<(echo '\usepackage{fancyhdr}') \
        --include-in-header=<(echo '\pagestyle{fancy}') \
        --include-in-header=<(echo '\fancyhead[L]{RAG Scan Stack}') \
        --include-in-header=<(echo '\fancyhead[R]{\thepage}') \
        --include-in-header=<(echo '\fancyfoot[C]{}') \
        2>/dev/null || {

        # Fallback to simpler conversion if fancy styling fails
        log_warning "Advanced styling failed, trying simple conversion..."
        pandoc "$input_file" \
            --from markdown \
            --to pdf \
            --output "$output_file" \
            --pdf-engine=pdflatex \
            --variable=geometry:margin=1in \
            --table-of-contents \
            --number-sections
    }

    if [ -f "$output_file" ]; then
        local file_size=$(du -h "$output_file" | cut -f1)
        log_success "Created $output_file ($file_size)"
        return 0
    else
        log_error "Failed to create $output_file"
        return 1
    fi
}

# Create slide-style PDF using beamer
convert_slides_pdf() {
    local input_file="$1"
    local output_file="$2"
    local title="$3"

    log_info "Converting $input_file to slides: $output_file..."

    pandoc "$input_file" \
        --from markdown \
        --to beamer \
        --output "$output_file" \
        --pdf-engine=pdflatex \
        --variable=theme:Madrid \
        --variable=colortheme:default \
        --variable=fonttheme:structurebold \
        --variable=title:"$title" \
        --variable=author:"RAG Scan Stack Platform" \
        --variable=date:"$(date '+%B %d, %Y')" \
        --variable=institute:"Security Testing Framework" \
        --slide-level=2 \
        2>/dev/null || {

        log_warning "Beamer slides failed, creating standard PDF instead..."
        convert_single_pdf "$input_file" "$output_file" "$title"
    }
}

# Create combined PDF with all materials
create_combined_pdf() {
    log_info "Creating combined presentation PDF..."

    # Create temporary combined markdown file
    local temp_file="temp_combined.md"
    local output_file="RAG-Scan-Stack-Complete-Guide.pdf"

    cat > "$temp_file" <<EOF
% RAG Scan Stack - Complete Platform Guide
% Security Testing & Red Team Framework
% $(date '+%B %d, %Y')

\newpage
\tableofcontents
\newpage

EOF

    # Add each guide with page breaks
    echo "# User Guide & Features Overview" >> "$temp_file"
    echo "" >> "$temp_file"
    tail -n +2 "01-user-guide-features.md" >> "$temp_file"
    echo "" >> "$temp_file"
    echo "\\newpage" >> "$temp_file"
    echo "" >> "$temp_file"

    echo "# Management & Health Monitoring" >> "$temp_file"
    echo "" >> "$temp_file"
    tail -n +2 "02-management-health.md" >> "$temp_file"
    echo "" >> "$temp_file"
    echo "\\newpage" >> "$temp_file"
    echo "" >> "$temp_file"

    echo "# Simple Architecture" >> "$temp_file"
    echo "" >> "$temp_file"
    tail -n +2 "03-architecture-simple.md" >> "$temp_file"

    # Convert combined file
    pandoc "$temp_file" \
        --from markdown \
        --to pdf \
        --output "$output_file" \
        --pdf-engine=pdflatex \
        --variable=geometry:margin=1in \
        --variable=fontsize:10pt \
        --variable=documentclass:report \
        --table-of-contents \
        --toc-depth=3 \
        --number-sections \
        --highlight-style=github \
        2>/dev/null || {

        log_warning "Advanced combined PDF failed, trying simple version..."
        pandoc "$temp_file" \
            --from markdown \
            --to pdf \
            --output "$output_file" \
            --table-of-contents \
            --number-sections
    }

    # Cleanup
    rm -f "$temp_file"

    if [ -f "$output_file" ]; then
        local file_size=$(du -h "$output_file" | cut -f1)
        log_success "Created combined guide: $output_file ($file_size)"
        return 0
    else
        log_error "Failed to create combined PDF"
        return 1
    fi
}

# Main conversion function
convert_presentations() {
    log_info "Starting PDF conversion process..."

    # Create output directory
    mkdir -p pdfs

    local success_count=0
    local total_count=0

    # Convert individual guides
    presentations=(
        "01-user-guide-features.md|pdfs/01-User-Guide-Features.pdf|RAG Scan Stack - User Guide & Features"
        "02-management-health.md|pdfs/02-Management-Health.pdf|RAG Scan Stack - Management & Health Monitoring"
        "03-architecture-simple.md|pdfs/03-Architecture-Simple.pdf|RAG Scan Stack - Simple Architecture"
    )

    for presentation in "${presentations[@]}"; do
        IFS='|' read -r input_file output_file title <<< "$presentation"

        if [ -f "$input_file" ]; then
            total_count=$((total_count + 1))
            if convert_single_pdf "$input_file" "$output_file" "$title"; then
                success_count=$((success_count + 1))
            fi
        else
            log_warning "Input file not found: $input_file"
        fi
    done

    # Create slide versions if requested
    if [ "$1" = "--slides" ] || [ "$1" = "--all" ]; then
        log_info "Creating slide versions..."

        slide_presentations=(
            "01-user-guide-features.md|pdfs/01-User-Guide-Slides.pdf|User Guide & Features"
            "02-management-health.md|pdfs/02-Management-Slides.pdf|Management & Health"
            "03-architecture-simple.md|pdfs/03-Architecture-Slides.pdf|Simple Architecture"
        )

        for presentation in "${slide_presentations[@]}"; do
            IFS='|' read -r input_file output_file title <<< "$presentation"

            if [ -f "$input_file" ]; then
                total_count=$((total_count + 1))
                if convert_slides_pdf "$input_file" "$output_file" "$title"; then
                    success_count=$((success_count + 1))
                fi
            fi
        done
    fi

    # Create combined PDF
    if [ "$1" = "--combined" ] || [ "$1" = "--all" ]; then
        total_count=$((total_count + 1))
        if create_combined_pdf; then
            success_count=$((success_count + 1))
        fi
    fi

    return 0
}

# Show results and next steps
show_results() {
    echo ""
    log_success "PDF conversion completed!"

    if [ -d "pdfs" ]; then
        echo ""
        log_info "Generated PDFs:"
        find pdfs -name "*.pdf" -exec ls -lh {} \; | awk '{print "  📄 " $9 " (" $5 ")"}'

        # Show combined PDF if it exists
        if [ -f "RAG-Scan-Stack-Complete-Guide.pdf" ]; then
            local combined_size=$(du -h "RAG-Scan-Stack-Complete-Guide.pdf" | cut -f1)
            echo "  📄 RAG-Scan-Stack-Complete-Guide.pdf ($combined_size) - Complete Guide"
        fi
    fi

    echo ""
    log_info "Usage examples:"
    echo "  📊 Present to executives: Use individual PDFs for focused discussions"
    echo "  📖 Technical documentation: Use combined PDF for comprehensive reference"
    echo "  🎯 Conference slides: Use slide versions for presentation format"
    echo ""
    log_info "Next steps:"
    echo "  1. Review PDFs in pdfs/ directory"
    echo "  2. Customize styling by editing this script"
    echo "  3. Print or share as needed"
    echo "  4. Re-run script when content updates"
}

# Parse command line arguments
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --slides     Create slide-format PDFs using Beamer"
    echo "  --combined   Create single combined PDF with all materials"
    echo "  --all        Create all formats (documents, slides, combined)"
    echo "  --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Create standard document PDFs"
    echo "  $0 --slides          # Create presentation slides"
    echo "  $0 --combined        # Create combined reference guide"
    echo "  $0 --all             # Create everything"
}

# Main execution
main() {
    # Change to script directory
    cd "$(dirname "$0")"

    # Parse arguments
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --slides|--combined|--all)
            MODE="$1"
            ;;
        "")
            MODE="--standard"
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac

    # Check dependencies
    if ! check_pandoc; then
        log_error "Cannot proceed without pandoc"
        exit 1
    fi

    # Run conversion
    if convert_presentations "$MODE"; then
        show_results
        exit 0
    else
        log_error "PDF conversion failed"
        exit 1
    fi
}

# Handle interruption
trap 'echo -e "\n\n⏹️  PDF conversion interrupted"; exit 1' INT

# Run main function
main "$@"