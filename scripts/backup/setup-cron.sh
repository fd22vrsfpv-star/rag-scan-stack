#!/bin/bash
#
# setup-cron.sh - Setup Automated Backup Cron Jobs
#
# This script configures cron jobs for automated backups of the RAG Scan Stack.
# It will add the recommended backup schedule to the current user's crontab.
#
# Usage:
#   ./setup-cron.sh [--remove] [--list]
#
# Options:
#   --remove    Remove backup cron jobs
#   --list      List current backup cron jobs
#   --help      Show this help message
#
# Author: RAG Scan Stack Operations Team
# Version: 1.0
# Last Updated: 2025-11-19

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Cron marker for identification
CRON_MARKER="# RAG Scan Stack - Automated Backups"

# Function to show usage
usage() {
    cat <<EOF
Usage: $0 [options]

Setup automated backup cron jobs for RAG Scan Stack.

Options:
  --remove    Remove all backup cron jobs
  --list      List current backup cron jobs
  --help      Show this help message

Default behavior (no options): Add/update backup cron jobs

Examples:
  $0                  # Setup cron jobs
  $0 --list           # View current jobs
  $0 --remove         # Remove all backup jobs
EOF
}

# Function to list current backup cron jobs
list_cron_jobs() {
    echo -e "${BLUE}Current backup cron jobs:${NC}"
    echo ""

    if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        crontab -l 2>/dev/null | sed -n "/$CRON_MARKER/,/^$/p"
    else
        echo "No backup cron jobs found."
    fi
}

# Function to remove backup cron jobs
remove_cron_jobs() {
    echo -e "${YELLOW}Removing backup cron jobs...${NC}"

    if ! crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo "No backup cron jobs found to remove."
        return 0
    fi

    # Remove lines between marker and next empty line
    crontab -l 2>/dev/null | \
        sed "/$CRON_MARKER/,/^$/d" | \
        crontab -

    echo -e "${GREEN}✓ Backup cron jobs removed${NC}"
}

# Function to setup cron jobs
setup_cron_jobs() {
    echo "=========================================="
    echo "RAG Scan Stack - Backup Cron Setup"
    echo "=========================================="
    echo ""

    # Check if scripts exist
    local missing_scripts=0
    for script in backup-postgres.sh backup-full.sh backup-volumes.sh; do
        if [ ! -f "$SCRIPT_DIR/$script" ]; then
            echo -e "${RED}✗ Error: Script not found: $script${NC}"
            missing_scripts=$((missing_scripts + 1))
        fi
    done

    if [ $missing_scripts -gt 0 ]; then
        echo -e "${RED}Cannot proceed - missing backup scripts${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All backup scripts found${NC}"
    echo ""

    # Check if backup directory exists
    if [ -f "$PROJECT_ROOT/.backup-config.env" ]; then
        # shellcheck source=/dev/null
        source "$PROJECT_ROOT/.backup-config.env"
        BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/backups}"
    else
        BACKUP_BASE_DIR="/backups"
    fi

    if [ ! -d "$BACKUP_BASE_DIR" ]; then
        echo -e "${YELLOW}⚠️  Backup directory does not exist: $BACKUP_BASE_DIR${NC}"
        read -p "Create it now? (y/n): " response
        if [ "$response" = "y" ] || [ "$response" = "yes" ]; then
            sudo mkdir -p "$BACKUP_BASE_DIR"
            sudo chown $(whoami):$(whoami) "$BACKUP_BASE_DIR"
            echo -e "${GREEN}✓ Backup directory created${NC}"
        else
            echo -e "${RED}Cannot proceed without backup directory${NC}"
            exit 1
        fi
    fi

    echo -e "${GREEN}✓ Backup directory exists: $BACKUP_BASE_DIR${NC}"
    echo ""

    # Remove existing backup cron jobs if present
    if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo -e "${YELLOW}Existing backup cron jobs found - will be replaced${NC}"
        remove_cron_jobs
        echo ""
    fi

    # Create log directory
    sudo mkdir -p /var/log/rag-backup
    sudo chown $(whoami):$(whoami) /var/log/rag-backup

    # Prepare new cron entries
    echo "Adding cron jobs..."
    echo ""
    echo "Proposed schedule:"
    echo "  - Hourly database backup"
    echo "  - Daily full backup at 2:00 AM"
    echo "  - Weekly volume backup on Sundays at 3:00 AM"
    echo ""

    read -p "Proceed with this schedule? (y/n): " response
    if [ "$response" != "y" ] && [ "$response" != "yes" ]; then
        echo "Setup cancelled."
        exit 0
    fi

    # Get current crontab (if any)
    crontab -l 2>/dev/null > /tmp/crontab.tmp || echo "" > /tmp/crontab.tmp

    # Add new cron jobs
    cat >> /tmp/crontab.tmp <<EOF

$CRON_MARKER
# Hourly PostgreSQL backup (low overhead)
0 * * * * $SCRIPT_DIR/backup-postgres.sh >> /var/log/rag-backup/postgres.log 2>&1

# Daily full backup at 2 AM (off-peak hours)
0 2 * * * $SCRIPT_DIR/backup-full.sh >> /var/log/rag-backup/full.log 2>&1

# Weekly volume backup on Sundays at 3 AM
0 3 * * 0 $SCRIPT_DIR/backup-volumes.sh >> /var/log/rag-backup/volumes.log 2>&1

EOF

    # Install new crontab
    crontab /tmp/crontab.tmp
    rm /tmp/crontab.tmp

    echo -e "${GREEN}✓ Cron jobs installed successfully!${NC}"
    echo ""
    echo "=========================================="
    echo "Setup Complete"
    echo "=========================================="
    echo ""
    echo "Cron jobs have been added:"
    list_cron_jobs
    echo ""
    echo "Log files will be stored in:"
    echo "  - /var/log/rag-backup/postgres.log"
    echo "  - /var/log/rag-backup/full.log"
    echo "  - /var/log/rag-backup/volumes.log"
    echo ""
    echo "Next scheduled backups:"
    echo "  - Postgres: $(date -d 'next hour' +'%Y-%m-%d %H:00:00')"
    echo "  - Full: $(date -d 'tomorrow 02:00' +'%Y-%m-%d %H:00:00')"
    echo "  - Volumes: $(date -d 'next sunday 03:00' +'%Y-%m-%d %H:00:00')"
    echo ""
    echo -e "${BLUE}To view cron jobs:${NC} $0 --list"
    echo -e "${BLUE}To remove cron jobs:${NC} $0 --remove"
    echo -e "${BLUE}To view logs:${NC} tail -f /var/log/rag-backup/*.log"
    echo ""
}

# Function to verify cron setup
verify_setup() {
    echo ""
    echo "Verifying cron setup..."
    echo ""

    # Check if cron daemon is running
    if systemctl is-active --quiet cron || systemctl is-active --quiet crond; then
        echo -e "${GREEN}✓ Cron daemon is running${NC}"
    else
        echo -e "${RED}✗ Cron daemon is not running${NC}"
        echo "  Start it with: sudo systemctl start cron"
        return 1
    fi

    # Check if cron jobs are installed
    if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo -e "${GREEN}✓ Backup cron jobs are installed${NC}"
        local job_count=$(crontab -l 2>/dev/null | grep "$SCRIPT_DIR/backup" | wc -l)
        echo "  Found $job_count backup job(s)"
    else
        echo -e "${YELLOW}⚠️  No backup cron jobs found${NC}"
        return 1
    fi

    # Check if log directory exists and is writable
    if [ -d /var/log/rag-backup ] && [ -w /var/log/rag-backup ]; then
        echo -e "${GREEN}✓ Log directory is writable${NC}"
    else
        echo -e "${RED}✗ Log directory issue${NC}"
        return 1
    fi

    echo ""
    echo -e "${GREEN}✓ Cron setup verification passed!${NC}"
    return 0
}

# Main execution
main() {
    # Parse arguments
    case "${1:-}" in
        --help|-h)
            usage
            exit 0
            ;;
        --list|-l)
            list_cron_jobs
            exit 0
            ;;
        --remove|-r)
            remove_cron_jobs
            exit 0
            ;;
        --verify|-v)
            verify_setup
            exit $?
            ;;
        "")
            setup_cron_jobs
            verify_setup
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
