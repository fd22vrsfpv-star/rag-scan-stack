#!/bin/bash
#
# backup-full.sh - Complete System Backup Script
#
# This script performs a complete backup of the RAG Scan Stack including:
# - PostgreSQL databases
# - Docker volumes
# - Scan result files
# - Configuration files
#
# Usage:
#   ./backup-full.sh
#
# Configuration: Set environment variables in .backup-config.env
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

# Load configuration
if [ -f "$PROJECT_ROOT/.backup-config.env" ]; then
    # shellcheck source=/dev/null
    source "$PROJECT_ROOT/.backup-config.env"
else
    echo -e "${YELLOW}⚠️  Warning: .backup-config.env not found, using defaults${NC}"
fi

# Configuration with defaults
BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
ENABLE_S3_UPLOAD="${ENABLE_S3_UPLOAD:-false}"
S3_BUCKET="${S3_BUCKET:-}"

# Directories to backup
SCAN_DATA_DIRS=(
    "nmap_out"
    "web_reports"
    "nuclei_reports"
    "playwright_screenshots"
)

CONFIG_FILES=(
    ".env"
    "docker-compose.yml"
    "kong/kong.yml"
    ".backup-config.env"
)

# Create backup directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE_DIR/full/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

# Logging
LOG_FILE="$BACKUP_DIR/backup-full.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

START_TIME=$(date +%s)

echo "=========================================="
echo "RAG Scan Stack - Complete System Backup"
echo "=========================================="
echo "Timestamp: $(date)"
echo "Backup Directory: $BACKUP_DIR"
echo ""

# Function to log messages
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to log section headers
log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Function to backup PostgreSQL databases
backup_databases() {
    log_section "1. Backing up PostgreSQL databases"

    if [ -f "$SCRIPT_DIR/backup-postgres.sh" ]; then
        # Run PostgreSQL backup and capture output directory
        local postgres_backup_dir=$("$SCRIPT_DIR/backup-postgres.sh" 2>&1 | tail -1)

        if [ -d "$postgres_backup_dir" ]; then
            # Copy to full backup directory
            log "Copying PostgreSQL backups to full backup..."
            cp -r "$postgres_backup_dir" "$BACKUP_DIR/postgres"
            log "${GREEN}✓ PostgreSQL backup complete${NC}"
        else
            echo -e "${RED}✗ Error: PostgreSQL backup failed${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Error: backup-postgres.sh not found${NC}"
        return 1
    fi
}

# Function to backup Docker volumes
backup_volumes() {
    log_section "2. Backing up Docker volumes"

    if [ -f "$SCRIPT_DIR/backup-volumes.sh" ]; then
        # Run volumes backup and capture output directory
        local volumes_backup_dir=$("$SCRIPT_DIR/backup-volumes.sh" 2>&1 | tail -1)

        if [ -d "$volumes_backup_dir" ]; then
            # Copy to full backup directory
            log "Copying volume backups to full backup..."
            cp -r "$volumes_backup_dir" "$BACKUP_DIR/volumes"
            log "${GREEN}✓ Volume backup complete${NC}"
        else
            echo -e "${YELLOW}⚠️  Warning: Volume backup had issues${NC}"
        fi
    else
        echo -e "${RED}✗ Error: backup-volumes.sh not found${NC}"
        return 1
    fi
}

# Function to backup scan data files
backup_scan_data() {
    log_section "3. Backing up scan data files"

    mkdir -p "$BACKUP_DIR/scan_data"

    for dir in "${SCAN_DATA_DIRS[@]}"; do
        local source_dir="$PROJECT_ROOT/$dir"

        if [ -d "$source_dir" ]; then
            log "Backing up: $dir"

            # Create tar archive of scan data
            if tar czf "$BACKUP_DIR/scan_data/${dir}.tar.gz" -C "$PROJECT_ROOT" "$dir" 2>/dev/null; then
                local size=$(du -h "$BACKUP_DIR/scan_data/${dir}.tar.gz" | cut -f1)
                local file_count=$(find "$source_dir" -type f | wc -l)
                log "  ${GREEN}✓ $dir: $size ($file_count files)${NC}"
            else
                echo -e "${YELLOW}  ⚠️  Warning: Failed to backup $dir${NC}"
            fi
        else
            log "  ${YELLOW}Directory not found: $dir (skipping)${NC}"
        fi
    done

    log "${GREEN}✓ Scan data backup complete${NC}"
}

# Function to backup configuration files
backup_configuration() {
    log_section "4. Backing up configuration files"

    mkdir -p "$BACKUP_DIR/config"

    for file in "${CONFIG_FILES[@]}"; do
        local source_file="$PROJECT_ROOT/$file"

        if [ -f "$source_file" ]; then
            log "Backing up: $file"

            # Create directory structure
            local dir_name=$(dirname "$file")
            if [ "$dir_name" != "." ]; then
                mkdir -p "$BACKUP_DIR/config/$dir_name"
            fi

            # Copy file
            if cp "$source_file" "$BACKUP_DIR/config/$file"; then
                log "  ${GREEN}✓ Copied${NC}"
            else
                echo -e "${YELLOW}  ⚠️  Warning: Failed to backup $file${NC}"
            fi
        else
            log "  ${YELLOW}File not found: $file (skipping)${NC}"
        fi
    done

    # Backup entire kong directory if it exists
    if [ -d "$PROJECT_ROOT/kong" ]; then
        log "Backing up Kong configuration directory..."
        if cp -r "$PROJECT_ROOT/kong" "$BACKUP_DIR/config/"; then
            log "  ${GREEN}✓ Kong config backed up${NC}"
        fi
    fi

    log "${GREEN}✓ Configuration backup complete${NC}"
}

# Function to backup Docker Compose state
backup_docker_state() {
    log_section "5. Backing up Docker state"

    mkdir -p "$BACKUP_DIR/docker_state"

    # Export running containers info
    log "Exporting Docker container information..."
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" \
        > "$BACKUP_DIR/docker_state/containers.txt" 2>/dev/null || true

    # Export Docker networks
    log "Exporting Docker networks..."
    docker network ls > "$BACKUP_DIR/docker_state/networks.txt" 2>/dev/null || true

    # Export Docker volumes
    log "Exporting Docker volumes..."
    docker volume ls > "$BACKUP_DIR/docker_state/volumes.txt" 2>/dev/null || true

    # Export Docker Compose config
    log "Exporting Docker Compose configuration..."
    if command -v docker-compose &>/dev/null; then
        docker-compose config > "$BACKUP_DIR/docker_state/docker-compose-resolved.yml" 2>/dev/null || true
    fi

    log "${GREEN}✓ Docker state backup complete${NC}"
}

# Function to create comprehensive manifest
create_manifest() {
    log_section "6. Creating backup manifest"

    cat > "$BACKUP_DIR/MANIFEST.md" <<EOF
# RAG Scan Stack - Complete System Backup

## Backup Information

- **Backup ID:** $TIMESTAMP
- **Backup Date:** $(date)
- **Backup Type:** Full System Backup
- **Backup Location:** $BACKUP_DIR

## System Information

### Host Information
- **Hostname:** $(hostname)
- **OS:** $(uname -s) $(uname -r)
- **Architecture:** $(uname -m)

### Docker Information
- **Docker Version:** $(docker --version 2>/dev/null || echo "N/A")
- **Docker Compose Version:** $(docker-compose --version 2>/dev/null || echo "N/A")

### Git Information
- **Branch:** $(cd "$PROJECT_ROOT" && git branch --show-current 2>/dev/null || echo "N/A")
- **Commit:** $(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "N/A")
- **Commit Date:** $(cd "$PROJECT_ROOT" && git log -1 --format=%cd 2>/dev/null || echo "N/A")

## Backup Contents

### 1. PostgreSQL Databases
$(if [ -d "$BACKUP_DIR/postgres" ]; then
    echo "✓ Backed up"
    echo ""
    ls -lh "$BACKUP_DIR/postgres" 2>/dev/null | tail -n +2 | sed 's/^/    /'
else
    echo "✗ Not available"
fi)

### 2. Docker Volumes
$(if [ -d "$BACKUP_DIR/volumes" ]; then
    echo "✓ Backed up"
    echo ""
    ls -lh "$BACKUP_DIR/volumes" 2>/dev/null | tail -n +2 | sed 's/^/    /'
else
    echo "✗ Not available"
fi)

### 3. Scan Data Files
$(if [ -d "$BACKUP_DIR/scan_data" ]; then
    echo "✓ Backed up"
    echo ""
    ls -lh "$BACKUP_DIR/scan_data" 2>/dev/null | tail -n +2 | sed 's/^/    /'
else
    echo "✗ Not available"
fi)

### 4. Configuration Files
$(if [ -d "$BACKUP_DIR/config" ]; then
    echo "✓ Backed up"
    echo ""
    find "$BACKUP_DIR/config" -type f 2>/dev/null | sed "s|$BACKUP_DIR/config/||" | sed 's/^/    - /'
else
    echo "✗ Not available"
fi)

### 5. Docker State
$(if [ -d "$BACKUP_DIR/docker_state" ]; then
    echo "✓ Backed up"
    echo ""
    ls -lh "$BACKUP_DIR/docker_state" 2>/dev/null | tail -n +2 | sed 's/^/    /'
else
    echo "✗ Not available"
fi)

## Backup Statistics

- **Total Backup Size:** $(du -sh "$BACKUP_DIR" | cut -f1)
- **Total Files:** $(find "$BACKUP_DIR" -type f | wc -l)
- **Backup Duration:** $(($(date +%s) - START_TIME)) seconds

## Backup Configuration

- **Retention Period:** $BACKUP_RETENTION_DAYS days
- **S3 Upload:** $ENABLE_S3_UPLOAD
$(if [ "$ENABLE_S3_UPLOAD" = "true" ]; then
    echo "- **S3 Bucket:** $S3_BUCKET"
fi)

## Restore Instructions

To restore from this backup:

\`\`\`bash
# 1. Stop all services
cd $PROJECT_ROOT
docker-compose down

# 2. Run restore script
./scripts/backup/restore.sh $TIMESTAMP

# 3. Start services
docker-compose up -d
\`\`\`

For detailed restore procedures, see: Docs/BACKUP_RESTORE.md

## Verification

Backup integrity should be verified regularly:

\`\`\`bash
# Verify PostgreSQL backups
gzip -t $BACKUP_DIR/postgres/postgres-full.sql.gz

# Verify volume backups
for f in $BACKUP_DIR/volumes/*.tar.gz; do
    tar tzf "\$f" >/dev/null && echo "✓ \$(basename "\$f")"
done

# Verify scan data backups
for f in $BACKUP_DIR/scan_data/*.tar.gz; do
    tar tzf "\$f" >/dev/null && echo "✓ \$(basename "\$f")"
done
\`\`\`

---

**Backup completed:** $(date)
EOF

    log "${GREEN}✓ Manifest created${NC}"
}

# Function to upload to S3
upload_to_s3() {
    if [ "$ENABLE_S3_UPLOAD" = "true" ] && [ -n "$S3_BUCKET" ]; then
        log_section "7. Uploading to S3"

        if command -v aws &> /dev/null; then
            log "Uploading complete backup to S3: $S3_BUCKET"

            if aws s3 sync "$BACKUP_DIR" "s3://$S3_BUCKET/full/$TIMESTAMP/" \
                --exclude "*.log"; then
                log "${GREEN}✓ S3 upload complete${NC}"
            else
                echo -e "${YELLOW}⚠️  Warning: S3 upload failed${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Warning: AWS CLI not installed, skipping S3 upload${NC}"
        fi
    else
        log "S3 upload disabled"
    fi
}

# Function to cleanup old backups
cleanup_old_backups() {
    log_section "8. Cleaning up old backups"

    log "Cleaning up full backups older than $BACKUP_RETENTION_DAYS days..."

    local deleted_count=0
    while IFS= read -r -d '' dir; do
        rm -rf "$dir"
        deleted_count=$((deleted_count + 1))
        log "  Deleted: $(basename "$dir")"
    done < <(find "$BACKUP_BASE_DIR/full" -maxdepth 1 -type d -mtime +"$BACKUP_RETENTION_DAYS" -print0 2>/dev/null)

    if [ $deleted_count -eq 0 ]; then
        log "No old backups to delete"
    else
        log "${GREEN}✓ Deleted $deleted_count old full backup(s)${NC}"
    fi
}

# Function to print final summary
print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    echo ""
    echo "=========================================="
    echo "Backup Summary"
    echo "=========================================="
    echo "Backup ID: $TIMESTAMP"
    echo "Start Time: $(date -d @$START_TIME)"
    echo "End Time: $(date -d @$end_time)"
    echo "Duration: ${duration}s"
    echo "Backup Location: $BACKUP_DIR"
    echo ""
    echo "Backup Components:"
    echo "  ✓ PostgreSQL databases"
    echo "  ✓ Docker volumes"
    echo "  ✓ Scan data files"
    echo "  ✓ Configuration files"
    echo "  ✓ Docker state"
    echo ""
    echo "Total Backup Size: $(du -sh "$BACKUP_DIR" | cut -f1)"
    echo "Total Files: $(find "$BACKUP_DIR" -type f | wc -l)"
    echo ""
    echo "Manifest: $BACKUP_DIR/MANIFEST.md"
    echo "Log: $LOG_FILE"
    echo "=========================================="
}

# Main execution
main() {
    log "Starting complete system backup..."
    log "Project root: $PROJECT_ROOT"

    # Perform all backup operations
    if ! backup_databases; then
        echo -e "${RED}✗ Database backup failed! Aborting.${NC}"
        exit 1
    fi

    if ! backup_volumes; then
        echo -e "${YELLOW}⚠️  Volume backup had issues, continuing...${NC}"
    fi

    backup_scan_data
    backup_configuration
    backup_docker_state
    create_manifest

    # Post-backup operations
    upload_to_s3
    cleanup_old_backups

    # Final summary
    print_summary

    log "${GREEN}✓✓✓ Complete system backup finished successfully! ✓✓✓${NC}"
    echo ""
    echo -e "${GREEN}Backup available at: $BACKUP_DIR${NC}"
    echo -e "${GREEN}Manifest: $BACKUP_DIR/MANIFEST.md${NC}"

    # Return backup directory path
    echo "$BACKUP_DIR"
}

# Run main function
main "$@"
