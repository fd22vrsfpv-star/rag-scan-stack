#!/bin/bash
#
# backup-volumes.sh - Docker Volumes Backup Script
#
# This script performs automated backups of Docker volumes used by the RAG Scan Stack.
# It creates compressed tar archives of volume data.
#
# Usage:
#   ./backup-volumes.sh
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

# Docker volumes to backup
VOLUMES=(
    "rag-pgdata"
    "nuclei-templates"
    "searchsploit-data"
    "ollama-data"
)

# Create backup directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE_DIR/volumes/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

# Logging
LOG_FILE="$BACKUP_DIR/backup.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

echo "========================================"
echo "Docker Volumes Backup Script"
echo "========================================"
echo "Timestamp: $(date)"
echo "Backup Directory: $BACKUP_DIR"
echo ""

# Function to log messages
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if volume exists
check_volume() {
    local volume=$1
    if docker volume inspect "$volume" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to backup a single volume
backup_volume() {
    local volume=$1
    log "Backing up volume: $volume"

    if ! check_volume "$volume"; then
        echo -e "${YELLOW}  ⚠️  Warning: Volume '$volume' does not exist, skipping${NC}"
        return 1
    fi

    # Get volume mount point (for reference)
    local mount_point=$(docker volume inspect "$volume" --format '{{ .Mountpoint }}')
    log "  Mount point: $mount_point"

    # Create tar archive of volume data
    if docker run --rm \
        -v "$volume:/data:ro" \
        -v "$BACKUP_DIR:/backup" \
        alpine:latest \
        tar czf "/backup/${volume}.tar.gz" -C /data . 2>/dev/null; then

        local size=$(du -h "$BACKUP_DIR/${volume}.tar.gz" | cut -f1)
        log "  ${GREEN}✓ Backup complete: $size${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Error: Failed to backup volume '$volume'${NC}"
        return 1
    fi
}

# Function to create backup manifest
create_manifest() {
    log "Creating backup manifest..."

    cat > "$BACKUP_DIR/manifest.txt" <<EOF
RAG Scan Stack - Docker Volumes Backup Manifest
===============================================

Backup Timestamp: $TIMESTAMP
Backup Date: $(date)

Volumes backed up:
-----------------
EOF

    for volume in "${VOLUMES[@]}"; do
        if [ -f "$BACKUP_DIR/${volume}.tar.gz" ]; then
            local size=$(du -h "$BACKUP_DIR/${volume}.tar.gz" | cut -f1)
            echo "$volume - $size" >> "$BACKUP_DIR/manifest.txt"

            # Add volume details
            echo "" >> "$BACKUP_DIR/manifest.txt"
            echo "Volume: $volume" >> "$BACKUP_DIR/manifest.txt"
            docker volume inspect "$volume" >> "$BACKUP_DIR/manifest.txt" 2>/dev/null || true
            echo "" >> "$BACKUP_DIR/manifest.txt"
        fi
    done

    cat >> "$BACKUP_DIR/manifest.txt" <<EOF

Files in this backup:
--------------------
$(ls -lh "$BACKUP_DIR" | tail -n +2)

Total backup size: $(du -sh "$BACKUP_DIR" | cut -f1)

Backup Configuration:
--------------------
Retention: $BACKUP_RETENTION_DAYS days
S3 Upload: $ENABLE_S3_UPLOAD

EOF

    log "${GREEN}✓ Manifest created${NC}"
}

# Function to upload to S3
upload_to_s3() {
    if [ "$ENABLE_S3_UPLOAD" = "true" ] && [ -n "$S3_BUCKET" ]; then
        log "Uploading backup to S3: $S3_BUCKET"

        if command -v aws &> /dev/null; then
            if aws s3 sync "$BACKUP_DIR" "s3://$S3_BUCKET/volumes/$TIMESTAMP/" \
                --exclude "backup.log"; then
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
    log "Cleaning up backups older than $BACKUP_RETENTION_DAYS days..."

    local deleted_count=0
    while IFS= read -r -d '' dir; do
        rm -rf "$dir"
        deleted_count=$((deleted_count + 1))
        log "  Deleted: $(basename "$dir")"
    done < <(find "$BACKUP_BASE_DIR/volumes" -maxdepth 1 -type d -mtime +"$BACKUP_RETENTION_DAYS" -print0 2>/dev/null)

    if [ $deleted_count -eq 0 ]; then
        log "No old backups to delete"
    else
        log "${GREEN}✓ Deleted $deleted_count old backup(s)${NC}"
    fi
}

# Function to verify backup integrity
verify_backup() {
    log "Verifying backup integrity..."

    local errors=0
    local verified=0

    for volume in "${VOLUMES[@]}"; do
        local backup_file="$BACKUP_DIR/${volume}.tar.gz"

        if [ ! -f "$backup_file" ]; then
            echo -e "${YELLOW}  ⚠️  Backup file not found: ${volume}.tar.gz (volume may not exist)${NC}"
            continue
        fi

        if [ ! -s "$backup_file" ]; then
            echo -e "${RED}  ✗ Error: Backup file is empty: ${volume}.tar.gz${NC}"
            errors=$((errors + 1))
            continue
        fi

        # Test tar integrity
        if tar tzf "$backup_file" >/dev/null 2>&1; then
            log "  ${GREEN}✓ $volume: integrity check passed${NC}"
            verified=$((verified + 1))
        else
            echo -e "${RED}  ✗ Error: Backup file is corrupted: ${volume}.tar.gz${NC}"
            errors=$((errors + 1))
        fi
    done

    log "Verified $verified volume backup(s)"

    if [ $errors -gt 0 ]; then
        echo -e "${RED}✗ Backup verification failed with $errors error(s)${NC}"
        return 1
    else
        log "${GREEN}✓ All backup integrity checks passed${NC}"
        return 0
    fi
}

# Function to print backup summary
print_summary() {
    local end_time=$(date)
    local duration=$SECONDS

    echo ""
    echo "========================================"
    echo "Backup Summary"
    echo "========================================"
    echo "Start Time: $(head -2 "$LOG_FILE" | tail -1 | cut -d']' -f1 | tr -d '[')"
    echo "End Time: $end_time"
    echo "Duration: ${duration}s"
    echo "Backup Location: $BACKUP_DIR"
    echo ""
    echo "Files created:"
    ls -lh "$BACKUP_DIR" | tail -n +2
    echo ""
    echo "Total backup size: $(du -sh "$BACKUP_DIR" | cut -f1)"
    echo "========================================"
}

# Main execution
main() {
    log "Starting Docker volumes backup..."

    local success_count=0
    local failure_count=0

    # Backup each volume
    for volume in "${VOLUMES[@]}"; do
        if backup_volume "$volume"; then
            success_count=$((success_count + 1))
        else
            failure_count=$((failure_count + 1))
        fi
        echo ""
    done

    log "Backed up $success_count volume(s) successfully"
    if [ $failure_count -gt 0 ]; then
        echo -e "${YELLOW}⚠️  Failed to backup $failure_count volume(s)${NC}"
    fi

    # Create manifest
    create_manifest

    # Verify backups
    if ! verify_backup; then
        echo -e "${RED}✗ Backup verification failed! Please investigate.${NC}"
        exit 1
    fi

    # Post-backup operations
    upload_to_s3
    cleanup_old_backups

    # Summary
    print_summary

    if [ $failure_count -eq 0 ]; then
        log "${GREEN}✓ All volume backups completed successfully!${NC}"
    else
        log "${YELLOW}⚠️  Volume backups completed with $failure_count warning(s)${NC}"
    fi

    echo ""
    echo -e "${GREEN}Backup available at: $BACKUP_DIR${NC}"

    # Return backup directory path
    echo "$BACKUP_DIR"
}

# Run main function
main "$@"
