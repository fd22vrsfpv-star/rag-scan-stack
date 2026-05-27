#!/bin/bash
#
# backup-postgres.sh - PostgreSQL Database Backup Script
#
# This script performs automated backups of the RAG Scan Stack PostgreSQL databases.
# It creates compressed backups of all databases and optionally encrypts and uploads them.
#
# Usage:
#   ./backup-postgres.sh
#
# Configuration: Set environment variables in .backup-config.env
#
# Author: RAG Scan Stack Operations Team
# Version: 1.0
# Last Updated: 2025-11-19

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
ENABLE_ENCRYPTION="${ENABLE_ENCRYPTION:-false}"
ENCRYPTION_RECIPIENT="${ENCRYPTION_RECIPIENT:-backup@example.com}"
ENABLE_S3_UPLOAD="${ENABLE_S3_UPLOAD:-false}"
S3_BUCKET="${S3_BUCKET:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-rag-postgres}"
POSTGRES_USER="${POSTGRES_USER:-app}"

# Create backup directory structure
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE_DIR/postgres/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

# Logging
LOG_FILE="$BACKUP_DIR/backup.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

echo "========================================"
echo "PostgreSQL Backup Script"
echo "========================================"
echo "Timestamp: $(date)"
echo "Backup Directory: $BACKUP_DIR"
echo ""

# Function to log messages
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if container is running
check_container() {
    if ! docker ps --format '{{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
        echo -e "${RED}✗ Error: PostgreSQL container '$POSTGRES_CONTAINER' is not running${NC}"
        exit 1
    fi
    log "${GREEN}✓ PostgreSQL container is running${NC}"
}

# Function to perform full database dump
backup_full() {
    log "Creating full database dump (all databases)..."

    if docker exec "$POSTGRES_CONTAINER" pg_dumpall -U "$POSTGRES_USER" | \
        gzip > "$BACKUP_DIR/postgres-full.sql.gz"; then

        local size=$(du -h "$BACKUP_DIR/postgres-full.sql.gz" | cut -f1)
        log "${GREEN}✓ Full dump complete: $size${NC}"
    else
        echo -e "${RED}✗ Error: Full database dump failed${NC}"
        exit 1
    fi
}

# Function to backup individual databases
backup_databases() {
    log "Backing up individual databases..."

    # Get list of databases
    local databases=$(docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -t -c \
        "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';")

    for db in $databases; do
        # Trim whitespace
        db=$(echo "$db" | xargs)

        if [ -z "$db" ]; then
            continue
        fi

        log "  Backing up database: $db"

        if docker exec "$POSTGRES_CONTAINER" pg_dump -U "$POSTGRES_USER" -d "$db" -Fc > \
            "$BACKUP_DIR/${db}.dump"; then

            local size=$(du -h "$BACKUP_DIR/${db}.dump" | cut -f1)
            log "  ${GREEN}✓ $db: $size${NC}"
        else
            echo -e "${RED}  ✗ Failed to backup: $db${NC}"
        fi
    done
}

# Function to backup database schema only (for quick reference)
backup_schema() {
    log "Backing up database schemas..."

    if docker exec "$POSTGRES_CONTAINER" pg_dumpall -U "$POSTGRES_USER" --schema-only | \
        gzip > "$BACKUP_DIR/schema-only.sql.gz"; then
        log "${GREEN}✓ Schema backup complete${NC}"
    else
        echo -e "${YELLOW}⚠️  Warning: Schema backup failed${NC}"
    fi
}

# Function to backup database globals (roles, tablespaces, etc.)
backup_globals() {
    log "Backing up database globals (roles, tablespaces)..."

    if docker exec "$POSTGRES_CONTAINER" pg_dumpall -U "$POSTGRES_USER" --globals-only > \
        "$BACKUP_DIR/globals.sql"; then
        log "${GREEN}✓ Globals backup complete${NC}"
    else
        echo -e "${YELLOW}⚠️  Warning: Globals backup failed${NC}"
    fi
}

# Function to create backup manifest
create_manifest() {
    log "Creating backup manifest..."

    cat > "$BACKUP_DIR/manifest.txt" <<EOF
RAG Scan Stack - PostgreSQL Backup Manifest
============================================

Backup Timestamp: $TIMESTAMP
Backup Date: $(date)
PostgreSQL Container: $POSTGRES_CONTAINER
PostgreSQL User: $POSTGRES_USER

Files in this backup:
---------------------
$(ls -lh "$BACKUP_DIR" | tail -n +2)

PostgreSQL Version:
-------------------
$(docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -t -c "SELECT version();")

Database Sizes:
--------------
$(docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -t -c "
SELECT
    datname AS database,
    pg_size_pretty(pg_database_size(datname)) AS size
FROM pg_database
WHERE datistemplate = false
ORDER BY pg_database_size(datname) DESC;
")

Backup Configuration:
--------------------
Retention: $BACKUP_RETENTION_DAYS days
Encryption: $ENABLE_ENCRYPTION
S3 Upload: $ENABLE_S3_UPLOAD

EOF

    log "${GREEN}✓ Manifest created${NC}"
}

# Function to encrypt backup
encrypt_backup() {
    if [ "$ENABLE_ENCRYPTION" = "true" ]; then
        log "Encrypting backup files..."

        for file in "$BACKUP_DIR"/*.{gz,dump,sql} 2>/dev/null; do
            if [ -f "$file" ]; then
                if gpg --encrypt --recipient "$ENCRYPTION_RECIPIENT" "$file"; then
                    log "  ${GREEN}✓ Encrypted: $(basename "$file")${NC}"
                    # Remove unencrypted file
                    rm "$file"
                else
                    echo -e "${YELLOW}  ⚠️  Warning: Failed to encrypt $(basename "$file")${NC}"
                fi
            fi
        done
    else
        log "Encryption disabled (set ENABLE_ENCRYPTION=true to enable)"
    fi
}

# Function to upload to S3
upload_to_s3() {
    if [ "$ENABLE_S3_UPLOAD" = "true" ] && [ -n "$S3_BUCKET" ]; then
        log "Uploading backup to S3: $S3_BUCKET"

        if command -v aws &> /dev/null; then
            if aws s3 sync "$BACKUP_DIR" "s3://$S3_BUCKET/postgres/$TIMESTAMP/" \
                --exclude "backup.log"; then
                log "${GREEN}✓ S3 upload complete${NC}"
            else
                echo -e "${YELLOW}⚠️  Warning: S3 upload failed${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Warning: AWS CLI not installed, skipping S3 upload${NC}"
        fi
    else
        log "S3 upload disabled (set ENABLE_S3_UPLOAD=true and S3_BUCKET to enable)"
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
    done < <(find "$BACKUP_BASE_DIR/postgres" -maxdepth 1 -type d -mtime +"$BACKUP_RETENTION_DAYS" -print0 2>/dev/null)

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

    # Check if backup files exist and are not empty
    if [ ! -f "$BACKUP_DIR/postgres-full.sql.gz" ] || [ ! -s "$BACKUP_DIR/postgres-full.sql.gz" ]; then
        echo -e "${RED}✗ Error: Full backup file is missing or empty${NC}"
        errors=$((errors + 1))
    else
        # Test gzip integrity
        if gzip -t "$BACKUP_DIR/postgres-full.sql.gz" 2>/dev/null; then
            log "${GREEN}✓ Full backup integrity check passed${NC}"
        else
            echo -e "${RED}✗ Error: Full backup file is corrupted${NC}"
            errors=$((errors + 1))
        fi
    fi

    # Check individual database dumps
    local dump_count=$(find "$BACKUP_DIR" -name "*.dump" 2>/dev/null | wc -l)
    log "Found $dump_count individual database backup(s)"

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
    log "Starting PostgreSQL backup..."

    # Pre-flight checks
    check_container

    # Perform backups
    backup_full
    backup_databases
    backup_schema
    backup_globals

    # Create manifest
    create_manifest

    # Verify backup
    if ! verify_backup; then
        echo -e "${RED}✗ Backup verification failed! Please investigate.${NC}"
        exit 1
    fi

    # Post-backup operations
    encrypt_backup
    upload_to_s3
    cleanup_old_backups

    # Summary
    print_summary

    log "${GREEN}✓ Backup completed successfully!${NC}"
    echo ""
    echo -e "${GREEN}Backup available at: $BACKUP_DIR${NC}"

    # Return backup directory path for potential chaining
    echo "$BACKUP_DIR"
}

# Run main function
main "$@"
