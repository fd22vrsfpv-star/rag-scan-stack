#!/bin/bash
#
# restore.sh - System Restore Script
#
# This script restores the RAG Scan Stack from backup including:
# - PostgreSQL databases
# - Docker volumes
# - Scan result files
# - Configuration files
#
# Usage:
#   ./restore.sh <backup-timestamp> [options]
#
# Options:
#   --database-only    Restore only PostgreSQL databases
#   --volumes-only     Restore only Docker volumes
#   --skip-volumes     Skip volume restoration
#   --dry-run          Show what would be restored without actually restoring
#   --force            Skip confirmation prompts
#
# Examples:
#   ./restore.sh 20251119-020000                    # Full restore
#   ./restore.sh 20251119-020000 --database-only    # Database only
#   ./restore.sh 20251119-020000 --dry-run          # Dry run
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
fi

# Configuration with defaults
BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/backups}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-rag-postgres}"
POSTGRES_USER="${POSTGRES_USER:-app}"

# Parse command line arguments
BACKUP_TIMESTAMP=""
DATABASE_ONLY=false
VOLUMES_ONLY=false
SKIP_VOLUMES=false
DRY_RUN=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --database-only)
            DATABASE_ONLY=true
            shift
            ;;
        --volumes-only)
            VOLUMES_ONLY=true
            shift
            ;;
        --skip-volumes)
            SKIP_VOLUMES=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            if [ -z "$BACKUP_TIMESTAMP" ]; then
                BACKUP_TIMESTAMP="$1"
            else
                echo -e "${RED}Error: Unknown option: $1${NC}"
                exit 1
            fi
            shift
            ;;
    esac
done

# Function to show usage
usage() {
    cat <<EOF
Usage: $0 <backup-timestamp> [options]

Restore RAG Scan Stack from backup.

Options:
  --database-only    Restore only PostgreSQL databases
  --volumes-only     Restore only Docker volumes
  --skip-volumes     Skip volume restoration
  --dry-run          Show what would be restored without actually restoring
  --force            Skip confirmation prompts

Available backups:
$(list_backups)

Examples:
  $0 20251119-020000                    # Full restore
  $0 20251119-020000 --database-only    # Database only
  $0 20251119-020000 --dry-run          # Dry run
EOF
}

# Function to list available backups
list_backups() {
    if [ -d "$BACKUP_BASE_DIR/full" ]; then
        local backups=$(find "$BACKUP_BASE_DIR/full" -maxdepth 1 -type d -name "20*" | sort -r | head -10)
        if [ -n "$backups" ]; then
            echo "$backups" | while read -r backup; do
                local timestamp=$(basename "$backup")
                local size=$(du -sh "$backup" 2>/dev/null | cut -f1)
                echo "  $timestamp ($size)"
            done
        else
            echo "  No full backups found"
        fi
    else
        echo "  Backup directory not found: $BACKUP_BASE_DIR/full"
    fi
}

# Validate arguments
if [ -z "$BACKUP_TIMESTAMP" ]; then
    echo -e "${RED}Error: Backup timestamp required${NC}"
    echo ""
    usage
    exit 1
fi

# Determine backup directory
BACKUP_DIR="$BACKUP_BASE_DIR/full/$BACKUP_TIMESTAMP"

# Check if backup exists
if [ ! -d "$BACKUP_DIR" ]; then
    echo -e "${RED}Error: Backup not found: $BACKUP_DIR${NC}"
    echo ""
    echo "Available backups:"
    list_backups
    exit 1
fi

# Logging
LOG_FILE="/tmp/restore-$BACKUP_TIMESTAMP-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

START_TIME=$(date +%s)

echo "=========================================="
echo "RAG Scan Stack - System Restore"
echo "=========================================="
echo "Timestamp: $(date)"
echo "Backup: $BACKUP_TIMESTAMP"
echo "Backup Directory: $BACKUP_DIR"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
fi
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

# Function to confirm action
confirm() {
    if [ "$FORCE" = true ]; then
        return 0
    fi

    local message="$1"
    echo -e "${YELLOW}$message${NC}"
    read -p "Continue? (yes/no): " response
    if [ "$response" != "yes" ]; then
        echo "Restore cancelled."
        exit 0
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log_section "Checking prerequisites"

    # Check if Docker is running
    if ! docker info &>/dev/null; then
        echo -e "${RED}✗ Error: Docker is not running${NC}"
        exit 1
    fi
    log "${GREEN}✓ Docker is running${NC}"

    # Check if backup directory exists and has required components
    if [ ! -f "$BACKUP_DIR/MANIFEST.md" ]; then
        echo -e "${YELLOW}⚠️  Warning: Backup manifest not found${NC}"
    else
        log "${GREEN}✓ Backup manifest found${NC}"
    fi

    # Check what components are available in backup
    echo ""
    echo "Backup components available:"
    if [ -d "$BACKUP_DIR/postgres" ]; then
        echo "  ✓ PostgreSQL databases"
    else
        echo "  ✗ PostgreSQL databases"
    fi

    if [ -d "$BACKUP_DIR/volumes" ]; then
        echo "  ✓ Docker volumes"
    else
        echo "  ✗ Docker volumes"
    fi

    if [ -d "$BACKUP_DIR/scan_data" ]; then
        echo "  ✓ Scan data files"
    else
        echo "  ✗ Scan data files"
    fi

    if [ -d "$BACKUP_DIR/config" ]; then
        echo "  ✓ Configuration files"
    else
        echo "  ✗ Configuration files"
    fi
}

# Function to stop services
stop_services() {
    log_section "Stopping services"

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would stop all services"
        return 0
    fi

    confirm "This will stop all running services. Any active operations will be interrupted."

    log "Stopping Docker Compose services..."
    cd "$PROJECT_ROOT"

    if docker-compose down; then
        log "${GREEN}✓ Services stopped${NC}"
    else
        echo -e "${RED}✗ Error: Failed to stop services${NC}"
        exit 1
    fi
}

# Function to restore PostgreSQL databases
restore_databases() {
    log_section "Restoring PostgreSQL databases"

    if [ ! -d "$BACKUP_DIR/postgres" ]; then
        echo -e "${YELLOW}⚠️  PostgreSQL backup not found, skipping${NC}"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would restore databases from:"
        ls -lh "$BACKUP_DIR/postgres"
        return 0
    fi

    # Start only PostgreSQL container
    log "Starting PostgreSQL container..."
    cd "$PROJECT_ROOT"
    docker-compose up -d "$POSTGRES_CONTAINER"

    # Wait for PostgreSQL to be ready
    log "Waiting for PostgreSQL to be ready..."
    local attempts=0
    while ! docker exec "$POSTGRES_CONTAINER" pg_isready -U "$POSTGRES_USER" &>/dev/null; do
        attempts=$((attempts + 1))
        if [ $attempts -gt 30 ]; then
            echo -e "${RED}✗ Error: PostgreSQL did not become ready in time${NC}"
            exit 1
        fi
        sleep 2
        echo -n "."
    done
    echo ""
    log "${GREEN}✓ PostgreSQL is ready${NC}"

    # Restore full database dump
    if [ -f "$BACKUP_DIR/postgres/postgres-full.sql.gz" ]; then
        log "Restoring full database dump..."
        confirm "This will OVERWRITE ALL existing data in PostgreSQL!"

        if gunzip -c "$BACKUP_DIR/postgres/postgres-full.sql.gz" | \
            docker exec -i "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" &>/dev/null; then
            log "${GREEN}✓ Database restore complete${NC}"
        else
            echo -e "${RED}✗ Error: Database restore failed${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}⚠️  Full database dump not found${NC}"

        # Try individual database dumps
        log "Looking for individual database dumps..."
        for dump in "$BACKUP_DIR/postgres"/*.dump; do
            if [ -f "$dump" ]; then
                local dbname=$(basename "$dump" .dump)
                log "  Restoring database: $dbname"

                if docker exec -i "$POSTGRES_CONTAINER" pg_restore -U "$POSTGRES_USER" \
                    -d "$dbname" --clean --if-exists < "$dump" &>/dev/null; then
                    log "  ${GREEN}✓ $dbname restored${NC}"
                else
                    echo -e "${YELLOW}  ⚠️  Failed to restore $dbname${NC}"
                fi
            fi
        done
    fi

    # Verify restoration
    log "Verifying database restoration..."
    local db_count=$(docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -t -c \
        "SELECT COUNT(*) FROM pg_database WHERE datistemplate = false;")
    log "Databases restored: $db_count"

    log "${GREEN}✓ Database restoration complete${NC}"
}

# Function to restore Docker volumes
restore_volumes() {
    log_section "Restoring Docker volumes"

    if [ ! -d "$BACKUP_DIR/volumes" ]; then
        echo -e "${YELLOW}⚠️  Volume backups not found, skipping${NC}"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would restore volumes from:"
        ls -lh "$BACKUP_DIR/volumes"
        return 0
    fi

    confirm "This will OVERWRITE existing Docker volume data!"

    for volume_backup in "$BACKUP_DIR/volumes"/*.tar.gz; do
        if [ ! -f "$volume_backup" ]; then
            continue
        fi

        local volume_name=$(basename "$volume_backup" .tar.gz)
        log "Restoring volume: $volume_name"

        # Remove existing volume
        if docker volume inspect "$volume_name" &>/dev/null; then
            log "  Removing existing volume..."
            docker volume rm "$volume_name" || true
        fi

        # Create new volume
        docker volume create "$volume_name"

        # Restore data
        if docker run --rm \
            -v "$volume_name:/data" \
            -v "$BACKUP_DIR/volumes:/backup:ro" \
            alpine:latest \
            tar xzf "/backup/$(basename "$volume_backup")" -C /data 2>/dev/null; then
            log "  ${GREEN}✓ $volume_name restored${NC}"
        else
            echo -e "${YELLOW}  ⚠️  Failed to restore $volume_name${NC}"
        fi
    done

    log "${GREEN}✓ Volume restoration complete${NC}"
}

# Function to restore scan data files
restore_scan_data() {
    log_section "Restoring scan data files"

    if [ ! -d "$BACKUP_DIR/scan_data" ]; then
        echo -e "${YELLOW}⚠️  Scan data backups not found, skipping${NC}"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would restore scan data from:"
        ls -lh "$BACKUP_DIR/scan_data"
        return 0
    fi

    for scan_backup in "$BACKUP_DIR/scan_data"/*.tar.gz; do
        if [ ! -f "$scan_backup" ]; then
            continue
        fi

        local dir_name=$(basename "$scan_backup" .tar.gz)
        log "Restoring: $dir_name"

        # Extract to project root
        if tar xzf "$scan_backup" -C "$PROJECT_ROOT"; then
            log "  ${GREEN}✓ $dir_name restored${NC}"
        else
            echo -e "${YELLOW}  ⚠️  Failed to restore $dir_name${NC}"
        fi
    done

    log "${GREEN}✓ Scan data restoration complete${NC}"
}

# Function to restore configuration files
restore_configuration() {
    log_section "Restoring configuration files"

    if [ ! -d "$BACKUP_DIR/config" ]; then
        echo -e "${YELLOW}⚠️  Configuration backups not found, skipping${NC}"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would restore configuration files from:"
        find "$BACKUP_DIR/config" -type f
        return 0
    fi

    confirm "This will OVERWRITE existing configuration files!"

    # Backup current configuration before overwriting
    local config_backup="/tmp/config-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$config_backup"
    log "Backing up current configuration to: $config_backup"

    for file in "$BACKUP_DIR/config"/{.env,docker-compose.yml,kong/kong.yml,.backup-config.env}; do
        if [ -f "$file" ]; then
            local rel_path="${file#$BACKUP_DIR/config/}"
            local target="$PROJECT_ROOT/$rel_path"
            if [ -f "$target" ]; then
                mkdir -p "$(dirname "$config_backup/$rel_path")"
                cp "$target" "$config_backup/$rel_path" || true
            fi
        fi
    done

    # Restore configuration files
    log "Restoring configuration files..."
    if cp -r "$BACKUP_DIR/config/"* "$PROJECT_ROOT/"; then
        log "${GREEN}✓ Configuration restored${NC}"
        log "Previous configuration backed up to: $config_backup"
    else
        echo -e "${RED}✗ Error: Failed to restore configuration${NC}"
        exit 1
    fi
}

# Function to start services
start_services() {
    log_section "Starting services"

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would start all services"
        return 0
    fi

    log "Starting all Docker Compose services..."
    cd "$PROJECT_ROOT"

    if docker-compose up -d; then
        log "${GREEN}✓ Services started${NC}"
    else
        echo -e "${RED}✗ Error: Failed to start services${NC}"
        exit 1
    fi

    # Wait for services to be healthy
    log "Waiting for services to be healthy (60 seconds)..."
    sleep 60

    log "Checking service health..."
    local healthy=0
    local total=0

    for service in rag-api nmap_scanner web-scanner nuclei-runner playwright-scanner autogen-agents; do
        total=$((total + 1))
        if curl -s -f "http://localhost:8000/health" &>/dev/null || \
           curl -s -f "http://localhost:8010/health" &>/dev/null || \
           curl -s -f "http://localhost:8012/health" &>/dev/null; then
            healthy=$((healthy + 1))
        fi
    done

    log "Services healthy: $healthy / $total"
}

# Function to verify restore
verify_restore() {
    log_section "Verifying restore"

    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would verify restoration"
        return 0
    fi

    local errors=0

    # Check PostgreSQL
    if docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -c "SELECT 1;" &>/dev/null; then
        log "${GREEN}✓ PostgreSQL is accessible${NC}"
    else
        echo -e "${RED}✗ PostgreSQL verification failed${NC}"
        errors=$((errors + 1))
    fi

    # Check volumes
    local volumes=$(docker volume ls -q | grep -E "^(rag-pgdata|nuclei-templates|searchsploit-data|ollama-data)$" | wc -l)
    if [ $volumes -gt 0 ]; then
        log "${GREEN}✓ Docker volumes verified ($volumes volumes)${NC}"
    else
        echo -e "${YELLOW}⚠️  No expected volumes found${NC}"
    fi

    # Check configuration files
    if [ -f "$PROJECT_ROOT/.env" ] && [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        log "${GREEN}✓ Configuration files verified${NC}"
    else
        echo -e "${RED}✗ Configuration files missing${NC}"
        errors=$((errors + 1))
    fi

    if [ $errors -eq 0 ]; then
        log "${GREEN}✓ Restore verification passed${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Restore verification completed with $errors warning(s)${NC}"
        return 1
    fi
}

# Function to print summary
print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    echo ""
    echo "=========================================="
    echo "Restore Summary"
    echo "=========================================="
    echo "Backup: $BACKUP_TIMESTAMP"
    echo "Start Time: $(date -d @$START_TIME)"
    echo "End Time: $(date -d @$end_time)"
    echo "Duration: ${duration}s"
    echo ""
    echo "Components restored:"
    if [ "$DATABASE_ONLY" = false ] && [ "$VOLUMES_ONLY" = false ]; then
        echo "  ✓ PostgreSQL databases"
        echo "  ✓ Docker volumes"
        echo "  ✓ Scan data files"
        echo "  ✓ Configuration files"
    elif [ "$DATABASE_ONLY" = true ]; then
        echo "  ✓ PostgreSQL databases only"
    elif [ "$VOLUMES_ONLY" = true ]; then
        echo "  ✓ Docker volumes only"
    fi
    echo ""
    echo "Log: $LOG_FILE"
    echo "=========================================="
}

# Main execution
main() {
    log "Starting system restore..."

    # Check prerequisites
    check_prerequisites

    # Determine what to restore
    if [ "$VOLUMES_ONLY" = true ]; then
        stop_services
        restore_volumes
        start_services
    elif [ "$DATABASE_ONLY" = true ]; then
        stop_services
        restore_databases
        start_services
    else
        # Full restore
        stop_services
        restore_databases

        if [ "$SKIP_VOLUMES" = false ]; then
            restore_volumes
        fi

        restore_scan_data
        restore_configuration
        start_services
    fi

    # Verify restoration
    verify_restore

    # Print summary
    print_summary

    if [ "$DRY_RUN" = true ]; then
        log "${BLUE}DRY RUN COMPLETE - No changes were made${NC}"
    else
        log "${GREEN}✓✓✓ System restore completed successfully! ✓✓✓${NC}"
    fi

    echo ""
    echo -e "${GREEN}Restore log saved to: $LOG_FILE${NC}"
}

# Run main function
main "$@"
