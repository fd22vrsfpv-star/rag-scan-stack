#!/bin/bash
#
# test-backup-system.sh - Test Backup System Functionality
#
# This script tests the backup and restore system to ensure everything is working correctly.
# It performs non-destructive tests where possible.
#
# Usage:
#   ./test-backup-system.sh [--full]
#
# Options:
#   --full      Perform full testing including restore (more invasive)
#   --quick     Quick tests only (default)
#
# Author: RAG Scan Stack Operations Team
# Version: 1.0
# Last Updated: 2025-11-19

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Test mode
FULL_TEST=false
if [ "${1:-}" = "--full" ]; then
    FULL_TEST=true
fi

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

echo "=========================================="
echo "RAG Scan Stack - Backup System Test"
echo "=========================================="
echo "Mode: $([ "$FULL_TEST" = true ] && echo "FULL" || echo "QUICK")"
echo "Date: $(date)"
echo ""

# Function to log test results
log_test() {
    local name="$1"
    local status="$2"
    local message="${3:-}"

    case "$status" in
        PASS)
            echo -e "${GREEN}✓ PASS${NC}: $name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
        FAIL)
            echo -e "${RED}✗ FAIL${NC}: $name"
            if [ -n "$message" ]; then
                echo -e "  ${RED}Error: $message${NC}"
            fi
            TESTS_FAILED=$((TESTS_FAILED + 1))
            ;;
        SKIP)
            echo -e "${YELLOW}⊘ SKIP${NC}: $name"
            if [ -n "$message" ]; then
                echo -e "  ${YELLOW}Reason: $message${NC}"
            fi
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            ;;
    esac
}

# Test 1: Check if backup scripts exist
test_scripts_exist() {
    echo -e "\n${BLUE}[Test 1]${NC} Checking if backup scripts exist..."

    local scripts=("backup-postgres.sh" "backup-volumes.sh" "backup-full.sh" "restore.sh" "setup-cron.sh")
    local missing=0

    for script in "${scripts[@]}"; do
        if [ -f "$SCRIPT_DIR/$script" ] && [ -x "$SCRIPT_DIR/$script" ]; then
            echo "  ✓ $script (executable)"
        else
            echo "  ✗ $script (missing or not executable)"
            missing=$((missing + 1))
        fi
    done

    if [ $missing -eq 0 ]; then
        log_test "Backup scripts exist and are executable" "PASS"
    else
        log_test "Backup scripts exist and are executable" "FAIL" "$missing script(s) missing or not executable"
    fi
}

# Test 2: Check if configuration file exists
test_config_exists() {
    echo -e "\n${BLUE}[Test 2]${NC} Checking configuration..."

    if [ -f "$PROJECT_ROOT/.backup-config.env" ]; then
        local perms=$(stat -c "%a" "$PROJECT_ROOT/.backup-config.env")
        if [ "$perms" = "600" ]; then
            log_test "Configuration file exists with correct permissions" "PASS"
        else
            log_test "Configuration file permissions" "FAIL" "Expected 600, got $perms"
        fi
    else
        log_test "Configuration file exists" "SKIP" "File not found (using defaults)"
    fi
}

# Test 3: Check if backup directory exists or can be created
test_backup_directory() {
    echo -e "\n${BLUE}[Test 3]${NC} Checking backup directory..."

    local backup_dir="/backups"
    if [ -f "$PROJECT_ROOT/.backup-config.env" ]; then
        source "$PROJECT_ROOT/.backup-config.env"
        backup_dir="${BACKUP_BASE_DIR:-/backups}"
    fi

    if [ -d "$backup_dir" ]; then
        if [ -w "$backup_dir" ]; then
            log_test "Backup directory is writable" "PASS"
        else
            log_test "Backup directory is writable" "FAIL" "$backup_dir is not writable"
        fi
    else
        log_test "Backup directory exists" "SKIP" "$backup_dir does not exist (will be created on first backup)"
    fi
}

# Test 4: Check if Docker is running
test_docker_running() {
    echo -e "\n${BLUE}[Test 4]${NC} Checking Docker..."

    if docker info &>/dev/null; then
        log_test "Docker is running" "PASS"
    else
        log_test "Docker is running" "FAIL" "Docker is not running or not accessible"
    fi
}

# Test 5: Check if PostgreSQL container exists
test_postgres_container() {
    echo -e "\n${BLUE}[Test 5]${NC} Checking PostgreSQL container..."

    if docker ps --format '{{.Names}}' | grep -q "^rag-postgres$"; then
        log_test "PostgreSQL container is running" "PASS"
    else
        log_test "PostgreSQL container is running" "SKIP" "Container not found (may not be started yet)"
    fi
}

# Test 6: Check if PostgreSQL is accessible
test_postgres_accessible() {
    echo -e "\n${BLUE}[Test 6]${NC} Checking PostgreSQL accessibility..."

    if docker ps --format '{{.Names}}' | grep -q "^rag-postgres$"; then
        if docker exec rag-postgres pg_isready -U app &>/dev/null; then
            log_test "PostgreSQL is accessible" "PASS"
        else
            log_test "PostgreSQL is accessible" "FAIL" "pg_isready failed"
        fi
    else
        log_test "PostgreSQL is accessible" "SKIP" "Container not running"
    fi
}

# Test 7: Test database backup
test_database_backup() {
    echo -e "\n${BLUE}[Test 7]${NC} Testing database backup..."

    if ! docker ps --format '{{.Names}}' | grep -q "^rag-postgres$"; then
        log_test "Database backup" "SKIP" "PostgreSQL container not running"
        return
    fi

    echo "  Running backup-postgres.sh..."
    if "$SCRIPT_DIR/backup-postgres.sh" &>/tmp/test-backup-postgres.log; then
        local backup_dir=$(tail -1 /tmp/test-backup-postgres.log)
        if [ -d "$backup_dir" ] && [ -f "$backup_dir/postgres-full.sql.gz" ]; then
            local size=$(du -h "$backup_dir/postgres-full.sql.gz" | cut -f1)
            echo "  Backup created: $size"
            log_test "Database backup" "PASS"

            # Test backup integrity
            if gzip -t "$backup_dir/postgres-full.sql.gz" 2>/dev/null; then
                log_test "Database backup integrity" "PASS"
            else
                log_test "Database backup integrity" "FAIL" "Backup file is corrupted"
            fi
        else
            log_test "Database backup" "FAIL" "Backup files not created"
        fi
    else
        log_test "Database backup" "FAIL" "Backup script failed (see /tmp/test-backup-postgres.log)"
    fi
}

# Test 8: Test volume backup
test_volume_backup() {
    echo -e "\n${BLUE}[Test 8]${NC} Testing volume backup..."

    if ! docker volume ls -q | grep -q "rag-pgdata"; then
        log_test "Volume backup" "SKIP" "No volumes found"
        return
    fi

    echo "  Running backup-volumes.sh..."
    if "$SCRIPT_DIR/backup-volumes.sh" &>/tmp/test-backup-volumes.log; then
        local backup_dir=$(tail -1 /tmp/test-backup-volumes.log)
        if [ -d "$backup_dir" ]; then
            local volume_count=$(find "$backup_dir" -name "*.tar.gz" | wc -l)
            echo "  Backed up $volume_count volume(s)"
            log_test "Volume backup" "PASS"

            # Test backup integrity
            local corrupted=0
            for f in "$backup_dir"/*.tar.gz; do
                if [ -f "$f" ]; then
                    if ! tar tzf "$f" >/dev/null 2>&1; then
                        corrupted=$((corrupted + 1))
                    fi
                fi
            done

            if [ $corrupted -eq 0 ]; then
                log_test "Volume backup integrity" "PASS"
            else
                log_test "Volume backup integrity" "FAIL" "$corrupted volume backup(s) corrupted"
            fi
        else
            log_test "Volume backup" "FAIL" "Backup directory not created"
        fi
    else
        log_test "Volume backup" "FAIL" "Backup script failed (see /tmp/test-backup-volumes.log)"
    fi
}

# Test 9: Test full backup
test_full_backup() {
    if [ "$FULL_TEST" = false ]; then
        log_test "Full system backup" "SKIP" "Use --full flag to enable"
        return
    fi

    echo -e "\n${BLUE}[Test 9]${NC} Testing full system backup..."

    echo "  Running backup-full.sh (this may take several minutes)..."
    if "$SCRIPT_DIR/backup-full.sh" &>/tmp/test-backup-full.log; then
        local backup_dir=$(tail -1 /tmp/test-backup-full.log)
        if [ -d "$backup_dir" ] && [ -f "$backup_dir/MANIFEST.md" ]; then
            local size=$(du -sh "$backup_dir" | cut -f1)
            echo "  Full backup created: $size"
            log_test "Full system backup" "PASS"
        else
            log_test "Full system backup" "FAIL" "Backup incomplete"
        fi
    else
        log_test "Full system backup" "FAIL" "Backup script failed (see /tmp/test-backup-full.log)"
    fi
}

# Test 10: Test restore (dry run)
test_restore_dry_run() {
    echo -e "\n${BLUE}[Test 10]${NC} Testing restore (dry run)..."

    local latest_backup=$(ls -t /backups/full/ 2>/dev/null | head -1)
    if [ -z "$latest_backup" ]; then
        log_test "Restore dry run" "SKIP" "No backups found"
        return
    fi

    if "$SCRIPT_DIR/restore.sh" "$latest_backup" --dry-run --force &>/tmp/test-restore.log; then
        log_test "Restore dry run" "PASS"
    else
        log_test "Restore dry run" "FAIL" "Restore script failed (see /tmp/test-restore.log)"
    fi
}

# Test 11: Check cron setup
test_cron_setup() {
    echo -e "\n${BLUE}[Test 11]${NC} Checking cron setup..."

    if crontab -l 2>/dev/null | grep -q "RAG Scan Stack"; then
        local job_count=$(crontab -l 2>/dev/null | grep "/backup-.*\.sh" | wc -l)
        echo "  Found $job_count backup cron job(s)"
        log_test "Cron jobs configured" "PASS"
    else
        log_test "Cron jobs configured" "SKIP" "No cron jobs found (run setup-cron.sh to configure)"
    fi
}

# Test 12: Check documentation
test_documentation() {
    echo -e "\n${BLUE}[Test 12]${NC} Checking documentation..."

    if [ -f "$PROJECT_ROOT/Docs/BACKUP_RESTORE.md" ]; then
        log_test "Documentation exists" "PASS"
    else
        log_test "Documentation exists" "FAIL" "BACKUP_RESTORE.md not found"
    fi
}

# Print summary
print_summary() {
    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo "Total Tests: $total"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    else
        echo "Failed: 0"
    fi
    if [ $TESTS_SKIPPED -gt 0 ]; then
        echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    else
        echo "Skipped: 0"
    fi
    echo "=========================================="

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        echo ""
        echo "The backup system appears to be working correctly."
        if [ $TESTS_SKIPPED -gt 0 ]; then
            echo ""
            echo "Note: Some tests were skipped. This may be normal if:"
            echo "  - Services are not yet started"
            echo "  - No backups exist yet"
            echo "  - Cron jobs not configured yet"
        fi
        return 0
    else
        echo -e "${RED}✗ Some tests failed!${NC}"
        echo ""
        echo "Please review the failures above and:"
        echo "  1. Check that Docker is running"
        echo "  2. Ensure PostgreSQL container is started"
        echo "  3. Verify backup directory permissions"
        echo "  4. Review log files in /tmp/test-backup-*.log"
        return 1
    fi
}

# Main execution
main() {
    test_scripts_exist
    test_config_exists
    test_backup_directory
    test_docker_running
    test_postgres_container
    test_postgres_accessible
    test_database_backup
    test_volume_backup
    test_full_backup
    test_restore_dry_run
    test_cron_setup
    test_documentation

    print_summary
}

# Run tests
main
