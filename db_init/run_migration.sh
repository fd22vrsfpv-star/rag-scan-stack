#!/bin/bash
# Database Migration Script - Phase 1
# Adds missing tables to existing database

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}  Pentest Service - Database Migration${NC}"
echo -e "${GREEN}  Phase 1: Critical Schema Fixes${NC}"
echo -e "${GREEN}===============================================${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Check if rag-postgres container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^rag-postgres$"; then
    echo -e "${YELLOW}Warning: rag-postgres container not found${NC}"
    echo "Creating database from scratch..."
    cd /utils/agents && docker compose up -d rag-postgres
    echo "Waiting for database to initialize..."
    sleep 15
    echo -e "${GREEN}Database created with new schema${NC}"
    exit 0
fi

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^rag-postgres$"; then
    echo "Starting rag-postgres container..."
    cd /utils/agents && docker compose up -d rag-postgres
    sleep 5
fi

echo "Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if docker exec rag-postgres pg_isready -U app -d scans > /dev/null 2>&1; then
        echo -e "${GREEN}Database is ready!${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}Timeout waiting for database${NC}"
        exit 1
    fi
    sleep 1
done

echo ""
echo "Checking existing tables..."
EXISTING_TABLES=$(docker exec rag-postgres psql -U app -d scans -t -c "\dt" | wc -l)
echo "Found $EXISTING_TABLES existing tables"

echo ""
echo -e "${YELLOW}Applying migration...${NC}"
docker exec -i rag-postgres psql -U app -d scans < /utils/agents/db_init/add_missing_tables.sql

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Migration completed successfully!${NC}"
else
    echo -e "${RED}Migration failed${NC}"
    exit 1
fi

echo ""
echo "Verifying new tables..."
echo ""

# Check each critical table
TABLES=("web_findings" "vulns" "scan_recommendations" "playwright_scans" "playwright_findings" "playwright_screenshots" "dom_analysis" "zap_sessions")

for table in "${TABLES[@]}"; do
    if docker exec rag-postgres psql -U app -d scans -t -c "SELECT to_regclass('public.$table');" | grep -q "$table"; then
        echo -e "  ${GREEN}✓${NC} $table"
    else
        echo -e "  ${RED}✗${NC} $table"
    fi
done

echo ""
echo "Checking views..."
VIEWS=("all_high_severity_findings" "pending_scan_recommendations")

for view in "${VIEWS[@]}"; do
    if docker exec rag-postgres psql -U app -d scans -t -c "SELECT to_regclass('public.$view');" | grep -q "$view"; then
        echo -e "  ${GREEN}✓${NC} $view"
    else
        echo -e "  ${RED}✗${NC} $view"
    fi
done

echo ""
echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}  Migration Summary${NC}"
echo -e "${GREEN}===============================================${NC}"
echo ""
echo "Added tables:"
echo "  • web_findings (CRITICAL - web_scanner.py)"
echo "  • vulns (CRITICAL - /vulns endpoint)"
echo "  • scan_recommendations (scan_recommender.py)"
echo "  • playwright_scans (Phase 2)"
echo "  • playwright_findings (Phase 2)"
echo "  • playwright_screenshots (Phase 2)"
echo "  • dom_analysis (Phase 2)"
echo "  • zap_sessions (Playwright-ZAP bridge)"
echo ""
echo "Added views:"
echo "  • all_high_severity_findings"
echo "  • pending_scan_recommendations"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Restart your services: docker compose restart"
echo "2. Test web scanner: curl -X POST http://localhost:8010/jobs/web-scan ..."
echo "3. Test vulns endpoint: curl -H 'x-api-key: changeme' http://localhost:8000/vulns"
echo "4. See MIGRATION_GUIDE.md for detailed testing"
echo ""
echo -e "${GREEN}Ready for Phase 2: Playwright Integration${NC}"
