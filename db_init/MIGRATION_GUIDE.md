# Database Migration Guide

## Phase 1 - Critical Database Schema Fixes

### What's Been Fixed

This migration adds **critical missing tables** to the `scans` database that are required by the application but were not in the schema:

#### Critical Tables (Blocking Issues):
1. **`web_findings`** - Used by web_scanner.py but was only in n8n database
2. **`vulns`** - Used by api.py `/vulns` endpoint but didn't exist
3. **`scan_recommendations`** - Used by scan_recommender.py but didn't exist

#### New Tables for Phase 2 (Playwright Integration):
4. **`playwright_scans`** - Scan execution tracking
5. **`playwright_findings`** - Security findings from browser testing
6. **`playwright_screenshots`** - Screenshot storage
7. **`dom_analysis`** - Client-side security analysis
8. **`zap_sessions`** - ZAP/Playwright integration tracking

### Migration Options

#### Option 1: Fresh Database (Recommended for Development)
If you can afford to reset your database:

```bash
# Stop all containers
docker compose down

# Remove the database volume
docker volume rm rag-scan-stack_rag-pgdata

# Start fresh with new schema
docker compose up -d rag-postgres

# Wait for database to initialize (setup_alldb.sql runs automatically)
docker compose logs -f rag-postgres

# Start remaining services
docker compose up -d
```

#### Option 2: Migrate Existing Database (Preserves Data)
If you need to keep existing data:

```bash
# Ensure containers are running
docker compose up -d rag-postgres

# Wait for database to be ready
sleep 10

# Apply migration
docker exec -i rag-postgres psql -U app -d scans < /utils/agents/db_init/add_missing_tables.sql

# Verify tables were created
docker exec -it rag-postgres psql -U app -d scans -c "\dt" | grep -E "web_findings|vulns|scan_recommendations|playwright"
```

#### Option 3: Manual psql Command
```bash
# Connect to running database
docker exec -it rag-postgres psql -U app -d scans

# Then run SQL manually (paste the content of add_missing_tables.sql)
# Or source it:
# \i /docker-entrypoint-initdb.d/add_missing_tables.sql
```

### Verification Commands

After migration, verify the tables exist:

```bash
# List all tables
docker exec -it rag-postgres psql -U app -d scans -c "\dt"

# Check web_findings structure
docker exec -it rag-postgres psql -U app -d scans -c "\d web_findings"

# Check vulns structure
docker exec -it rag-postgres psql -U app -d scans -c "\d vulns"

# Check scan_recommendations structure
docker exec -it rag-postgres psql -U app -d scans -c "\d scan_recommendations"

# View all indexes
docker exec -it rag-postgres psql -U app -d scans -c "\di" | grep -E "web_findings|vulns|scan_recommendations|playwright"
```

### What's Changed in setup_alldb.sql

The main schema file (`/utils/agents/db_init/setup_alldb.sql`) has been updated to include all new tables. This means:
- **Fresh deployments** will automatically get all tables
- **Existing deployments** need to run the migration (Option 2 above)

### Testing After Migration

```bash
# 1. Test web scanner (should no longer fail on web_findings insert)
curl -X POST "http://localhost:8010/jobs/web-scan" \
  -H "Content-Type: application/json" \
  -d '{"do_gobuster": false, "do_zap": true, "limit": 1}'

# 2. Test vulns endpoint (should no longer return 500 error)
curl -H "x-api-key: changeme" "http://localhost:8000/vulns?limit=10"

# 3. Test scan recommendations (should persist to database)
curl "http://localhost:8013/next_scan?ip=192.168.1.1&persist=true"
```

### Rollback (If Needed)

If you encounter issues, you can drop the new tables:

```bash
docker exec -it rag-postgres psql -U app -d scans <<EOF
DROP VIEW IF EXISTS all_high_severity_findings CASCADE;
DROP VIEW IF EXISTS pending_scan_recommendations CASCADE;
DROP TABLE IF EXISTS zap_sessions CASCADE;
DROP TABLE IF EXISTS dom_analysis CASCADE;
DROP TABLE IF EXISTS playwright_screenshots CASCADE;
DROP TABLE IF EXISTS playwright_findings CASCADE;
DROP TABLE IF EXISTS playwright_scans CASCADE;
DROP TABLE IF EXISTS scan_recommendations CASCADE;
DROP TABLE IF EXISTS vulns CASCADE;
DROP TABLE IF EXISTS web_findings CASCADE;
EOF
```

## Next Steps

After completing Phase 1 database migration:

### Phase 2: Playwright Integration
- Create `playwright-scanner` service
- Implement browser automation scanning
- Configure Playwright-ZAP proxy bridge

### Phase 3: Autogen Multi-Agent System
- Add autogen container
- Configure agent roles
- Integrate with existing services

### Phase 4: MCP (Model Context Protocol)
- Create MCP server
- Expose pentest operations as MCP tools
- Enable natural language control

## Troubleshooting

### Issue: "relation does not exist"
- Tables weren't created - check migration output for errors
- Run verification commands above

### Issue: "column does not exist"
- Partial migration - may need to drop tables and re-run
- Check that add_missing_tables.sql completed fully

### Issue: web_scanner still failing
- Check that web_findings exists in `scans` database (not n8n database)
- Verify DB_DSN environment variable points to scans database

### Issue: Permission denied
- Tables created but grants didn't apply
- Run: `docker exec -it rag-postgres psql -U app -d scans -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO app;"`

## Database Schema Reference

### web_findings
Stores findings from Gobuster, ZAP, and Playwright web scans.

Key columns:
- `url`, `source`, `issue_type`, `name`, `severity`
- `status_code`, `method`, `payload`, `cwe`

### vulns
Stores vulnerabilities detected by Nmap NSE scripts.

Key columns:
- `script`, `output`, `severity`, `cve`, `cvss`
- Foreign keys to `assets` and `ports`

### scan_recommendations
AI-generated next scan suggestions.

Key columns:
- `scanner`, `action`, `script`, `template`
- `source` ('rules', 'ollama', 'autogen')
- `priority`, `confidence`, `status`
- `fingerprint` (auto-generated hash for deduplication)

### playwright_scans
Browser automation scan sessions.

Key columns:
- `url`, `status`, `browser`, `viewport`
- `screenshots`, `console_logs`, `network_logs`

### playwright_findings
Security issues found during browser testing.

Key columns:
- `finding_type`, `severity`, `title`, `evidence`
- `cwe`, `owasp_category`, `confidence`

### Views

#### all_high_severity_findings
Unified view of high/critical findings from all sources (web, vuln, playwright).

#### pending_scan_recommendations
Scan recommendations ready to be executed, ordered by priority.

## Support

If you encounter issues with the migration:
1. Check docker logs: `docker compose logs rag-postgres`
2. Verify PostgreSQL version: `docker exec rag-postgres psql --version`
3. Check pgvector extension: `docker exec -it rag-postgres psql -U app -d scans -c "\dx"`
4. Report issues with full error output
