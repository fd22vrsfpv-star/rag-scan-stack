# Database Schema Management

This document explains how the RAG Scan Stack manages its database schema and how to ensure all required tables are present.

## Overview

The stack uses PostgreSQL with pgvector extension for storing:
- **Assets & Ports**: Network inventory
- **Scan Results**: Nmap, Nuclei, ZAP, Playwright findings
- **Recommendations**: AI-generated next-step suggestions
- **Agent Sessions**: Multi-agent conversation history
- **Exploits**: ExploitDB vulnerability database

## Schema Files

### Primary Schema File
- **`db_init/setup_alldb.sql`** - Complete schema for fresh installations
  - Creates 3 databases: `n8n`, `exploitdb`, `scans`
  - Defines all 21+ tables with indexes, triggers, and views
  - Runs automatically on first container startup

### Migration Scripts
- **`db_init/ensure_all_tables.sql`** - Idempotent schema update
  - Safe to run multiple times (uses `IF NOT EXISTS`)
  - Adds any missing tables to existing databases
  - Fixes schema drift issues

- **`db_init/create_agent_tables.sql`** - Agent-specific tables
  - `agent_sessions` and `agent_messages`
  - Can be run independently if only these are missing

- **`db_init/add_missing_tables.sql`** - Legacy migration script
  - Adds tables that were missing in older versions
  - Now superseded by `ensure_all_tables.sql`

## Database Initialization Process

### Fresh Installation
When starting with an empty database volume:

```bash
docker compose up -d rag-postgres
```

PostgreSQL automatically runs all `.sql` and `.sh` files in `/docker-entrypoint-initdb.d/` (mounted from `./db_init/`).

**Files executed (alphabetically):**
1. `create_agent_tables.sql`
2. `create_exploits.sh`
3. `ensure_all_tables.sql`
4. `setup_alldb.sql`

### Existing Installation
If your database was initialized before recent schema updates:

#### Option 1: Automated Script (Recommended)
```bash
./scripts/ensure_db_schema.sh
```

This script:
- ✓ Checks PostgreSQL availability
- ✓ Counts current tables
- ✓ Applies missing tables
- ✓ Verifies all critical tables exist
- ✓ Provides detailed status output

#### Option 2: Manual SQL Execution
```bash
docker exec rag-postgres psql -U app -d scans \
  -f /docker-entrypoint-initdb.d/ensure_all_tables.sql
```

#### Option 3: Fresh Database (⚠️ Destroys Data)
```bash
docker compose down
docker volume rm rag-scan-stack_rag-pgdata
docker compose up -d rag-postgres
```

## Required Tables

### Core Tables (6)
- `assets` - Network hosts and IPs
- `ports` - Open ports and services
- `scans` - Scan execution metadata
- `jobs` - Job queue management
- `tasks` - Task queue management
- `findings` - Generic findings

### Web Scanning (1)
- `web_findings` - Gobuster, ZAP, Playwright results

### Vulnerability Management (1)
- `vulns` - Nmap NSE vulnerability findings

### Scan Intelligence (1)
- `scan_recommendations` - AI-suggested next scans

### Playwright/Browser Testing (4)
- `playwright_scans` - Browser automation sessions
- `playwright_findings` - Client-side security issues
- `playwright_screenshots` - Visual evidence
- `dom_analysis` - DOM structure and security headers

### Integration (1)
- `zap_sessions` - ZAP proxy session tracking

### Agent System (2)
- `agent_sessions` - Multi-agent scan sessions
- `agent_messages` - Agent conversation history

### Supporting Tables (6)
- `port_observation` - Detailed port scan data
- `raw_output` - Raw scan output storage
- `scan_targets` - Scan target tracking
- `finding_evidence` - Finding evidence links
- `cve` - CVE metadata cache
- `dom_analysis` - DOM security analysis

## Common Issues

### Issue: "relation does not exist"
**Cause**: Table missing from database schema

**Solution**: Run the schema verification script
```bash
./scripts/ensure_db_schema.sh
```

### Issue: PostgreSQL init scripts not running
**Cause**: Database volume already exists from previous initialization

**Solution**:
- For production: Use migration scripts (Option 1 or 2 above)
- For development: Reset volume (Option 3 above)

### Issue: Schema drift after git pull
**Cause**: New tables added to setup_alldb.sql but not to existing database

**Solution**: Always run after pulling updates:
```bash
./scripts/ensure_db_schema.sh
```

## Development Workflow

### Adding New Tables

1. **Edit `db_init/setup_alldb.sql`**
   - Add table definition in appropriate section
   - Use `CREATE TABLE IF NOT EXISTS`
   - Add indexes and triggers
   - Update views if needed

2. **Edit `db_init/ensure_all_tables.sql`**
   - Mirror the same table definition
   - Ensures existing installations get the new table

3. **Test Migration**
   ```bash
   # On a development database with existing data
   ./scripts/ensure_db_schema.sh

   # Verify table was created
   docker exec rag-postgres psql -U app -d scans \
     -c "\d your_new_table"
   ```

4. **Document Changes**
   - Update this file with new table description
   - Update API documentation if needed
   - Add to MIGRATION_GUIDE.md if breaking changes

### Best Practices

- ✅ Always use `IF NOT EXISTS` for idempotency
- ✅ Add indexes for foreign keys and query patterns
- ✅ Use `updated_at` triggers for timestamp maintenance
- ✅ Test migrations on copy of production data
- ✅ Document column purposes in SQL comments
- ❌ Don't use reserved keywords as column names (e.g., `references`)
- ❌ Don't remove columns without migration path
- ❌ Don't change column types without data conversion

## Backup and Restore

### Backup Schema Only
```bash
docker exec rag-postgres pg_dump -U app -d scans \
  --schema-only > backup_schema.sql
```

### Backup Data Only
```bash
docker exec rag-postgres pg_dump -U app -d scans \
  --data-only > backup_data.sql
```

### Backup Complete Database
```bash
docker exec rag-postgres pg_dump -U app -d scans \
  > backup_complete.sql
```

### Restore
```bash
docker exec -i rag-postgres psql -U app -d scans \
  < backup_complete.sql
```

## Monitoring

### Check Table Sizes
```bash
docker exec rag-postgres psql -U app -d scans -c "
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

### Check Row Counts
```bash
docker exec rag-postgres psql -U app -d scans -c "
SELECT
  schemaname,
  tablename,
  n_live_tup as rows
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_live_tup DESC;
"
```

### Check Missing Indexes
```bash
docker exec rag-postgres psql -U app -d scans -c "
SELECT
  schemaname,
  tablename,
  attname,
  n_distinct,
  correlation
FROM pg_stats
WHERE schemaname = 'public'
  AND n_distinct > 100
  AND correlation < 0.1;
"
```

## Support

For database issues:
1. Check logs: `docker compose logs rag-postgres`
2. Verify schema: `./scripts/ensure_db_schema.sh`
3. Review migration guide: `db_init/MIGRATION_GUIDE.md`
4. Report issues with full error output and schema state
