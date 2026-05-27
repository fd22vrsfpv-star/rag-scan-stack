#!/bin/bash
# Update Database Role Passwords from .env
# Run this script after generating new credentials to update database passwords

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Update Database Role Passwords                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "   Please run ./generate-credentials.sh first"
    exit 1
fi

# Load environment variables
source .env

# Check if required variables are set
if [ -z "$POSTGRES_PASSWORD" ] || [ -z "$N8N_PASSWORD" ] || [ -z "$EXPLOITDB_PASSWORD" ] || [ -z "$SCANS_PASSWORD" ]; then
    echo "❌ Error: Required password variables not set in .env"
    echo "   Please ensure N8N_PASSWORD, EXPLOITDB_PASSWORD, SCANS_PASSWORD are set"
    exit 1
fi

echo "🔄 Updating database role passwords..."
echo ""

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
timeout=60
elapsed=0
until docker exec rag-postgres pg_isready -U app -d scans > /dev/null 2>&1; do
    if [ $elapsed -ge $timeout ]; then
        echo "❌ Error: PostgreSQL did not become ready in time"
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    echo -n "."
done
echo ""
echo "✓ PostgreSQL is ready"
echo ""

# Update role passwords
echo "Updating role passwords..."

# Update n8n password
docker exec rag-postgres psql -U app -d postgres -c "ALTER ROLE n8n WITH PASSWORD '${N8N_PASSWORD}';" 2>&1 | grep -v "ALTER ROLE" || true
echo "✓ Updated n8n role password"

# Update exploitdb password
docker exec rag-postgres psql -U app -d postgres -c "ALTER ROLE exploitdb WITH PASSWORD '${EXPLOITDB_PASSWORD}';" 2>&1 | grep -v "ALTER ROLE" || true
echo "✓ Updated exploitdb role password"

# Create edb_rw role if it doesn't exist and set password
docker exec rag-postgres psql -U app -d postgres -c "DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'edb_rw') THEN
    CREATE ROLE edb_rw LOGIN PASSWORD '${EXPLOITDB_PASSWORD}';
  ELSE
    ALTER ROLE edb_rw WITH PASSWORD '${EXPLOITDB_PASSWORD}';
  END IF;
END\$\$;" 2>&1 | grep -v "DO" || true
echo "✓ Updated edb_rw role password"

# Grant edb_rw access to exploitdb database
docker exec rag-postgres psql -U app -d exploitdb -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO edb_rw;" 2>&1 | grep -v "GRANT" || true
docker exec rag-postgres psql -U app -d exploitdb -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO edb_rw;" 2>&1 | grep -v "GRANT" || true
echo "✓ Granted edb_rw privileges on exploitdb database"

# Update scans password
docker exec rag-postgres psql -U app -d postgres -c "ALTER ROLE scans WITH PASSWORD '${SCANS_PASSWORD}';" 2>&1 | grep -v "ALTER ROLE" || true
echo "✓ Updated scans role password"

# Update the main app user password
docker exec rag-postgres psql -U app -d postgres -c "ALTER ROLE app WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>&1 | grep -v "ALTER ROLE" || true
echo "✓ Updated app role password"

echo ""
echo "✓ All database role passwords updated successfully!"
echo ""
echo "📝 Next Steps:"
echo "─────────────────────────────────────────────────────────────"
echo "1. Update Kong configuration:"
echo "   ./update-kong-config.sh"
echo "2. Restart services to apply changes:"
echo "   docker-compose restart"
echo "─────────────────────────────────────────────────────────────"
