# RAG Scan Stack - Security Setup Guide

## Overview

This guide explains how to securely configure credentials for the RAG Scan Stack. The system uses a centralized credential management approach where all API keys, database passwords, and security tokens are stored in a single `.env` file.

## Quick Start

For first-time setup, run these commands in order:

```bash
# 1. Generate secure random credentials
./generate-credentials.sh

# 2. Start all containers (uses default init passwords)
docker-compose up -d

# 3. Wait for PostgreSQL to be ready (30-60 seconds)
docker-compose logs -f rag-postgres

# 4. Update database passwords to secure values from .env
./update-database-credentials.sh

# 5. Update Kong API Gateway configuration
./update-kong-config.sh

# 6. Restart services to apply all changes
docker-compose restart
```

## Detailed Workflow

### Step 1: Generate Credentials

The `generate-credentials.sh` script creates a secure `.env` file with cryptographically random credentials:

```bash
./generate-credentials.sh
```

**What it generates:**
- `API_KEY` - 64-character hex string for API authentication
- `POSTGRES_PASSWORD` - 32-character password for PostgreSQL superuser
- `ZAP_API_KEY` - 64-character hex string for ZAP Proxy
- `KONG_ADMIN_TOKEN` - 64-character hex string for Kong Admin API
- `N8N_PASSWORD` - 24-character password for n8n database role
- `EXPLOITDB_PASSWORD` - 24-character password for exploitdb database role
- `SCANS_PASSWORD` - 24-character password for scans database role

**Security features:**
- Uses `openssl rand` for cryptographic randomness
- Creates backup of existing `.env` before overwriting
- Sets restrictive file permissions (`chmod 600`)
- Provides clear documentation and warnings

### Step 2: Initial Container Startup

```bash
docker-compose up -d
```

During initial startup, PostgreSQL runs initialization scripts in `/db_init/` that:
- Create database roles with **temporary initialization passwords**
- Set up database schemas and tables
- Configure extensions (pgvector, uuid-ossp, etc.)

**⚠️ IMPORTANT:** The database roles start with temporary passwords like `n8n_temp_init_pwd`. These MUST be changed immediately using the update script.

### Step 3: Update Database Passwords

Once PostgreSQL is running, update all database role passwords:

```bash
./update-database-credentials.sh
```

**What it does:**
- Loads secure passwords from `.env`
- Connects to running PostgreSQL container
- Executes `ALTER ROLE` commands to update passwords:
  - `n8n` role → `$N8N_PASSWORD`
  - `exploitdb` role → `$EXPLOITDB_PASSWORD`
  - `edb_rw` role → `$EXPLOITDB_PASSWORD`
  - `scans` role → `$SCANS_PASSWORD`
  - `app` role → `$POSTGRES_PASSWORD`

**Requirements:**
- PostgreSQL container must be running and healthy
- `.env` file must exist with valid credentials

### Step 4: Update Kong Configuration

Update the Kong API Gateway to use the secure API key:

```bash
./update-kong-config.sh
```

**What it does:**
- Loads `API_KEY` from `.env`
- Updates `kong/kong.yml` configuration
- Replaces all instances of `x-api-key: change-me` with actual API key
- Creates backup of previous configuration

### Step 5: Restart Services

Restart all services to apply the new credentials:

```bash
docker-compose restart
```

Alternatively, for a full rebuild:

```bash
docker-compose down
docker-compose up -d
```

## Credential Storage

### .env File

All credentials are stored in `/opt/rag-scan-stack/.env`:

```bash
# View current credentials (requires appropriate permissions)
cat .env

# Check file permissions (should be 600)
ls -la .env
```

**Security requirements:**
- File permissions must be `600` (owner read/write only)
- Never commit `.env` to version control
- Backup securely in encrypted storage
- Rotate credentials periodically

### .env.example Template

The `.env.example` file shows all available configuration options with safe placeholder values:

```bash
# Copy template to create new .env (not recommended - use generate-credentials.sh instead)
cp .env.example .env

# View all available configuration options
cat .env.example
```

**⚠️ WARNING:** Do not use `.env.example` directly in production. Always run `generate-credentials.sh` to create secure random credentials.

## Database Security

### Role-Based Access Control

The system uses multiple PostgreSQL roles with different permissions:

| Role | Database | Permissions | Used By |
|------|----------|-------------|---------|
| `app` | All | Superuser | Main application, initialization |
| `n8n` | `n8n` | Owner | n8n workflow automation (if configured) |
| `exploitdb` | `exploitdb` | Owner | ExploitDB ETL service |
| `edb_rw` | `exploitdb` | Read/Write | ExploitDB read-write operations |
| `scans` | `scans` | Owner | Scan storage and RAG operations |

### Connection Strings

Application services connect to PostgreSQL using connection strings from `.env`:

```bash
# Main application DSN
DB_DSN=postgresql://app:${POSTGRES_PASSWORD}@rag-postgres:5432/scans

# ExploitDB ETL DSN (read-write)
PG_DSN=postgres://edb_rw:${EXPLOITDB_PASSWORD}@rag-postgres:5432/exploits
```

## API Security

### API Key Authentication

All backend services require API key authentication via the `x-api-key` header:

```bash
# Test RAG API with authentication
curl -H "x-api-key: YOUR_API_KEY" http://localhost:8000/health

# Test via Kong Gateway (automatically injects API key)
curl http://localhost:7080/rag-api/health
```

### Kong Gateway Configuration

Kong acts as a reverse proxy that:
- Routes requests to backend services
- Automatically injects `x-api-key` header
- Provides centralized access control
- Enables rate limiting (can be configured)

**Configuration file:** `/opt/rag-scan-stack/kong/kong.yml`

## Rotating Credentials

To rotate credentials for security:

```bash
# 1. Generate new credentials (backs up existing .env)
./generate-credentials.sh

# 2. Update database passwords
./update-database-credentials.sh

# 3. Update Kong configuration
./update-kong-config.sh

# 4. Restart all services
docker-compose restart
```

**⚠️ IMPORTANT:** Rotating credentials may cause temporary service disruption. Plan accordingly.

## Troubleshooting

### "PostgreSQL did not become ready in time"

The update-database-credentials.sh script waits up to 60 seconds for PostgreSQL:

```bash
# Check PostgreSQL status
docker-compose logs rag-postgres

# Manually test connection
docker exec rag-postgres pg_isready -U app -d scans

# If PostgreSQL is stuck, restart it
docker-compose restart rag-postgres
```

### "Error: .env file not found"

You must run `generate-credentials.sh` first:

```bash
./generate-credentials.sh
```

### "Permission denied" when running scripts

Make scripts executable:

```bash
chmod +x generate-credentials.sh
chmod +x update-database-credentials.sh
chmod +x update-kong-config.sh
```

### Services can't authenticate

Verify credentials are correctly loaded:

```bash
# Check .env has correct format
cat .env | grep API_KEY

# Verify environment variables are passed to containers
docker-compose config | grep API_KEY

# Check specific service environment
docker exec rag-api printenv | grep API_KEY
```

### Database connection refused

Ensure PostgreSQL is running and passwords are updated:

```bash
# Check PostgreSQL is running
docker-compose ps rag-postgres

# Re-run password update
./update-database-credentials.sh

# Test connection manually
docker exec rag-postgres psql -U app -d scans -c "SELECT version();"
```

## Best Practices

### 1. Secure .env File

```bash
# Set restrictive permissions
chmod 600 .env

# Verify only owner can read
ls -la .env
# Should show: -rw------- 1 user user ...

# Never commit to git
echo ".env" >> .gitignore
```

### 2. Backup Credentials

```bash
# Create encrypted backup
gpg -c .env -o .env.gpg

# Store in secure location (NOT in the same directory)
cp .env.gpg ~/secure-backups/rag-stack-env-$(date +%Y%m%d).gpg
```

### 3. Rotate Regularly

Rotate credentials every 90 days or after:
- Team member departure
- Suspected credential exposure
- Security incident
- Major system updates

### 4. Monitor Access

```bash
# Check PostgreSQL connection logs
docker-compose logs rag-postgres | grep "connection authorized"

# Monitor failed authentication attempts
docker-compose logs rag-postgres | grep "authentication failed"

# Review Kong access logs
docker-compose logs kong | grep "x-api-key"
```

### 5. Principle of Least Privilege

- Each service has its own database role with minimal required permissions
- API keys are service-specific (can be separated further if needed)
- Kong provides an additional security layer for external access

## Security Checklist

Before deploying to production:

- [ ] Run `generate-credentials.sh` to create secure random credentials
- [ ] Verify `.env` file permissions are `600`
- [ ] Run `update-database-credentials.sh` after initial startup
- [ ] Run `update-kong-config.sh` to update API gateway
- [ ] Confirm no hardcoded credentials remain in configuration files
- [ ] Backup `.env` file in encrypted secure storage
- [ ] Add `.env` to `.gitignore`
- [ ] Test authentication on all services
- [ ] Document credential rotation schedule
- [ ] Configure firewall rules to restrict port access
- [ ] Enable HTTPS for external access (not implemented yet)
- [ ] Set up monitoring and alerting for authentication failures

## Additional Security Recommendations

### Network Security

```bash
# Restrict PostgreSQL to internal network only (already configured)
# See docker-compose.yml - PostgreSQL has no exposed ports

# Use firewall to restrict access to service ports
# See setup-rag-port-forwarding.ps1 for Windows firewall rules
```

### Container Security

```bash
# Run containers with security options
docker-compose.yml includes:
- restart: unless-stopped (automatic recovery)
- cap_add: NET_RAW, NET_ADMIN (only for services needing raw sockets)
- healthchecks (monitor service availability)
```

### Logging and Monitoring

```bash
# View all container logs
docker-compose logs -f

# Monitor specific service
docker-compose logs -f rag-postgres

# Check for errors
docker-compose logs | grep -i error
```

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review container logs: `docker-compose logs`
3. Verify configuration: `docker-compose config`
4. Test connectivity: `./test-remote-access.sh`

---

**Last Updated:** 2024-11-18
**Version:** 1.0
