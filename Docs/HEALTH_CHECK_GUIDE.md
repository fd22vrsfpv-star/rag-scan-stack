# Health Check System - Quick Reference Guide

## Overview

The RAG Scan Stack now includes a comprehensive health check system that verifies all services, databases, and tools are available and ready for scanning operations.

## Quick Start

### Command Line

```bash
# Run complete health check
./scripts/optional/check_system_health.sh

# Get JSON output
./scripts/optional/check_system_health.sh --json

# Get MCP-formatted output
./scripts/optional/check_system_health.sh --mcp

# Verbose mode (show all checks)
./scripts/optional/check_system_health.sh --verbose
```

### MCP Tool (via Claude Desktop/Code)

After configuring the MCP server (see [MCP README](../mcp/README.md)), ask Claude:

```
Check if all RAG Scan Stack services are healthy
```

```
What's the health status of the scanning tools?
```

```
List all running containers
```

## What Gets Checked

### ✓ Infrastructure (3 checks)
- Docker daemon availability
- Docker network configuration (agents_net)
- All required containers running

### ✓ Database (3 checks)
- PostgreSQL connectivity
- Table count (21 tables expected)
- Critical tables exist (assets, ports, web_findings, vulns, scan_recommendations, agent_sessions)

### ✓ AI/LLM (1 check)
- Ollama service running
- Required models available (nomic-embed-text, hermes-3-llama-3.1-8b-tools)

### ✓ Services (8 checks)
- rag-api (port 8000)
- web-scanner (port 8010)
- nuclei-runner (port 8011)
- nmap-scanner (port 8012)
- scan-recommender (port 8013)
- playwright-scanner (port 8014)
- autogen-agents (port 8015)
- llm-query (port 8002)

### ✓ Gateway (1 check)
- Kong API Gateway (port 7080)

### ✓ Tools (4 checks)
- nmap scanner
- nuclei scanner
- gobuster
- playwright

**Total: 19 automated checks**

## Output Formats

### Human-Readable (Default)

```
========================================
  RAG Scan Stack - System Health Check
========================================

ℹ Checking Docker availability...
✓ Docker is available
ℹ Checking Docker network...
✓ Docker network 'agents_net' exists
...

========================================
  Health Check Summary
========================================
Total Checks:  19
Passed:        19
Failed:        0
Warnings:      0

Health Score:  100%

✓ System is ready for scanning operations

Access points:
  - Kong API Gateway:    http://localhost:7080
  - Swagger UI:          http://localhost:7080/docs
  - RAG API:             http://localhost:8000
  - Autogen Agents:      http://localhost:8015
```

### JSON Format

```json
{
  "summary": {
    "total": 19,
    "passed": 19,
    "failed": 0,
    "warnings": 0,
    "health_percentage": 100
  },
  "checks": [
    {
      "check": "docker",
      "status": "pass",
      "message": "Docker is available and accessible",
      "details": ""
    },
    ...
  ]
}
```

### MCP Format

```json
{
  "status": "healthy",
  "total_checks": 19,
  "passed": 19,
  "failed": 0,
  "warnings": 0,
  "health_score": 100,
  "ready_for_operations": true
}
```

## Exit Codes

- `0` - All checks passed, system ready
- `1` - One or more checks failed

## Common Issues

### Issue: "Docker daemon not accessible"

**Solution:**
```bash
# Start Docker Desktop (Windows/Mac)
# Or start Docker service (Linux)
sudo systemctl start docker
```

### Issue: "Container not found"

**Solution:**
```bash
# Start all services
docker compose up -d

# Or rebuild specific service
docker compose up -d --build [service-name]
```

### Issue: "Database missing tables"

**Solution:**
```bash
# Run database schema verification
./scripts/ensure_db_schema.sh
```

### Issue: "Service not responding"

**Solution:**
```bash
# Check service logs
docker compose logs [service-name]

# Restart service
docker compose restart [service-name]

# Rebuild if needed
docker compose up -d --build [service-name]
```

### Issue: "Ollama models missing"

**Solution:**
```bash
# Check Ollama logs
docker compose logs ollama

# Restart Ollama init service
docker compose restart ollama-init

# Manually pull models
docker exec ollama ollama pull nomic-embed-text
docker exec ollama ollama pull interstellarninja/hermes-3-llama-3.1-8b-tools
```

## MCP Integration

### Setup for Claude Desktop

1. Install MCP package:
   ```bash
   cd /opt/rag-scan-stack/mcp
   pip install -r requirements.txt
   ```

2. Add to Claude Desktop config:

   **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

   **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "rag-scan-stack-health": {
         "command": "python3",
         "args": ["/opt/rag-scan-stack/mcp/health-check-server.py"]
       }
     }
   }
   ```

3. Restart Claude Desktop

### Available MCP Tools

1. **check_system_health** - Complete health check
2. **check_database_schema** - Database verification
3. **check_service** - Individual service check
4. **list_running_containers** - Container status

See [MCP README](../mcp/README.md) for detailed documentation.

## Automation

### Periodic Health Checks (Cron)

```bash
# Add to crontab
crontab -e

# Check every 15 minutes, log results
*/15 * * * * /opt/rag-scan-stack/scripts/optional/check_system_health.sh >> /var/log/rag-health.log 2>&1

# Email alerts on failure
*/15 * * * * /opt/rag-scan-stack/scripts/optional/check_system_health.sh || echo "Health check failed" | mail -s "Alert" admin@example.com
```

### Systemd Timer (Linux)

See [MCP README - Automation section](../mcp/README.md#automation) for systemd service configuration.

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Health Check
  run: |
    ./scripts/optional/check_system_health.sh
  timeout-minutes: 2

# GitLab CI example
health_check:
  script:
    - ./scripts/optional/check_system_health.sh
  timeout: 2m
```

## Monitoring Integration

### Prometheus

Export health check metrics:

```bash
# Add to prometheus exporter
./scripts/optional/check_system_health.sh --json | \
  jq -r '.summary | "rag_health_score \(.health_percentage)"'
```

### Grafana

Create dashboard using health check JSON output:

```bash
# Query Prometheus
rag_health_score > 90  # Alert if below 90%
```

## Development

### Adding New Checks

Edit `scripts/optional/check_system_health.sh`:

```bash
check_my_service() {
    log_info "Checking my service..."

    if curl -s -f http://localhost:9000/health &>/dev/null; then
        log_success "My service is healthy"
        add_result "my_service" "pass" "Service operational" ""
        return 0
    else
        log_error "My service is down"
        add_result "my_service" "fail" "Service not responding" ""
        return 1
    fi
}

# Add to main()
check_my_service
```

### Testing

```bash
# Test the script
./scripts/optional/check_system_health.sh --verbose

# Test with failures (stop a service)
docker compose stop nuclei-runner
./scripts/optional/check_system_health.sh

# Restart and retest
docker compose start nuclei-runner
./scripts/optional/check_system_health.sh
```

## Best Practices

1. **Run health checks after deployments**
   ```bash
   docker compose up -d --build
   sleep 30  # Wait for services to start
   ./scripts/optional/check_system_health.sh
   ```

2. **Include in startup scripts**
   ```bash
   #!/bin/bash
   docker compose up -d
   echo "Waiting for services..."
   sleep 30

   if ./scripts/optional/check_system_health.sh; then
       echo "System ready!"
   else
       echo "Health check failed, review logs"
       exit 1
   fi
   ```

3. **Monitor in production**
   - Set up automated checks every 15 minutes
   - Alert on consecutive failures (3+ times)
   - Log all health check results

4. **Before running scans**
   ```bash
   # Always verify system is ready
   if ! ./scripts/optional/check_system_health.sh; then
       echo "System not ready, aborting scan"
       exit 1
   fi

   # Proceed with scan
   curl -X POST http://localhost:8000/scan/...
   ```

## Performance

- **Execution time**: ~5-10 seconds
- **Resource usage**: Minimal (shell scripts + curl)
- **Network impact**: Local only (no external calls)
- **Safe to run frequently**: No side effects

## Security

- All checks are read-only
- No credentials exposed in output
- Logs can be sanitized if needed
- MCP server runs with limited permissions

## Support

- **Documentation**: See [MCP README](../mcp/README.md)
- **Database issues**: See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)
- **Service issues**: Check `docker compose logs [service]`
- **General help**: See main [README.md](../README.md)

## Summary

The health check system provides:
- ✅ **19 automated checks** across all components
- ✅ **Multiple output formats** (text, JSON, MCP)
- ✅ **MCP integration** for Claude Desktop/Code
- ✅ **Comprehensive coverage** of infrastructure, services, and tools
- ✅ **Easy automation** via cron, systemd, or CI/CD
- ✅ **Clear diagnostics** with actionable error messages

Use it to ensure your RAG Scan Stack is always ready for scanning operations!
