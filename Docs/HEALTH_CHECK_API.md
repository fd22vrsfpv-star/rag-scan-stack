# Health Check REST API

The RAG Scan Stack now provides HTTP API endpoints for system health monitoring, accessible via the RAG API service (http://localhost:8000).

## Overview

These endpoints provide programmatic access to health check functionality, replacing/complementing the MCP server approach. All endpoints return JSON responses and can be used for monitoring, CI/CD pipelines, and automated health verification.

##Access

- **Base URL**: `http://localhost:8000`
- **API Documentation**: `http://localhost:8000/docs` (Swagger UI)
- **All endpoints under**: `/health/*`

## API Endpoints

### 1. Complete System Health Check

**Endpoint**: `GET /health/`

**Description**: Performs a comprehensive health check of all RAG Scan Stack components (19 checks total).

**Parameters**:
- `format` (query, optional): Output format - "json" or "mcp". Default: "mcp"
- `verbose` (query, optional): Include verbose output. Default: false

**Response**: `SystemHealthResponse`

```json
{
  "status": "healthy",  // "healthy", "degraded", or "unhealthy"
  "timestamp": "2025-12-07T22:15:30Z",
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
      "message": "Docker is available",
      "details": null
    },
    // ... 18 more checks
  ],
  "ready_for_operations": true,
  "access_points": {
    "kong_gateway": "http://localhost:7080",
    "swagger_ui": "http://localhost:7080/docs",
    "rag_api": "http://localhost:8000",
    "autogen_agents": "http://localhost:8015"
  }
}
```

**Example**:
```bash
# Default (MCP format)
curl http://localhost:8000/health/

# JSON format
curl "http://localhost:8000/health/?format=json"

# Verbose output
curl "http://localhost:8000/health/?verbose=true"
```

**What Gets Checked**:
- Docker daemon and networking (3 checks)
- PostgreSQL connectivity and schema (3 checks)
- Ollama service and models (1 check)
- All microservices (8 checks: rag-api, web-scanner, nuclei-runner, nmap-scanner, scan-recommender, playwright-scanner, autogen-agents, llm-query)
- Kong API Gateway (1 check)
- Scanning tools (4 checks: nmap, nuclei, gobuster, playwright)

### 2. Database Schema Check

**Endpoint**: `GET /health/database`

**Description**: Verifies the PostgreSQL database schema is complete and correct.

**Response**: `DatabaseSchemaResponse`

```json
{
  "status": "healthy",
  "table_count": 21,
  "expected_tables": 21,
  "missing_tables": [],
  "critical_tables_present": true,
  "timestamp": "2025-12-07T22:15:30Z"
}
```

**Example**:
```bash
curl http://localhost:8000/health/database
```

**Checks**:
- Database connectivity
- Table count (expects 21 tables)
- Critical tables present (assets, ports, web_findings, vulns, scan_recommendations, agent_sessions, agent_messages)

### 3. Individual Service Check

**Endpoint**: `GET /health/service/{service_name}`

**Description**: Checks the health of an individual service.

**Path Parameters**:
- `service_name`: Name of the service to check

**Supported Services**:
- `web-scanner` (port 8010)
- `nuclei-runner` (port 8011)
- `nmap-scanner` (port 8012)
- `scan-recommender` (port 8013)
- `playwright-scanner` (port 8014)
- `autogen-agents` (port 8015)
- `llm-query` (port 8002)
- `kong` (port 7080)
- `rag-api` (port 8000)

**Response**: `ServiceHealthResponse`

```json
{
  "service": "web-scanner",
  "status": "healthy",
  "available": true,
  "url": "http://localhost:8010/health",
  "message": "Service is available",
  "timestamp": "2025-12-07T22:15:30Z"
}
```

**Example**:
```bash
# Check web scanner
curl http://localhost:8000/health/service/web-scanner

# Check all services
for service in web-scanner nuclei-runner nmap-scanner scan-recommender playwright-scanner autogen-agents llm-query kong; do
  echo "Checking $service..."
  curl -s "http://localhost:8000/health/service/$service" | jq '.status'
done
```

### 4. List Running Containers

**Endpoint**: `GET /health/containers`

**Description**: Lists all Docker containers in the RAG Scan Stack with their status.

**Response**: `ContainersResponse`

```json
{
  "total": 15,
  "running": 15,
  "containers": [
    {
      "name": "rag-api",
      "status": "Up 2 hours",
      "image": "rag-scan-stack-rag-api",
      "ports": ["0.0.0.0:8000->8000/tcp"]
    },
    // ... more containers
  ],
  "timestamp": "2025-12-07T22:15:30Z"
}
```

**Example**:
```bash
curl http://localhost:8000/health/containers | jq '.running'
```

### 5. Quick Health Check

**Endpoint**: `GET /health/quick`

**Description**: Simple quick health check - just returns OK if the API is responsive. Useful for load balancers and simple uptime monitoring.

**Response**:
```json
{
  "status": "ok",
  "service": "rag-api",
  "timestamp": "2025-12-07T22:15:30Z"
}
```

**Example**:
```bash
curl http://localhost:8000/health/quick
```

## Response Status Codes

All endpoints return standard HTTP status codes:

- `200 OK`: Request successful, health check completed
- `400 Bad Request`: Invalid parameters (e.g., unknown service name)
- `404 Not Found`: Endpoint not found
- `500 Internal Server Error`: Health check script failed or system error
- `504 Gateway Timeout`: Health check script timed out (30s limit)

## Error Handling

When a health check fails or encounters an error, the response will include details:

```json
{
  "detail": "Health check script timed out after 30 seconds"
}
```

## Integration Examples

### Monitoring Script

```bash
#!/bin/bash
# monitor_health.sh - Simple health monitoring

HEALTH=$(curl -s http://localhost:8000/health/?format=json)
FAILED=$(echo "$HEALTH" | jq -r '.summary.failed')
HEALTH_SCORE=$(echo "$HEALTH" | jq -r '.summary.health_percentage')

if [ "$FAILED" -gt 0 ]; then
  echo "ALERT: Health check failed! Score: $HEALTH_SCORE%"
  echo "$HEALTH" | jq '.checks[] | select(.status == "fail")'
  exit 1
else
  echo "System healthy: $HEALTH_SCORE%"
  exit 0
fi
```

### Python Integration

```python
import requests

def check_system_health():
    """Check RAG Scan Stack health via API"""
    response = requests.get("http://localhost:8000/health/", params={"format": "json"})
    response.raise_for_status()

    health = response.json()

    if health["summary"]["failed"] > 0:
        print(f"⚠️  System unhealthy: {health['summary']['health_percentage']}%")
        for check in health["checks"]:
            if check["status"] == "fail":
                print(f"  ❌ {check['check']}: {check['message']}")
        return False
    else:
        print(f"✅ System healthy: {health['summary']['health_percentage']}%")
        return True

if __name__ == "__main__":
    healthy = check_system_health()
    exit(0 if healthy else 1)
```

### Docker Health Check

Add to `docker-compose.yml`:

```yaml
services:
  rag-api:
    # ... existing config ...
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8000/health/quick || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### Kubernetes Liveness/Readiness Probes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: rag-api
spec:
  containers:
  - name: rag-api
    image: rag-scan-stack-rag-api:latest
    livenessProbe:
      httpGet:
        path: /health/quick
        port: 8000
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /health/
        port: 8000
      initialDelaySeconds: 60
      periodSeconds: 30
```

### CI/CD Pipeline Integration

**GitHub Actions**:
```yaml
- name: Health Check
  run: |
    response=$(curl -s http://localhost:8000/health/?format=json)
    failed=$(echo "$response" | jq -r '.summary.failed')
    if [ "$failed" -gt 0 ]; then
      echo "Health check failed"
      echo "$response" | jq '.checks[] | select(.status == "fail")'
      exit 1
    fi
```

**GitLab CI**:
```yaml
health_check:
  script:
    - |
      response=$(curl -s http://localhost:8000/health/?format=json)
      failed=$(echo "$response" | jq -r '.summary.failed')
      [ "$failed" -eq 0 ] || exit 1
```

### Prometheus Metrics Export

```bash
#!/bin/bash
# Export health metrics for Prometheus

while true; do
  health=$(curl -s http://localhost:8000/health/?format=json)
  health_score=$(echo "$health" | jq -r '.summary.health_percentage')
  passed=$(echo "$health" | jq -r '.summary.passed')
  failed=$(echo "$health" | jq -r '.summary.failed')

  cat <<EOF > /var/lib/node_exporter/textfile_collector/rag_health.prom
# HELP rag_health_score Overall health score percentage
# TYPE rag_health_score gauge
rag_health_score $health_score

# HELP rag_health_checks_passed Number of health checks passed
# TYPE rag_health_checks_passed gauge
rag_health_checks_passed $passed

# HELP rag_health_checks_failed Number of health checks failed
# TYPE rag_health_checks_failed gauge
rag_health_checks_failed $failed
EOF

  sleep 60
done
```

## Comparison: API vs MCP vs CLI

| Feature | REST API | MCP Server | CLI Script |
|---------|----------|------------|------------|
| **Access Method** | HTTP | Claude Desktop/Code | Bash |
| **Format** | JSON | JSON/MCP | Text/JSON |
| **Authentication** | Optional (API key) | Local only | Local only |
| **Network Access** | Yes (remote) | No (local stdio) | Local only |
| **Integration** | Easy (curl, any language) | Claude AI only | Bash scripts |
| **Automation** | Excellent | Limited | Good |
| **CI/CD** | ✅ Yes | ❌ No | ✅ Yes |
| **Monitoring Tools** | ✅ Yes | ❌ No | ⚠️  Limited |
| **Load Balancers** | ✅ Yes | ❌ No | ❌ No |
| **Kubernetes Probes** | ✅ Yes | ❌ No | ❌ No |

## Best Practices

1. **Use `/health/quick` for uptime monitoring** - Fast, lightweight endpoint
2. **Use `/health/` for comprehensive checks** - Complete system verification
3. **Monitor health score trends** - Track degradation over time
4. **Set alerts for health score < 90%** - Early warning system
5. **Check individual services** - Isolate failures quickly
6. **Include health checks in deployments** - Verify before marking deploysprompt successful
7. **Log health check results** - Maintain history for debugging

## Troubleshooting

### "Connection refused"
- Ensure rag-api container is running: `docker ps | grep rag-api`
- Check port mapping: `docker port rag-api`
- Verify API is listening: `docker logs rag-api | grep "Uvicorn running"`

### "Timeout"
- Health check script takes ~5-10 seconds normally
- If timing out, check system load and Docker performance
- Increase timeout in your client if needed

### "Health score low but no obvious failures"
- Some checks may warn without failing
- Check the `warnings` count in the response
- Review individual check details

### "Import errors in logs"
- Rebuild the container: `docker compose up -d --build rag-api`
- Verify health_router.py is in the container: `docker exec rag-api ls -la /app/app/rag-api/`

## See Also

- [Health Check CLI Guide](HEALTH_CHECK_GUIDE.md) - Using the bash script directly
- [MCP Setup Guide](../mcp/README.md) - MCP server for Claude integration
- [API Endpoints Guide](../API_ENDPOINTS.md) - Other RAG API endpoints

## Support

For issues or questions:
1. Check the Swagger UI at http://localhost:8000/docs
2. Review logs: `docker compose logs rag-api`
3. Run manual health check: `./scripts/check_system_health.sh`
4. Open an issue on GitHub
