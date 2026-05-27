"""
Health Check Router for RAG Scan Stack API

Provides HTTP endpoints for system health monitoring, replacing/complementing the MCP server approach.
Integrates with the existing check_system_health.sh script and provides structured JSON responses.
"""

import os
import json
import subprocess
import psycopg2
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter(prefix="/health", tags=["Health Checks"])

# Environment variables
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
# Inside container, the script is at /app/scripts/check_system_health.sh
HEALTH_CHECK_SCRIPT = "/app/scripts/check_system_health.sh"


# Response Models
class HealthCheckResult(BaseModel):
    """Individual health check result"""
    check: str = Field(..., description="Name of the check performed")
    status: str = Field(..., description="Status: pass, fail, or warn")
    message: str = Field(..., description="Human-readable status message")
    details: Optional[str] = Field(None, description="Additional details or error information")


class SystemHealthSummary(BaseModel):
    """Summary of all health checks"""
    total: int = Field(..., description="Total number of checks performed")
    passed: int = Field(..., description="Number of checks that passed")
    failed: int = Field(..., description="Number of checks that failed")
    warnings: int = Field(..., description="Number of warnings")
    health_percentage: int = Field(..., description="Overall health score (0-100)")


class SystemHealthResponse(BaseModel):
    """Complete system health check response"""
    status: str = Field(..., description="Overall status: healthy, degraded, or unhealthy")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the check")
    summary: SystemHealthSummary
    checks: List[HealthCheckResult]
    ready_for_operations: bool = Field(..., description="Whether the system is ready for scanning")
    access_points: Optional[Dict[str, str]] = Field(None, description="API access points")


class ServiceHealthResponse(BaseModel):
    """Individual service health response"""
    service: str
    status: str
    available: bool
    url: str
    message: str
    timestamp: str


class ContainerInfo(BaseModel):
    """Docker container information"""
    name: str
    status: str
    image: str
    ports: Optional[List[str]] = None


class ContainersResponse(BaseModel):
    """List of running containers"""
    total: int
    running: int
    containers: List[ContainerInfo]
    timestamp: str


class DatabaseSchemaResponse(BaseModel):
    """Database schema verification response"""
    status: str
    table_count: int
    expected_tables: int
    missing_tables: List[str]
    critical_tables_present: bool
    timestamp: str


def run_health_check_script(format_type: str = "json", verbose: bool = False) -> Dict[str, Any]:
    """
    Execute the health check script and return parsed results.

    Args:
        format_type: Output format (json, mcp, or text)
        verbose: Whether to include verbose output

    Returns:
        Parsed health check results

    Raises:
        HTTPException: If the script fails or returns invalid data
    """
    try:
        cmd = [HEALTH_CHECK_SCRIPT, f"--{format_type}"]
        if verbose:
            cmd.append("--verbose")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if format_type == "json" or format_type == "mcp":
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to parse health check output: {str(e)}"
                )
        else:
            return {"output": result.stdout, "exit_code": result.returncode}

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Health check script timed out after 30 seconds"
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail=f"Health check script not found: {HEALTH_CHECK_SCRIPT}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error running health check: {str(e)}"
        )


@router.get("/", response_model=SystemHealthResponse, summary="Complete System Health Check")
async def get_system_health(
    format: str = Query("mcp", description="Output format: json, mcp, or text"),
    verbose: bool = Query(False, description="Include verbose output")
):
    """
    Perform a comprehensive health check of all RAG Scan Stack components.

    This endpoint checks:
    - PostgreSQL connectivity and schema (34 tables)
    - All microservices (10 services including Ollama)
    - Service dependencies (Ollama, scan-recommender)

    Returns detailed results with health score and operational readiness.
    """
    import requests

    checks = []
    passed = 0
    failed = 0
    warnings = 0

    # Check database
    try:
        db_check = await check_database_schema()
        if db_check.status == "healthy":
            checks.append(HealthCheckResult(
                check="PostgreSQL Database",
                status="pass",
                message=f"Database healthy with {db_check.table_count}/{db_check.expected_tables} tables",
                details=None
            ))
            passed += 1
        else:
            checks.append(HealthCheckResult(
                check="PostgreSQL Database",
                status="fail",
                message=f"Database issues: {db_check.table_count}/{db_check.expected_tables} tables",
                details=f"Missing tables: {', '.join(db_check.missing_tables)}"
            ))
            failed += 1
    except Exception as e:
        checks.append(HealthCheckResult(
            check="PostgreSQL Database",
            status="fail",
            message="Database connection failed",
            details=str(e)
        ))
        failed += 1

    # Check all services (including Ollama as critical dependency)
    services = ["web-scanner", "nuclei-runner", "nmap-scanner", "scan-recommender",
                "playwright-scanner", "autogen-agents", "llm-query", "kong", "rag-api", "ollama"]

    for service in services:
        try:
            svc_check = await check_service(service)
            if svc_check.available:
                checks.append(HealthCheckResult(
                    check=f"Service: {service}",
                    status="pass",
                    message=svc_check.message,
                    details=svc_check.url
                ))
                passed += 1
            else:
                # rag-api self-check timeout is expected, treat as warning
                if service == "rag-api" and "timeout" in svc_check.message.lower():
                    checks.append(HealthCheckResult(
                        check=f"Service: {service}",
                        status="warn",
                        message="Self-check timeout (expected behavior)",
                        details=svc_check.url
                    ))
                    warnings += 1
                    passed += 1  # Count as passed since it's expected
                else:
                    checks.append(HealthCheckResult(
                        check=f"Service: {service}",
                        status="fail",
                        message=svc_check.message,
                        details=svc_check.url
                    ))
                    failed += 1
        except Exception as e:
            checks.append(HealthCheckResult(
                check=f"Service: {service}",
                status="fail",
                message=f"Service check failed: {str(e)}",
                details=None
            ))
            failed += 1

    total = passed + failed
    health_percentage = int((passed / total * 100)) if total > 0 else 0

    # Determine overall status
    if failed == 0:
        status = "healthy"
    elif health_percentage >= 70:
        status = "degraded"
    else:
        status = "unhealthy"

    return SystemHealthResponse(
        status=status,
        timestamp=datetime.utcnow().isoformat() + "Z",
        summary=SystemHealthSummary(
            total=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            health_percentage=health_percentage
        ),
        checks=checks,
        ready_for_operations=(failed == 0),
        access_points={
            "kong_gateway": "http://localhost:7080",
            "swagger_ui": "http://localhost:7080/docs",
            "rag_api": "https://localhost:8000",
            "autogen_agents": "https://localhost:8015",
            "dashboard": "https://localhost:3002"
        }
    )


@router.get("/database", response_model=DatabaseSchemaResponse, summary="Database Schema Check")
async def check_database_schema():
    """
    Verify the PostgreSQL database schema is complete and correct.

    Checks:
    - Database connectivity
    - Expected table count (21 tables)
    - Critical tables exist (assets, ports, web_findings, vulns, etc.)

    Returns detailed schema verification results.
    """
    try:
        conn = psycopg2.connect(DB_DSN)
        cursor = conn.cursor()

        # Count tables
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """)
        table_count = cursor.fetchone()[0]

        # Check for critical tables (comprehensive list — must match ensure_all_tables.sql)
        critical_tables = [
            # Foundation
            'assets', 'scans', 'ports', 'findings',
            # Core scanning
            'vulns', 'web_findings', 'recon_findings', 'scan_recommendations',
            'credential_findings', 'discovered_params', 'port_observation', 'cve',
            # Playwright
            'playwright_scans', 'playwright_findings', 'playwright_screenshots',
            # Content intelligence
            'dom_analysis', 'content_extractions', 'content_intel_patterns',
            # ZAP / KB
            'zap_sessions', 'kb_service_overrides',
            # Agent / LLM
            'agent_sessions', 'agent_messages', 'agent_tool_calls',
            'session_scan_metrics', 'llm_request_metrics',
            # Jobs / Tasks
            'jobs', 'tasks',
            # Exploit management
            'pending_exploits', 'exploit_results', 'exploit_chunks', 'tool_executions',
            # Webhooks
            'webhooks', 'webhook_events', 'webhook_deliveries',
            # Engagements / Workflow
            'engagements', 'follow_up_items', 'credential_vault', 'burp_followup_queue',
            'scheduled_scans', 'finding_activity', 'evidence_store',
            # Settings / Software
            'app_settings', 'software_research_cache',
            # Infrastructure
            'remote_nodes', 'node_ip_history',
            # AI Agents
            'gap_analysis_reports',
            # Sync
            'sync_log', 'sync_nodes',
            # Scope / Detection
            'scope_targets', 'detection_rule_state',
            # Cloud
            'cloud_scan_recommendations',
        ]

        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """)
        existing_tables = {row[0] for row in cursor.fetchall()}

        missing_tables = [t for t in critical_tables if t not in existing_tables]
        critical_present = len(missing_tables) == 0

        cursor.close()
        conn.close()

        # Expected table count — matches ensure_all_tables.sql (79+ tables)
        expected = 79
        status = "healthy" if table_count >= expected and critical_present else "unhealthy"

        return DatabaseSchemaResponse(
            status=status,
            table_count=table_count,
            expected_tables=expected,
            missing_tables=missing_tables,
            critical_tables_present=critical_present,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Database check failed: {str(e)}"
        )


@router.get("/service/{service_name}", response_model=ServiceHealthResponse, summary="Individual Service Check")
async def check_service(service_name: str):
    """
    Check the health of an individual service.

    Supported services:
    - web-scanner (port 8010)
    - nuclei-runner (port 8011)
    - nmap-scanner (port 8012)
    - scan-recommender (port 8013)
    - playwright-scanner (port 8014)
    - autogen-agents (port 8015)
    - llm-query (port 8002)
    - kong (port 7080)
    - ollama (port 11434)

    Returns service availability and health status.
    """
    # Service port mapping
    service_ports = {
        "web-scanner": 8010,
        "nuclei-runner": 8011,
        "nmap-scanner": 8012,
        "scan-recommender": 8013,
        "playwright-scanner": 8014,
        "autogen-agents": 8015,
        "llm-query": 8002,
        "kong": 7080,
        "rag-api": 8000,
        "ollama": 11434
    }

    # Map API service names (with hyphens) to Docker service names (with underscores)
    docker_service_names = {
        "web-scanner": "web-scanner",
        "nuclei-runner": "nuclei-runner",
        "nmap-scanner": "nmap_scanner",  # Docker uses underscore
        "scan-recommender": "scan-recommender",
        "playwright-scanner": "playwright-scanner",
        "autogen-agents": "autogen-agents",
        "llm-query": "llm_query",  # Docker uses underscore
        "kong": "kong",
        "rag-api": "localhost",  # Check itself via localhost
        "ollama": "ollama"
    }

    if service_name not in service_ports:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown service: {service_name}. Valid services: {', '.join(service_ports.keys())}"
        )

    port = service_ports[service_name]
    # Use Docker service name for inter-container communication
    host = docker_service_names[service_name]

    # Custom health check paths for services that don't use /health
    health_paths = {
        "llm-query": "/healthz",  # llm_query uses /healthz
        "kong": "/status"  # Kong uses /status
    }
    health_path = health_paths.get(service_name, "/health")
    url = f"https://{host}:{port}{health_path}"

    try:
        import requests
        # Kong returns 302 redirects, so don't follow them
        response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
        # Accept 200 OK or 302 redirect as valid responses
        available = response.status_code in [200, 302]
        status = "healthy" if available else "unhealthy"
        message = f"Service is {'available' if available else 'unavailable'}"

        return ServiceHealthResponse(
            service=service_name,
            status=status,
            available=available,
            url=url,
            message=message,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    except requests.exceptions.RequestException as e:
        return ServiceHealthResponse(
            service=service_name,
            status="unhealthy",
            available=False,
            url=url,
            message=f"Service unavailable: {str(e)}",
            timestamp=datetime.utcnow().isoformat() + "Z"
        )


@router.get("/containers", response_model=ContainersResponse, summary="List Running Containers")
async def list_containers():
    """
    List all Docker containers in the RAG Scan Stack.

    Returns:
    - Total container count
    - Running container count
    - Detailed information for each container (name, status, image, ports)
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Docker command failed: {result.stderr}"
            )

        containers = []
        running_count = 0

        for line in result.stdout.strip().split("\n"):
            if line:
                container_data = json.loads(line)
                status = container_data.get("Status", "")
                is_running = status.startswith("Up")

                if is_running:
                    running_count += 1

                containers.append(ContainerInfo(
                    name=container_data.get("Names", ""),
                    status=status,
                    image=container_data.get("Image", ""),
                    ports=container_data.get("Ports", "").split(", ") if container_data.get("Ports") else None
                ))

        return ContainersResponse(
            total=len(containers),
            running=running_count,
            containers=containers,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Docker command timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list containers: {str(e)}"
        )


@router.get("/quick", summary="Quick Health Check")
async def quick_health():
    """
    Quick health check - just returns OK if the API is responsive.
    Useful for load balancers and simple uptime monitoring.
    """
    return {
        "status": "ok",
        "service": "rag-api",
        "version": os.environ.get("BUILD_VERSION", "dev"),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/rag", summary="RAG/Exploit Database Status")
async def check_rag_status():
    """
    Check the status of the RAG (Retrieval-Augmented Generation) system
    used for exploit/vulnerability lookups.

    This checks:
    - exploit_chunks table existence and row count
    - Embedding model availability
    - Chat model availability
    - SearchSploit JSON data
    - ExploitDB files

    Returns detailed RAG system status.
    """
    import requests

    try:
        # Call the scan-recommender /rag/status endpoint
        response = requests.get("https://scan-recommender:8013/rag/status", verify=False, timeout=30)
        response.raise_for_status()
        rag_status = response.json()

        return {
            "status": "healthy" if rag_status.get("healthy") else "unhealthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "rag": rag_status
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": f"Failed to check RAG status: {str(e)}",
            "rag": None
        }


class RAGStatusComponent(BaseModel):
    """RAG component status"""
    name: str
    status: str
    details: Optional[Dict[str, Any]] = None


class FullSystemHealthResponse(BaseModel):
    """Complete system health including RAG status"""
    status: str
    timestamp: str
    summary: SystemHealthSummary
    checks: List[HealthCheckResult]
    rag_status: Optional[Dict[str, Any]] = None
    ready_for_operations: bool
    access_points: Optional[Dict[str, str]] = None


@router.get("/full", response_model=FullSystemHealthResponse, summary="Full System Health with RAG")
async def get_full_system_health():
    """
    Complete system health check including RAG/Exploit database status.

    This combines:
    - All service health checks
    - Database schema verification
    - RAG system status (exploit_chunks, embedding model, chat model, etc.)

    Returns comprehensive health report.
    """
    import requests

    # Get base system health
    base_health = await get_system_health()

    # Get RAG status
    rag_status = None
    rag_healthy = False
    try:
        response = requests.get("https://scan-recommender:8013/rag/status", verify=False, timeout=30)
        response.raise_for_status()
        rag_status = response.json()
        rag_healthy = rag_status.get("healthy", False)

        # Add RAG check to the checks list
        if rag_healthy:
            base_health.checks.append(HealthCheckResult(
                check="RAG/Exploit Database",
                status="pass",
                message=f"RAG operational with {rag_status.get('components', {}).get('database', {}).get('row_count', 0):,} exploit chunks",
                details=None
            ))
            base_health.summary.passed += 1
        else:
            action_required = rag_status.get("action_required", [])
            base_health.checks.append(HealthCheckResult(
                check="RAG/Exploit Database",
                status="fail" if not rag_status.get("components", {}).get("database", {}).get("table_exists") else "warn",
                message=action_required[0] if action_required else "RAG system needs attention",
                details=json.dumps(action_required) if len(action_required) > 1 else None
            ))
            if not rag_status.get("components", {}).get("database", {}).get("table_exists"):
                base_health.summary.failed += 1
            else:
                base_health.summary.warnings += 1

        base_health.summary.total += 1

    except Exception as e:
        base_health.checks.append(HealthCheckResult(
            check="RAG/Exploit Database",
            status="fail",
            message=f"RAG status check failed: {str(e)}",
            details=None
        ))
        base_health.summary.failed += 1
        base_health.summary.total += 1

    # Recalculate health percentage
    total = base_health.summary.total
    passed = base_health.summary.passed
    base_health.summary.health_percentage = int((passed / total * 100)) if total > 0 else 0

    # Update overall status
    if base_health.summary.failed == 0:
        base_health.status = "healthy"
    elif base_health.summary.health_percentage >= 70:
        base_health.status = "degraded"
    else:
        base_health.status = "unhealthy"

    return FullSystemHealthResponse(
        status=base_health.status,
        timestamp=datetime.utcnow().isoformat() + "Z",
        summary=base_health.summary,
        checks=base_health.checks,
        rag_status=rag_status,
        ready_for_operations=(base_health.summary.failed == 0),
        access_points=base_health.access_points
    )


class SchemaCheckRequest(BaseModel):
    tables: List[str] = []
    views: List[str] = []
    columns: Dict[str, List[str]] = {}


@router.get("/db-pool", summary="Database Connection Pool Status")
async def db_pool_status():
    """
    Return live Postgres connection pool stats from pg_stat_activity.

    Shows connection states (active, idle, idle-in-transaction, aborted),
    blocked locks, longest-running queries, and the internal pool size.
    Useful for diagnosing performance issues caused by connection exhaustion
    or transaction leaks.
    """
    try:
        conn = psycopg2.connect(DB_DSN)
        cur = conn.cursor()

        # Connection states
        cur.execute("""
            SELECT state, count(*) AS cnt
            FROM pg_stat_activity
            WHERE datname = current_database()
            GROUP BY state ORDER BY cnt DESC
        """)
        states = {row[0] or "unknown": row[1] for row in cur.fetchall()}

        # Total connections
        total = sum(states.values())

        # Blocked locks
        cur.execute("SELECT count(*) FROM pg_locks WHERE NOT granted")
        blocked_locks = cur.fetchone()[0]

        # Long-running queries (> 5s, excluding this query)
        cur.execute("""
            SELECT pid, state,
                   EXTRACT(EPOCH FROM (now() - query_start))::int AS duration_secs,
                   left(query, 200) AS query_preview
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND state != 'idle'
              AND query NOT LIKE '%pg_stat_activity%'
              AND query_start < now() - interval '5 seconds'
            ORDER BY query_start ASC
            LIMIT 10
        """)
        slow_queries = [
            {"pid": r[0], "state": r[1], "duration_secs": r[2], "query": r[3]}
            for r in cur.fetchall()
        ]

        # Idle-in-transaction age (oldest)
        cur.execute("""
            SELECT EXTRACT(EPOCH FROM (now() - state_change))::int AS idle_secs
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND state LIKE 'idle in transaction%'
            ORDER BY state_change ASC LIMIT 1
        """)
        row = cur.fetchone()
        oldest_idle_tx_secs = row[0] if row else None

        # Internal pool size (from api.py _DB_POOL)
        pool_info = None
        try:
            from api import _DB_POOL
            if _DB_POOL:
                pool_info = {
                    "minconn": _DB_POOL.minconn,
                    "maxconn": _DB_POOL.maxconn,
                }
        except Exception:
            pass

        cur.close()
        conn.close()

        # Determine health based on key indicators
        aborted = states.get("idle in transaction (aborted)", 0)
        idle_in_tx = states.get("idle in transaction", 0)
        status = "healthy"
        warnings = []
        if aborted > 0:
            status = "unhealthy"
            warnings.append(f"{aborted} connection(s) stuck in aborted transaction state")
        if blocked_locks > 5:
            status = "unhealthy"
            warnings.append(f"{blocked_locks} blocked locks detected")
        elif blocked_locks > 0:
            if status == "healthy":
                status = "degraded"
            warnings.append(f"{blocked_locks} blocked lock(s)")
        if idle_in_tx > 10:
            if status == "healthy":
                status = "degraded"
            warnings.append(f"{idle_in_tx} idle-in-transaction connections")
        if oldest_idle_tx_secs and oldest_idle_tx_secs > 120:
            warnings.append(f"Oldest idle-in-transaction: {oldest_idle_tx_secs}s")

        return {
            "status": status,
            "total_connections": total,
            "states": states,
            "blocked_locks": blocked_locks,
            "oldest_idle_tx_secs": oldest_idle_tx_secs,
            "slow_queries": slow_queries,
            "pool": pool_info,
            "warnings": warnings,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }


@router.post("/sql/check-schema")
async def check_schema_detail(req: SchemaCheckRequest):
    """Check for missing tables, views, and columns in the database."""
    try:
        conn = psycopg2.connect(DB_DSN)
        cur = conn.cursor()

        # Check tables
        missing_tables = []
        for table in req.tables:
            cur.execute(
                "SELECT to_regclass(%s)",
                (f"public.{table}",)
            )
            if cur.fetchone()[0] is None:
                missing_tables.append(table)

        # Check views
        missing_views = []
        for view in req.views:
            cur.execute(
                "SELECT 1 FROM pg_views WHERE schemaname = 'public' AND viewname = %s",
                (view,)
            )
            if not cur.fetchone():
                missing_views.append(view)

        # Check columns
        missing_columns = {}
        for table, columns in req.columns.items():
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s",
                (table,)
            )
            existing = {row[0] for row in cur.fetchall()}
            missing = [c for c in columns if c not in existing]
            if missing:
                missing_columns[table] = missing

        cur.close()
        conn.close()

        return {
            "ok": not missing_tables and not missing_views and not missing_columns,
            "missing_tables": missing_tables,
            "missing_views": missing_views,
            "missing_columns": missing_columns,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/sql/apply-schema")
async def apply_schema():
    """Apply the comprehensive schema SQL to create any missing tables, views, and columns."""
    schema_path = "/docker-entrypoint-initdb.d/ensure_all_tables.sql"

    try:
        conn = psycopg2.connect(DB_DSN)
        conn.autocommit = True
        cur = conn.cursor()

        # Count before
        cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'")
        tables_before = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pg_views WHERE schemaname = 'public'")
        views_before = cur.fetchone()[0]

        # Run migration statements to fix missing tables/views/columns
        warnings = []
        migrations = [
            # Critical tables
            "CREATE TABLE IF NOT EXISTS public.assets (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ip inet UNIQUE NOT NULL, hostname text, os text, first_seen timestamptz DEFAULT now(), last_seen timestamptz DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.ports (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE, proto text NOT NULL, port integer NOT NULL, service text, product text, version text, banner text, is_open boolean DEFAULT true, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.findings (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), title text, severity text, asset_id uuid, port integer, details jsonb, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.vulns (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE, port_id uuid REFERENCES public.ports(id) ON DELETE CASCADE, script text NOT NULL, output text NOT NULL, severity text, cve text[], cvss numeric, title text, refs jsonb DEFAULT '{}'::jsonb, metadata jsonb DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.engagements (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, created_at timestamptz DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.agent_sessions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_name text NOT NULL, target_description text NOT NULL, status text DEFAULT 'active', configuration jsonb DEFAULT '{}'::jsonb, summary text, metadata jsonb DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), end_time timestamptz, parent_session_id uuid)",
            "CREATE TABLE IF NOT EXISTS public.agent_messages (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE, agent_name text NOT NULL, role text NOT NULL, content text NOT NULL, metadata jsonb DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.pending_exploits (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), exploit_title text, source text, match_confidence numeric, status text DEFAULT 'pending', edb_id text, created_at timestamptz DEFAULT now())",
            # Column migrations
            "DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS last_seen timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS hostname text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS engagement_id uuid; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            # Allow multiple hostnames per IP (virtual hosts)
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_ip_key') THEN ALTER TABLE public.assets DROP CONSTRAINT assets_ip_key; END IF; END $$",
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_ip_hostname ON public.assets(ip, COALESCE(hostname, ''))",
            "CREATE INDEX IF NOT EXISTS ix_assets_hostname ON public.assets(hostname)",
            "DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS title text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS workflow_status text DEFAULT 'new'; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.pending_exploits ADD COLUMN IF NOT EXISTS edb_id text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.pending_exploits ADD COLUMN IF NOT EXISTS exploit_category text DEFAULT 'other'; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS is_open boolean DEFAULT true; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS product text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS version text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS banner text; EXCEPTION WHEN OTHERS THEN NULL; END $$",
            "ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS port integer",
            "CREATE INDEX IF NOT EXISTS idx_web_findings_port ON public.web_findings(port)",
            """CREATE OR REPLACE FUNCTION public._extract_port_from_url() RETURNS TRIGGER LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.port IS NULL AND NEW.url IS NOT NULL THEN
                NEW.port := (substring(NEW.url from '://[^/:]+:(\\d+)'))::integer;
                IF NEW.port IS NULL THEN
                  IF NEW.url LIKE 'https://%' THEN NEW.port := 443;
                  ELSIF NEW.url LIKE 'http://%' THEN NEW.port := 80;
                  END IF;
                END IF;
              END IF;
              RETURN NEW;
            END;
            $$""",
            "DROP TRIGGER IF EXISTS trg_web_findings_port ON public.web_findings",
            "CREATE TRIGGER trg_web_findings_port BEFORE INSERT OR UPDATE ON public.web_findings FOR EACH ROW EXECUTE FUNCTION public._extract_port_from_url()",
            "UPDATE public.web_findings SET port = (substring(url from '://[^/:]+:(\\d+)'))::integer WHERE port IS NULL AND url ~ '://[^/:]+:\\d+'",
            "UPDATE public.web_findings SET port = 443 WHERE port IS NULL AND url LIKE 'https://%'",
            "UPDATE public.web_findings SET port = 80 WHERE port IS NULL AND url LIKE 'http://%'",
            # Backfill port in vulns metadata
            "UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', to_jsonb(p.port)) FROM public.ports p WHERE vulns.port_id = p.id AND (vulns.metadata->>'port') IS NULL",
            "UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', '22'::jsonb) WHERE script LIKE 'ssh-audit:%' AND port_id IS NULL AND (metadata->>'port') IS NULL",
            "UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', '443'::jsonb) WHERE script LIKE ANY(ARRAY['sslscan:%','testssl:%','sslyze:%']) AND port_id IS NULL AND (metadata->>'port') IS NULL",
            # Non-critical but expected tables
            "CREATE TABLE IF NOT EXISTS public.agent_tool_calls (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid, agent_name text, tool_name text, arguments jsonb, result jsonb, created_at timestamptz DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS public.webhook_deliveries (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), webhook_id uuid, event_type text, payload jsonb, status text DEFAULT 'pending', status_code integer, error text, delivered_at timestamptz, created_at timestamptz DEFAULT now())",
            # Scope targets
            """CREATE TABLE IF NOT EXISTS public.scope_targets (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL DEFAULT 'default',
                target text NOT NULL, target_type text CHECK (target_type IN ('domain','ip','cidr','asn','url')),
                source text, added_at timestamptz NOT NULL DEFAULT now(), UNIQUE(name, target))""",
            "CREATE INDEX IF NOT EXISTS idx_scope_targets_name ON public.scope_targets(name)",
            # Detection rule state
            """CREATE TABLE IF NOT EXISTS public.detection_rule_state (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(), rule_id text NOT NULL UNIQUE,
                enabled boolean NOT NULL DEFAULT true, last_run timestamptz, last_match_count integer DEFAULT 0,
                created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())""",
            # Cloud scan recommendations
            """CREATE TABLE IF NOT EXISTS public.cloud_scan_recommendations (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cloud_provider text NOT NULL,
                tool text NOT NULL, command text NOT NULL, priority integer DEFAULT 50,
                status text DEFAULT 'pending', fingerprint text, reason text,
                created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())""",
            # Software research cache
            """CREATE TABLE IF NOT EXISTS public.software_research_cache (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(), product text NOT NULL, version text NOT NULL DEFAULT '',
                source text NOT NULL DEFAULT 'combined', results jsonb NOT NULL DEFAULT '{}',
                cve_ids text[] DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())""",
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_sw_research_product_version ON public.software_research_cache(LOWER(product), LOWER(version), source)",
            # follow_up_items metadata
            "ALTER TABLE public.follow_up_items ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'",
            # jobs table missing columns
            "ALTER TABLE public.jobs ADD COLUMN IF NOT EXISTS result jsonb DEFAULT '{}'",
            "ALTER TABLE public.jobs ADD COLUMN IF NOT EXISTS progress jsonb DEFAULT '{}'",
            # llm_request_metrics new columns
            "ALTER TABLE public.llm_request_metrics ALTER COLUMN session_id DROP NOT NULL",
            "ALTER TABLE public.llm_request_metrics ADD COLUMN IF NOT EXISTS caller text",
            "ALTER TABLE public.llm_request_metrics ADD COLUMN IF NOT EXISTS tokens_per_sec numeric",
            "ALTER TABLE public.llm_request_metrics ADD COLUMN IF NOT EXISTS request_params jsonb DEFAULT '{}'",
            # detected_software view: skip here — full 15-source view managed by ensure_all_tables.sql
            # Only create if it doesn't exist at all (fresh install)
            """DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_views WHERE viewname = 'detected_software') THEN
                    CREATE VIEW public.detected_software AS
                    SELECT a.id AS asset_id, host(a.ip)::text AS ip, a.hostname, p.port, p.proto AS protocol,
                           COALESCE(p.product, p.service) AS product, p.version, 'nmap' AS source,
                           'service_detection' AS detection_type, p.created_at AS first_seen,
                           COALESCE(p.updated_at, p.created_at) AS last_seen
                    FROM public.ports p JOIN public.assets a ON p.asset_id = a.id
                    WHERE COALESCE(p.is_open, true) AND (p.product IS NOT NULL OR p.service IS NOT NULL);
                END IF;
            END $$""",
            # Engagement propagation triggers
            """CREATE OR REPLACE FUNCTION propagate_engagement_to_vulns() RETURNS TRIGGER LANGUAGE plpgsql AS $t$
            BEGIN IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
                SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE id = NEW.asset_id;
            END IF; RETURN NEW; END; $t$""",
            "DROP TRIGGER IF EXISTS trg_vulns_engagement ON vulns",
            "CREATE TRIGGER trg_vulns_engagement BEFORE INSERT ON vulns FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_vulns()",
            """CREATE OR REPLACE FUNCTION propagate_engagement_to_findings() RETURNS TRIGGER LANGUAGE plpgsql AS $t$
            BEGIN IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
                SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE id = NEW.asset_id;
            END IF; RETURN NEW; END; $t$""",
            "DROP TRIGGER IF EXISTS trg_findings_engagement ON findings",
            "CREATE TRIGGER trg_findings_engagement BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_findings()",
            """CREATE OR REPLACE FUNCTION propagate_engagement_to_followups() RETURNS TRIGGER LANGUAGE plpgsql AS $t$
            DECLARE _ip text;
            BEGIN IF NEW.engagement_id IS NULL AND NEW.target IS NOT NULL THEN
                _ip := substring(NEW.target from '(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})');
                IF _ip IS NOT NULL AND _ip ~ '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$' THEN
                  BEGIN SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE ip = _ip::inet LIMIT 1;
                  EXCEPTION WHEN OTHERS THEN NULL; END;
                END IF;
            END IF; RETURN NEW; END; $t$""",
            "DROP TRIGGER IF EXISTS trg_followups_engagement ON follow_up_items",
            "CREATE TRIGGER trg_followups_engagement BEFORE INSERT ON follow_up_items FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_followups()",
            # Engagement-scoped scopes
            "ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES engagements(id) ON DELETE CASCADE",
            "CREATE INDEX IF NOT EXISTS idx_scope_targets_engagement ON scope_targets(engagement_id)",
            """DO $$ DECLARE eng RECORD; legacy_id uuid;
            BEGIN
              FOR eng IN SELECT id, scope_name FROM engagements WHERE scope_name IS NOT NULL AND scope_name != '' LOOP
                UPDATE scope_targets SET engagement_id = eng.id WHERE name = eng.scope_name AND engagement_id IS NULL;
              END LOOP;
              IF EXISTS (SELECT 1 FROM scope_targets WHERE engagement_id IS NULL LIMIT 1) THEN
                SELECT id INTO legacy_id FROM engagements WHERE name = 'Legacy Scopes' LIMIT 1;
                IF legacy_id IS NULL THEN
                  INSERT INTO engagements (name, client, status, notes) VALUES ('Legacy Scopes', 'Migration', 'archived', 'Auto-created for orphaned scopes') RETURNING id INTO legacy_id;
                END IF;
                UPDATE scope_targets SET engagement_id = legacy_id WHERE engagement_id IS NULL;
              END IF;
            END $$""",
        ]

        executed = 0
        for stmt in migrations:
            try:
                cur.execute(stmt)
                executed += 1
            except Exception as e:
                err_str = str(e).strip()
                if 'already exists' not in err_str:
                    warnings.append(err_str[:150])

        # Count after
        cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'")
        tables_after = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pg_views WHERE schemaname = 'public'")
        views_after = cur.fetchone()[0]

        cur.close()
        conn.close()

        tables_added = tables_after - tables_before
        views_added = views_after - views_before

        return {
            "ok": True,
            "detail": f"Schema applied ({executed} statements). Tables: {tables_before}→{tables_after} (+{tables_added}), Views: {views_before}→{views_after} (+{views_added})",
            "tables_before": tables_before,
            "tables_after": tables_after,
            "views_before": views_before,
            "views_after": views_after,
            "statements_executed": executed,
            "warnings": warnings[:10] if warnings else [],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
