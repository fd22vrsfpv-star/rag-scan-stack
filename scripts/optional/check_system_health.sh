#!/usr/bin/env bash
#
# check_system_health.sh - Comprehensive system health check for RAG Scan Stack
#
# This script verifies that all services, tools, and dependencies are
# available and ready for scanning operations.
#
# Usage:
#   ./scripts/check_system_health.sh [--json] [--verbose]
#
# Options:
#   --json     Output results in JSON format
#   --verbose  Show detailed output for each check
#   --mcp      Format output for MCP tool integration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Options
JSON_OUTPUT=false
VERBOSE=false
MCP_FORMAT=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --json) JSON_OUTPUT=true ;;
        --verbose) VERBOSE=true ;;
        --mcp) MCP_FORMAT=true ;;
    esac
done

# JSON output array
JSON_RESULTS="[]"

# Functions
log_info() {
    if [[ "$JSON_OUTPUT" == "false" && "$MCP_FORMAT" == "false" ]]; then
        echo -e "${BLUE}ℹ${NC} $1"
    fi
}

log_success() {
    if [[ "$JSON_OUTPUT" == "false" && "$MCP_FORMAT" == "false" ]]; then
        echo -e "${GREEN}✓${NC} $1"
    fi
}

log_warning() {
    if [[ "$JSON_OUTPUT" == "false" && "$MCP_FORMAT" == "false" ]]; then
        echo -e "${YELLOW}⚠${NC} $1"
    fi
}

log_error() {
    if [[ "$JSON_OUTPUT" == "false" && "$MCP_FORMAT" == "false" ]]; then
        echo -e "${RED}✗${NC} $1"
    fi
}

add_result() {
    local check_name="$1"
    local status="$2"
    local message="$3"
    local details="${4:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$status" in
        "pass") PASSED_CHECKS=$((PASSED_CHECKS + 1)) ;;
        "fail") FAILED_CHECKS=$((FAILED_CHECKS + 1)) ;;
        "warn") WARNING_CHECKS=$((WARNING_CHECKS + 1)) ;;
    esac

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        local result=$(cat <<EOF
{
  "check": "$check_name",
  "status": "$status",
  "message": "$message",
  "details": "$details"
}
EOF
)
        JSON_RESULTS=$(echo "$JSON_RESULTS" | jq ". += [$result]")
    fi
}

check_docker() {
    log_info "Checking Docker availability..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        add_result "docker_binary" "fail" "Docker command not found in PATH" ""
        return 1
    fi

    if ! docker ps &> /dev/null; then
        log_error "Docker daemon not accessible"
        add_result "docker_daemon" "fail" "Cannot communicate with Docker daemon" ""
        return 1
    fi

    log_success "Docker is available"
    add_result "docker" "pass" "Docker is available and accessible" ""
    return 0
}

check_containers() {
    log_info "Checking Docker containers..."

    local required_containers=(
        "rag-postgres"
        "ollama"
        "kong"
        "rag-api"
        "web-scanner"
        "nuclei-runner"
        "nmap_scanner"
        "scan-recommender"
        "playwright-scanner"
        "autogen-agents"
        "llm_query"
        "zap"
    )

    local all_running=true
    local container_status=""

    for container in "${required_containers[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            local status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")
            if [[ "$status" == "running" ]]; then
                [[ "$VERBOSE" == "true" ]] && log_success "Container $container is running"
                container_status="${container_status}${container}:running\n"
            else
                log_warning "Container $container exists but status is: $status"
                container_status="${container_status}${container}:${status}\n"
                all_running=false
            fi
        else
            log_error "Container $container not found"
            container_status="${container_status}${container}:missing\n"
            all_running=false
        fi
    done

    if [[ "$all_running" == "true" ]]; then
        log_success "All required containers are running"
        add_result "containers" "pass" "All ${#required_containers[@]} required containers are running" "$container_status"
        return 0
    else
        log_error "Some containers are not running"
        add_result "containers" "fail" "Not all required containers are running" "$container_status"
        return 1
    fi
}

check_service_health() {
    local service_name="$1"
    local url="$2"
    local expected="${3:-ok}"

    local response=$(curl -s -f -m 5 "$url" 2>/dev/null || echo "")

    if [[ -n "$response" ]]; then
        if echo "$response" | grep -q "$expected"; then
            [[ "$VERBOSE" == "true" ]] && log_success "$service_name health check passed"
            add_result "health_${service_name}" "pass" "$service_name is healthy" "$response"
            return 0
        else
            log_warning "$service_name responded but unexpected format"
            add_result "health_${service_name}" "warn" "$service_name responded but unexpected format" "$response"
            return 1
        fi
    else
        log_error "$service_name health check failed"
        add_result "health_${service_name}" "fail" "$service_name did not respond" ""
        return 1
    fi
}

check_services() {
    log_info "Checking service health endpoints..."

    local all_healthy=true

    # Wait a moment for services to be ready
    sleep 2

    # Check each service
    check_service_health "rag-api" "http://localhost:8000/health" "ok" || all_healthy=false
    check_service_health "web-scanner" "http://localhost:8010/health" "ok" || all_healthy=false
    check_service_health "nuclei-runner" "http://localhost:8011/health" "ok" || all_healthy=false
    check_service_health "nmap-scanner" "http://localhost:8012/health" "ok" || all_healthy=false
    check_service_health "scan-recommender" "http://localhost:8013/health" "ok" || all_healthy=false
    check_service_health "playwright-scanner" "http://localhost:8014/health" "ok" || all_healthy=false
    check_service_health "autogen-agents" "http://localhost:8015/health" "ok" || all_healthy=false
    check_service_health "llm-query" "http://localhost:8002/healthz" "ok" || all_healthy=false

    if [[ "$all_healthy" == "true" ]]; then
        log_success "All services are healthy"
        return 0
    else
        log_warning "Some services are not responding"
        return 1
    fi
}

check_database() {
    log_info "Checking database..."

    # Check PostgreSQL is running
    if ! docker exec rag-postgres pg_isready -U app -d scans &>/dev/null; then
        log_error "PostgreSQL is not ready"
        add_result "database" "fail" "PostgreSQL is not accepting connections" ""
        return 1
    fi

    # Check table count
    local table_count=$(docker exec rag-postgres psql -U app -d scans -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" 2>/dev/null | tr -d ' ')

    if [[ "$table_count" -ge 21 ]]; then
        log_success "Database has $table_count tables"
        add_result "database_schema" "pass" "Database has $table_count tables (expected: 21)" ""
    else
        log_error "Database only has $table_count tables (expected: 21)"
        add_result "database_schema" "fail" "Database missing tables: found $table_count, expected 21" ""
        return 1
    fi

    # Check critical tables
    local critical_tables=("assets" "ports" "web_findings" "vulns" "scan_recommendations" "agent_sessions")
    local missing_tables=()

    for table in "${critical_tables[@]}"; do
        if ! docker exec rag-postgres psql -U app -d scans -t -c "SELECT to_regclass('public.${table}');" 2>/dev/null | grep -q "$table"; then
            missing_tables+=("$table")
        fi
    done

    if [[ ${#missing_tables[@]} -eq 0 ]]; then
        log_success "All critical tables exist"
        add_result "database_tables" "pass" "All ${#critical_tables[@]} critical tables exist" ""
        return 0
    else
        log_error "Missing critical tables: ${missing_tables[*]}"
        add_result "database_tables" "fail" "Missing tables: ${missing_tables[*]}" ""
        return 1
    fi
}

check_ollama() {
    log_info "Checking Ollama and models..."

    # Check Ollama is responding
    local ollama_status=$(curl -s -f http://localhost:11434/api/tags 2>/dev/null || echo "")

    if [[ -z "$ollama_status" ]]; then
        log_error "Ollama is not responding"
        add_result "ollama" "fail" "Ollama service is not responding" ""
        return 1
    fi

    # Check required models
    local required_models=("nomic-embed-text" "hermes-3-llama-3.1-8b-tools")
    local missing_models=()

    for model in "${required_models[@]}"; do
        if ! echo "$ollama_status" | grep -q "$model"; then
            missing_models+=("$model")
        fi
    done

    if [[ ${#missing_models[@]} -eq 0 ]]; then
        log_success "Ollama running with all required models"
        add_result "ollama_models" "pass" "All required models are available" "$ollama_status"
        return 0
    else
        log_warning "Ollama running but missing models: ${missing_models[*]}"
        add_result "ollama_models" "warn" "Missing models: ${missing_models[*]}" "$ollama_status"
        return 1
    fi
}

check_kong() {
    log_info "Checking Kong API Gateway..."

    # Check Kong is responding
    if ! curl -s -f http://localhost:7080/docs &>/dev/null; then
        log_error "Kong gateway is not responding"
        add_result "kong" "fail" "Kong API Gateway is not responding" ""
        return 1
    fi

    log_success "Kong API Gateway is operational"
    add_result "kong" "pass" "Kong API Gateway is routing requests" ""
    return 0
}

check_tools() {
    log_info "Checking scanning tools availability..."

    local all_tools=true

    # Check nmap in nmap_scanner container
    if docker exec nmap_scanner nmap --version &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && log_success "nmap is available"
        add_result "tool_nmap" "pass" "nmap scanner is available" ""
    else
        log_error "nmap is not available"
        add_result "tool_nmap" "fail" "nmap scanner not found" ""
        all_tools=false
    fi

    # Check nuclei in nuclei-runner container
    if docker exec nuclei-runner nuclei -version &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && log_success "nuclei is available"
        add_result "tool_nuclei" "pass" "nuclei scanner is available" ""
    else
        log_error "nuclei is not available"
        add_result "tool_nuclei" "fail" "nuclei scanner not found" ""
        all_tools=false
    fi

    # Check gobuster in web-scanner container
    if docker exec web-scanner gobuster version &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && log_success "gobuster is available"
        add_result "tool_gobuster" "pass" "gobuster is available" ""
    else
        log_warning "gobuster is not available"
        add_result "tool_gobuster" "warn" "gobuster not found" ""
    fi

    # Check playwright in playwright-scanner container
    if docker exec playwright-scanner python -c "import playwright" &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && log_success "playwright is available"
        add_result "tool_playwright" "pass" "playwright is available" ""
    else
        log_error "playwright is not available"
        add_result "tool_playwright" "fail" "playwright not found" ""
        all_tools=false
    fi

    if [[ "$all_tools" == "true" ]]; then
        log_success "All scanning tools are available"
        return 0
    else
        log_error "Some scanning tools are missing"
        return 1
    fi
}

check_network() {
    log_info "Checking Docker network..."

    if docker network inspect agents_net &>/dev/null; then
        log_success "Docker network 'agents_net' exists"
        add_result "network" "pass" "Docker network 'agents_net' is configured" ""
        return 0
    else
        log_error "Docker network 'agents_net' not found"
        add_result "network" "fail" "Docker network 'agents_net' does not exist" ""
        return 1
    fi
}

# Main execution
main() {
    if [[ "$JSON_OUTPUT" == "false" && "$MCP_FORMAT" == "false" ]]; then
        echo "========================================"
        echo "  RAG Scan Stack - System Health Check"
        echo "========================================"
        echo ""
    fi

    # Run all checks
    check_docker
    check_network
    check_containers
    check_database
    check_ollama
    check_services
    check_kong
    check_tools

    # Summary
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        # Output JSON
        echo "$JSON_RESULTS" | jq "{
            summary: {
                total: $TOTAL_CHECKS,
                passed: $PASSED_CHECKS,
                failed: $FAILED_CHECKS,
                warnings: $WARNING_CHECKS,
                health_percentage: (($PASSED_CHECKS * 100) / $TOTAL_CHECKS)
            },
            checks: .
        }"
    elif [[ "$MCP_FORMAT" == "true" ]]; then
        # MCP tool format output
        cat <<EOF
{
  "status": "$([ $FAILED_CHECKS -eq 0 ] && echo "healthy" || echo "degraded")",
  "total_checks": $TOTAL_CHECKS,
  "passed": $PASSED_CHECKS,
  "failed": $FAILED_CHECKS,
  "warnings": $WARNING_CHECKS,
  "health_score": $((PASSED_CHECKS * 100 / TOTAL_CHECKS)),
  "ready_for_operations": $([ $FAILED_CHECKS -eq 0 ] && echo "true" || echo "false")
}
EOF
    else
        # Human-readable summary
        echo ""
        echo "========================================"
        echo "  Health Check Summary"
        echo "========================================"
        echo -e "Total Checks:  $TOTAL_CHECKS"
        echo -e "${GREEN}Passed:${NC}        $PASSED_CHECKS"
        echo -e "${RED}Failed:${NC}        $FAILED_CHECKS"
        echo -e "${YELLOW}Warnings:${NC}      $WARNING_CHECKS"
        echo ""

        local health_percent=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
        echo -e "Health Score:  ${health_percent}%"
        echo ""

        if [[ $FAILED_CHECKS -eq 0 ]]; then
            echo -e "${GREEN}✓ System is ready for scanning operations${NC}"
            echo ""
            echo "Access points:"
            echo "  - Kong API Gateway:    http://localhost:7080"
            echo "  - Swagger UI:          http://localhost:7080/docs"
            echo "  - RAG API:             http://localhost:8000"
            echo "  - Autogen Agents:      http://localhost:8015"
            exit 0
        else
            echo -e "${RED}✗ System has $FAILED_CHECKS critical issue(s)${NC}"
            echo ""
            echo "Run with --verbose for detailed information"
            echo "Or run: ./scripts/ensure_db_schema.sh to fix database issues"
            exit 1
        fi
    fi
}

# Initialize jq if JSON output requested
if [[ "$JSON_OUTPUT" == "true" ]]; then
    if ! command -v jq &> /dev/null; then
        echo "Error: jq is required for JSON output but not installed"
        exit 1
    fi
fi

# Run main
main "$@"
