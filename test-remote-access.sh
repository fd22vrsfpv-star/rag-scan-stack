#!/bin/bash
# Test RAG Stack Remote Access
# Run this from the remote machine to verify connectivity

RAG_HOST="192.168.1.135"

echo "Testing RAG Stack connectivity to $RAG_HOST..."
echo "================================================"
echo ""

# Define services to test
declare -A SERVICES=(
    ["RAG API"]="8000/health"
    ["LLM Query"]="8002/healthz"
    ["Web Scanner"]="8010/health"
    ["Nuclei Runner"]="8011/health"
    ["Nmap Scanner"]="8012/health"
    ["Scan Recommender"]="8013/health"
    ["Playwright Scanner"]="8014/health"
    ["Autogen Agents"]="8015/health"
    ["ZAP Proxy"]="8090/"
    ["Ollama"]="11434/api/tags"
    ["Kong Gateway"]="7080/"
)

success_count=0
fail_count=0

# Test each service
for service in "${!SERVICES[@]}"; do
    endpoint="${SERVICES[$service]}"
    url="http://$RAG_HOST:${endpoint%%/*}"

    printf "%-25s " "$service:"

    if response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null); then
        if [ "$response" = "200" ] || [ "$response" = "000" ]; then
            echo "✓ ACCESSIBLE (HTTP $response)"
            ((success_count++))
        else
            echo "✗ ERROR (HTTP $response)"
            ((fail_count++))
        fi
    else
        echo "✗ CANNOT CONNECT"
        ((fail_count++))
    fi
done

echo ""
echo "================================================"
echo "Results: $success_count successful, $fail_count failed"
echo ""

if [ $fail_count -eq 0 ]; then
    echo "✓ All services are accessible!"
    exit 0
else
    echo "✗ Some services are not accessible."
    echo ""
    echo "Troubleshooting steps:"
    echo "1. Verify Windows firewall rules are configured"
    echo "2. Check port forwarding on Windows: netsh interface portproxy show all"
    echo "3. Ensure Docker containers are running"
    echo "4. Verify the RAG host IP is correct: $RAG_HOST"
    exit 1
fi
