#!/bin/bash
echo "=== RAG Scan Stack Health Report ==="
echo

# Test database
echo "Database:"
curl -s http://localhost:8000/health/database | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"✅ PostgreSQL: {d['status']} ({d['table_count']}/{d['expected_tables']} tables)\")"
echo

# Test all services
echo "Services:"
for service in web-scanner nuclei-runner nmap-scanner scan-recommender playwright-scanner autogen-agents llm-query kong rag-api; do
  status=$(curl -s http://localhost:8000/health/service/$service | python3 -c "import sys, json; d=json.load(sys.stdin); print('✅' if d['available'] else '❌', '$service:', d['status'])")
  echo "$status"
done
