#!/bin/bash
# Import tools via Open WebUI API
# First, you need to get your API key from Open WebUI Settings -> Account -> API Keys

API_KEY="${1:-your-api-key-here}"
WEBUI_URL="http://localhost:3000"

# Read the tool content
CONTENT=$(cat /opt/rag-scan-stack/open-webui/tools/all_tools.py | jq -Rs .)

curl -X POST "$WEBUI_URL/api/v1/tools/create" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"rag_scan_stack_tools\",
    \"name\": \"RAG-Scan-Stack All Tools\",
    \"content\": $CONTENT,
    \"meta\": {
      \"description\": \"Complete pentest toolkit\",
      \"manifest\": {}
    }
  }"
