#!/bin/bash
set -e

# Configuration
CSV_PATH="${EXPLOITDB_CSV:-/opt/exploitdb/files_exploits.csv}"
PG_DSN="${PG_DSN:-dbname=postgres user=app password=app host=rag-postgres port=5432}"
OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"

echo "=============================================="
echo "Scan Recommender - Startup (On-Demand Mode)"
echo "=============================================="

# Wait for postgres to be ready
echo "Waiting for PostgreSQL..."
until python3 -c "import psycopg2; psycopg2.connect('$PG_DSN')" 2>/dev/null; do
    echo "  PostgreSQL not ready, waiting..."
    sleep 2
done
echo "✓ PostgreSQL is ready"

# Wait for the LLM backend to be ready. Only the local Ollama needs a readiness
# gate; any other backend (azure/openai/anthropic/vllm — incl. a GUI-selected
# DeepSeek via openai) does not depend on it, so skip the wait. The wait is
# BOUNDED: a crashed/absent Ollama must never hang startup — after ~60s we start
# anyway and let the app resolve the effective backend at request time
# (dashboard DB llm.* over env).
# Second condition: does the Ollama hostname even resolve? LLM_BACKEND is an
# ENV var, but the effective backend lives in the dashboard DB — so a stack
# running Azure/DeepSeek still shows LLM_BACKEND=ollama here and paid the full
# 60s penalty on EVERY restart, waiting for a container that does not exist.
# A DNS check costs milliseconds and skips the wait when there is nothing there.
_ollama_name="$(printf '%s' "${OLLAMA_HOST:-http://ollama:11434}" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')"
if [ "${LLM_BACKEND:-ollama}" = "ollama" ] && ! getent hosts "$_ollama_name" >/dev/null 2>&1; then
    echo "Ollama host '${_ollama_name}' does not resolve - skipping Ollama wait"
elif [ "${LLM_BACKEND:-ollama}" = "ollama" ]; then
    echo "Waiting for Ollama (up to 60s)..."
    _tries=0
    until curl -s "${OLLAMA_HOST}/api/tags" > /dev/null 2>&1; do
        _tries=$((_tries + 1))
        if [ "$_tries" -ge 30 ]; then
            echo "⚠ Ollama not ready after 60s — starting anyway"
            break
        fi
        echo "  Ollama not ready, waiting..."
        sleep 2
    done
    [ "$_tries" -lt 30 ] && echo "✓ Ollama is ready"
else
    echo "Non-Ollama backend (${LLM_BACKEND:-ollama}) - skipping Ollama wait"
fi

# Verify CSV exists for on-demand search
if [ -f "$CSV_PATH" ]; then
    CSV_LINES=$(wc -l < "$CSV_PATH")
    echo "✓ ExploitDB CSV ready ($CSV_LINES entries)"
else
    echo "⚠ ExploitDB CSV not found at $CSV_PATH"
    echo "  On-demand search will not work without it"
fi

# Ensure DB schema exists (for optional on-demand embedding)
echo "Ensuring database schema..."
if [ "${LLM_BACKEND:-ollama}" != "azure" ]; then
    python3 -c "
import os
os.environ['PG_DSN'] = '$PG_DSN'
os.environ['OLLAMA_HOST'] = '$OLLAMA_HOST'
import sys
sys.path.insert(0, '/app')
from exploits_rag import _dim, _ensure_schema
try:
    dim = _dim()
    _ensure_schema(dim)
    print('✓ Database schema ready')
except Exception as e:
    print(f'⚠ Schema setup: {e}')
" 2>&1 || echo "  (Schema will be created on first embedding)"
else
    python3 -c "
import os, sys
os.environ['PG_DSN'] = '$PG_DSN'
os.environ['LLM_BACKEND'] = 'azure'
os.environ['AZURE_ENDPOINT'] = '${AZURE_ENDPOINT:-}'
os.environ['AZURE_API_KEY'] = '${AZURE_API_KEY:-}'
os.environ['AZURE_EMBED_MODEL'] = '${AZURE_EMBED_MODEL:-}'
os.environ['AZURE_API_VERSION'] = '${AZURE_API_VERSION:-2024-08-01-preview}'
sys.path.insert(0, '/app')
from exploits_rag import _dim, _ensure_schema
try:
    dim = _dim()
    _ensure_schema(dim)
    print('✓ Database schema ready (Azure embeddings)')
except Exception as e:
    print(f'⚠ Schema setup with Azure: {e}')
" 2>&1 || echo "  (Schema will be created on first embedding)"
fi

echo "=============================================="
echo "Starting Uvicorn server..."
echo "  Mode: On-demand (no bulk ingest)"
echo "  Searches CSV directly, embeds on request"
echo "=============================================="

# Start the main application
if [ -f /certs/server.key ] && [ -f /certs/server.crt ]; then
    exec uvicorn multi_app:app --host 0.0.0.0 --port 8013 \
        --ssl-keyfile=/certs/server.key --ssl-certfile=/certs/server.crt
else
    exec uvicorn multi_app:app --host 0.0.0.0 --port 8013
fi
