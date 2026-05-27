#!/bin/bash
# Fix ETL import path issues across all services

echo "Fixing ETL import paths across all services..."

# Fix web_scanner (mounts ETL to /scanner/etl)
echo "Fixing web_scanner..."
if ! grep -q "sys.path.append.*scanner.*etl" /opt/rag-scan-stack/web_scanner/web_scan.py; then
    sed -i '/from etl.parse_zap import parse_zap_alerts/i\
        import sys\
        sys.path.append("/scanner/etl")' /opt/rag-scan-stack/web_scanner/web_scan.py
    echo "✓ Fixed web_scanner import path"
else
    echo "✓ web_scanner already has correct path"
fi

# Check osint_runner for ETL imports
echo "Checking osint_runner..."
if grep -q "from etl\." /opt/rag-scan-stack/osint_runner/*.py; then
    echo "⚠ osint_runner uses ETL imports - might need fixing"
    grep -l "from etl\." /opt/rag-scan-stack/osint_runner/*.py
else
    echo "✓ osint_runner doesn't use ETL imports"
fi

# Check pd_runner for ETL imports
echo "Checking pd_runner..."
if grep -q "from etl\." /opt/rag-scan-stack/pd_runner/*.py; then
    echo "⚠ pd_runner uses ETL imports - might need fixing"
    grep -l "from etl\." /opt/rag-scan-stack/pd_runner/*.py
else
    echo "✓ pd_runner doesn't use ETL imports"
fi

# Check brutus_runner for ETL imports
echo "Checking brutus_runner..."
if grep -q "from etl\." /opt/rag-scan-stack/brutus_runner/*.py; then
    echo "⚠ brutus_runner uses ETL imports - might need fixing"
    grep -l "from etl\." /opt/rag-scan-stack/brutus_runner/*.py
else
    echo "✓ brutus_runner doesn't use ETL imports"
fi

# Check nmap_scanner for ETL imports (should already be fixed like rag-api)
echo "Checking nmap_scanner..."
if grep -q "from etl\." /opt/rag-scan-stack/nmap_scanner/*.py; then
    echo "⚠ nmap_scanner uses ETL imports - checking if fixed..."
    if grep -q "sys.path.append.*app.*etl" /opt/rag-scan-stack/nmap_scanner/*.py; then
        echo "✓ nmap_scanner already has correct path"
    else
        echo "⚠ nmap_scanner needs path fix"
    fi
else
    echo "✓ nmap_scanner doesn't use ETL imports"
fi

echo ""
echo "ETL import path check complete!"
echo "Services that mount ETL directories:"
echo "- rag-api: /app/etl (✅ fixed)"
echo "- nmap_scanner: /app/etl"
echo "- web-scanner: /scanner/etl (✅ fixing now)"
echo "- osint-runner: /runner/etl"
echo "- pd-runner: /runner/etl"
echo "- brutus-runner: /runner/etl"