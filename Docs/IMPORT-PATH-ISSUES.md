# ETL Import Path Issues

## Problem
Services that import ETL parsers may fail due to incorrect Python path configuration. Each container mounts the ETL directory to different paths:

- **rag-api**: `/app/etl`
- **nmap_scanner**: `/app/etl`  
- **web-scanner**: `/scanner/etl`
- **osint-runner**: `/runner/etl`
- **pd-runner**: `/runner/etl`
- **brutus-runner**: `/runner/etl`

## Symptoms
- `ModuleNotFoundError: No module named 'asset_utils'`
- `ModuleNotFoundError: No module named 'etl.parse_xxx'`
- ETL ingestion failures with "ingest_failed" status
- Services falling back to direct insertion instead of using ETL parsers

## Solution
Add the correct ETL path to `sys.path` before importing ETL modules:

### For rag-api and nmap_scanner containers:
```python
import sys
sys.path.append('/app/etl')
from etl.parse_xxx import parse_xxx
```

### For web-scanner container:
```python
import sys  
sys.path.append('/scanner/etl')
from etl.parse_zap import parse_zap_alerts
```

### For osint-runner, pd-runner, brutus-runner containers:
```python
import sys
sys.path.append('/runner/etl') 
from etl.parse_xxx import parse_xxx
```

## Automated Fix
Run the automated fix script:
```bash
./scripts/fix-etl-imports.sh
```

This script:
1. Scans all services for ETL imports
2. Adds correct `sys.path.append()` statements
3. Reports which services were fixed

## Prevention
- Always test ETL imports when adding new parsers
- Run the fix script after major changes
- Consider adding ETL path setup to container startup scripts

## Fixed Issues
- ✅ `parse_masscan.py` - Fixed asset_utils import
- ✅ `web_scanner/web_scan.py` - Fixed ZAP ETL import

## Testing
To test if ETL imports work correctly:

1. **Check logs for import errors**:
   ```bash
   docker compose logs | grep -i "modulenotfounderror\|importerror"
   ```

2. **Test specific service ETL import**:
   ```bash
   docker exec [service-name] python -c "
   import sys
   sys.path.append('/app/etl')  # adjust path for service
   from etl.parse_nmap import parse_nmap
   print('ETL import successful')
   "
   ```

3. **Run a scan and check ingestion**:
   - Start any scan that uses ETL ingestion
   - Check that results appear in the database
   - Verify no "ingest_failed" status