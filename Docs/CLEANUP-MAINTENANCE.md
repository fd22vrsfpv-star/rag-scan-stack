# Cleanup & Maintenance

## Automated Scan File Cleanup

The system generates thousands of scan output files that need periodic cleanup to prevent disk exhaustion.

### Default Cleanup Policy

- **Retention Period**: 120 days (configurable)
- **Affected Directories**:
  - `nmap_out/` - Nmap scan results
  - `nuclei_reports/` - Nuclei vulnerability scan reports  
  - `web_reports/` - Web application scan reports
  - `osint_reports/` - OSINT/reconnaissance reports
  - `pd_reports/` - Port discovery reports
  - `brutus_reports/` - Credential brute-force reports
  - `playwright_reports/` - Browser automation reports
  - `playwright_screenshots/` - Screenshots from web scans

### Setup Automated Cleanup

**One-time setup:**
```bash
./scripts/setup-cleanup-cron.sh
```

This creates a daily cron job that runs at 3 AM to remove files older than 60 days.

### Manual Cleanup

**Test what would be cleaned (dry run):**
```bash
./scripts/cleanup-old-files.sh
```

**Execute cleanup with default 120-day retention:**
```bash
DRY_RUN=0 ./scripts/cleanup-old-files.sh
```

This will clean up:
- ✅ Old scan output files (older than 120 days)
- ✅ Completed scan job records (older than 120 days)
- ✅ Stuck "running" scan statuses

**Execute cleanup with custom retention period:**
```bash
RETENTION_DAYS=30 DRY_RUN=0 ./scripts/cleanup-old-files.sh
```

### Database Cleanup

Clean old scan records from the database:

**Test database cleanup (dry run):**
```bash
curl -k -X POST "https://localhost:3002/api/cleanup/findings?sources=all&older_than_hours=1440&dry_run=true"
```

**Execute database cleanup (remove records older than 30 days):**
```bash
curl -k -X POST "https://localhost:3002/api/cleanup/findings?sources=all&older_than_hours=720&dry_run=false"
```

### Monitoring

Check cleanup logs:
```bash
tail -f /var/log/rag-cleanup.log
```

Check current file counts:
```bash
find nmap_out nuclei_reports web_reports osint_reports pd_reports -type f | wc -l
```

### Configuration

The cleanup script respects these environment variables:

- `RETENTION_DAYS` - Days to keep files (default: 60)
- `DRY_RUN` - Set to 0 to actually delete files (default: 1 for dry run)

### Troubleshooting

If cleanup isn't running:

1. **Check cron job exists:**
   ```bash
   crontab -l | grep cleanup
   ```

2. **Check cron service status:**
   ```bash
   sudo systemctl status cron
   ```

3. **Run cleanup manually:**
   ```bash
   DRY_RUN=0 ./scripts/cleanup-old-files.sh
   ```

4. **Check disk usage:**
   ```bash
   du -sh nmap_out nuclei_reports web_reports osint_reports pd_reports
   ```