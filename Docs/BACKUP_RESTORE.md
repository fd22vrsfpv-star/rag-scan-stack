# RAG Scan Stack - Backup & Restore Guide

**Version:** 1.0
**Last Updated:** 2025-11-19
**Author:** RAG Scan Stack Operations Team

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Backup System Architecture](#backup-system-architecture)
4. [Configuration](#configuration)
5. [Backup Procedures](#backup-procedures)
6. [Restore Procedures](#restore-procedures)
7. [Automation & Scheduling](#automation--scheduling)
8. [Monitoring & Verification](#monitoring--verification)
9. [Disaster Recovery](#disaster-recovery)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices](#best-practices)
12. [FAQs](#faqs)

---

## Overview

The RAG Scan Stack backup system provides comprehensive data protection for:

- **PostgreSQL Databases** - All application data, scan results, and metadata
- **Docker Volumes** - Persistent storage (pgdata, nuclei templates, search exploit data, Ollama models)
- **Scan Results** - Nmap, web scans, Nuclei reports, screenshots
- **Configuration** - Environment variables, Docker Compose, Kong config

### Recovery Objectives

| Component | RTO (Recovery Time) | RPO (Recovery Point) |
|-----------|--------------------|--------------------|
| PostgreSQL Database | 30 minutes | 1 hour |
| Docker Volumes | 1 hour | 24 hours |
| Scan Data Files | 2 hours | 24 hours |
| Configuration | 5 minutes | 0 (version controlled) |

---

## Quick Start

### First-Time Setup

```bash
# 1. Navigate to project directory
cd /utils/agents

# 2. Review and customize backup configuration
nano .backup-config.env

# 3. Create backup directory
sudo mkdir -p /backups
sudo chown $(whoami):$(whoami) /backups

# 4. Run your first backup
./scripts/backup/backup-full.sh

# 5. Verify backup was created
ls -lh /backups/full/
```

### Automated Backups

```bash
# Set up cron jobs for automated backups
crontab -e

# Add these lines:
# Hourly database backup
0 * * * * /utils/agents/scripts/backup/backup-postgres.sh

# Daily full backup at 2 AM
0 2 * * * /utils/agents/scripts/backup/backup-full.sh

# Weekly volume backup on Sundays at 3 AM
0 3 * * 0 /utils/agents/scripts/backup/backup-volumes.sh
```

---

## Backup System Architecture

### Components

```
/utils/agents/scripts/backup/
├── backup-postgres.sh      # PostgreSQL database backups
├── backup-volumes.sh        # Docker volume backups
├── backup-full.sh           # Complete system backup (orchestrates all)
└── restore.sh               # System restore

/backups/
├── postgres/
│   └── YYYYMMDD-HHMMSS/
│       ├── postgres-full.sql.gz
│       ├── scans.dump
│       ├── exploits.dump
│       ├── schema-only.sql.gz
│       ├── globals.sql
│       └── manifest.txt
├── volumes/
│   └── YYYYMMDD-HHMMSS/
│       ├── rag-pgdata.tar.gz
│       ├── nuclei-templates.tar.gz
│       ├── searchsploit-data.tar.gz
│       ├── ollama-data.tar.gz
│       └── manifest.txt
└── full/
    └── YYYYMMDD-HHMMSS/
        ├── postgres/
        ├── volumes/
        ├── scan_data/
        ├── config/
        ├── docker_state/
        └── MANIFEST.md
```

### Backup Types

| Type | Script | Frequency | Size | Duration |
|------|--------|-----------|------|----------|
| **PostgreSQL** | `backup-postgres.sh` | Hourly | 1-10 GB | 2-5 min |
| **Volumes** | `backup-volumes.sh` | Weekly | 10-50 GB | 5-15 min |
| **Full System** | `backup-full.sh` | Daily | 20-100 GB | 10-30 min |

---

## Configuration

### Basic Configuration

Edit `.backup-config.env`:

```bash
# Essential settings
BACKUP_BASE_DIR="/backups"              # Where to store backups
BACKUP_RETENTION_DAYS=30                # How long to keep backups
POSTGRES_CONTAINER="rag-postgres"       # PostgreSQL container name
POSTGRES_USER="app"                     # PostgreSQL user
```

### Advanced Configuration

#### Enable S3 Upload

```bash
# Install AWS CLI
sudo apt-get install awscli

# Configure AWS credentials
aws configure
# AWS Access Key ID: [your-key]
# AWS Secret Access Key: [your-secret]
# Default region: us-east-1

# Update .backup-config.env
ENABLE_S3_UPLOAD=true
S3_BUCKET="mycompany-rag-backups"
S3_REGION="us-east-1"
S3_STORAGE_CLASS="STANDARD_IA"
```

#### Enable Encryption

```bash
# Install GPG
sudo apt-get install gnupg

# Generate or import encryption key
gpg --gen-key
# OR
gpg --import backup-public-key.asc

# Update .backup-config.env
ENABLE_ENCRYPTION=true
ENCRYPTION_RECIPIENT="backup@mycompany.com"
```

#### Enable Email Notifications

```bash
# Install mail utilities
sudo apt-get install mailutils

# Configure SMTP (example for Gmail)
sudo nano /etc/postfix/main.cf
# relayhost = [smtp.gmail.com]:587
# smtp_sasl_auth_enable = yes
# smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
# smtp_sasl_security_options = noanonymous
# smtp_tls_security_level = encrypt

# Update .backup-config.env
ENABLE_EMAIL_NOTIFICATIONS=true
EMAIL_NOTIFICATION_ADDRESS="ops@mycompany.com"
```

---

## Backup Procedures

### Manual Backups

#### Full System Backup

```bash
# Backup everything (recommended)
./scripts/backup/backup-full.sh

# Output:
# ==========================================
# RAG Scan Stack - Complete System Backup
# ==========================================
# ...
# ✓✓✓ Complete system backup finished successfully! ✓✓✓
# Backup available at: /backups/full/20251119-020000
```

#### Database-Only Backup

```bash
# Backup only PostgreSQL databases
./scripts/backup/backup-postgres.sh

# Output:
# ========================================
# PostgreSQL Backup Script
# ========================================
# ...
# ✓ Backup completed successfully!
# Backup available at: /backups/postgres/20251119-030000
```

#### Volumes-Only Backup

```bash
# Backup only Docker volumes
./scripts/backup/backup-volumes.sh

# Output:
# ========================================
# Docker Volumes Backup Script
# ========================================
# ...
# ✓ All volume backups completed successfully!
```

### Verify Backup Integrity

```bash
# Check backup files exist
ls -lh /backups/full/20251119-020000/

# Verify PostgreSQL backup integrity
gzip -t /backups/full/20251119-020000/postgres/postgres-full.sql.gz
echo $?  # Should return 0

# Verify volume backups
for f in /backups/full/20251119-020000/volumes/*.tar.gz; do
    echo "Checking: $(basename $f)"
    tar tzf "$f" >/dev/null && echo "✓ OK" || echo "✗ FAILED"
done

# View backup manifest
cat /backups/full/20251119-020000/MANIFEST.md
```

---

## Restore Procedures

### Full System Restore

```bash
# 1. List available backups
./scripts/backup/restore.sh

# Output shows available backups:
#   20251119-020000 (45G)
#   20251118-020000 (43G)
#   20251117-020000 (42G)

# 2. Perform full restore (DESTRUCTIVE!)
./scripts/backup/restore.sh 20251119-020000

# You will be prompted to confirm:
# ⚠️  This will stop all running services. Any active operations will be interrupted.
# Continue? (yes/no): yes
#
# ⚠️  This will OVERWRITE ALL existing data in PostgreSQL!
# Continue? (yes/no): yes
#
# ⚠️  This will OVERWRITE existing Docker volume data!
# Continue? (yes/no): yes

# 3. Wait for restore to complete (15-45 minutes)
# ✓✓✓ System restore completed successfully! ✓✓✓
```

### Partial Restores

#### Database-Only Restore

```bash
# Restore only the database (keeps volumes intact)
./scripts/backup/restore.sh 20251119-020000 --database-only
```

#### Volumes-Only Restore

```bash
# Restore only Docker volumes (keeps database intact)
./scripts/backup/restore.sh 20251119-020000 --volumes-only
```

#### Dry Run (Test Without Changes)

```bash
# See what would be restored without making changes
./scripts/backup/restore.sh 20251119-020000 --dry-run

# Output:
# DRY RUN MODE - No changes will be made
# ...
# DRY RUN: Would restore databases from: ...
# DRY RUN: Would restore volumes from: ...
```

### Emergency Recovery

If the system is completely down:

```bash
# 1. Ensure Docker is running
sudo systemctl start docker

# 2. Navigate to project directory
cd /utils/agents

# 3. Restore from latest backup
LATEST=$(ls -t /backups/full/ | head -1)
./scripts/backup/restore.sh $LATEST --force

# 4. Verify services are healthy
docker-compose ps
curl http://localhost:8000/health
```

---

## Automation & Scheduling

### Recommended Cron Schedule

```cron
# RAG Scan Stack - Backup Schedule
# Edit with: crontab -e

# Hourly PostgreSQL backup (low overhead)
0 * * * * /utils/agents/scripts/backup/backup-postgres.sh >> /var/log/rag-backup-postgres.log 2>&1

# Daily full backup at 2 AM (off-peak hours)
0 2 * * * /utils/agents/scripts/backup/backup-full.sh >> /var/log/rag-backup-full.log 2>&1

# Weekly volume backup on Sundays at 3 AM (heavier operation)
0 3 * * 0 /utils/agents/scripts/backup/backup-volumes.sh >> /var/log/rag-backup-volumes.log 2>&1

# Monthly backup verification on 1st of month at 4 AM
0 4 1 * * /utils/agents/scripts/dr/test-disaster-recovery.sh >> /var/log/rag-backup-verify.log 2>&1
```

### Systemd Timer (Alternative to Cron)

Create `/etc/systemd/system/rag-backup.service`:

```ini
[Unit]
Description=RAG Scan Stack Full Backup
After=docker.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/utils/agents
ExecStart=/utils/agents/scripts/backup/backup-full.sh
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/rag-backup.timer`:

```ini
[Unit]
Description=RAG Scan Stack Backup Timer
Requires=rag-backup.service

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl enable rag-backup.timer
sudo systemctl start rag-backup.timer
sudo systemctl list-timers
```

---

## Monitoring & Verification

### Check Backup Status

```bash
# List recent backups
ls -lht /backups/full/ | head -10

# Check backup age
LATEST=$(ls -t /backups/full/ | head -1)
echo "Latest backup: $LATEST"
stat /backups/full/$LATEST -c "Created: %y"

# Check backup size
du -sh /backups/full/$LATEST
```

### Automated Monitoring Script

Create `/utils/agents/scripts/backup/check-backup-health.sh`:

```bash
#!/bin/bash
# Check backup health and alert if issues found

BACKUP_DIR="/backups/full"
MAX_AGE_HOURS=25  # Alert if backup older than 25 hours

LATEST=$(ls -t $BACKUP_DIR | head -1)
if [ -z "$LATEST" ]; then
    echo "ERROR: No backups found!"
    exit 1
fi

LATEST_PATH="$BACKUP_DIR/$LATEST"
AGE_HOURS=$(( ($(date +%s) - $(stat -c %Y "$LATEST_PATH")) / 3600 ))

if [ $AGE_HOURS -gt $MAX_AGE_HOURS ]; then
    echo "WARNING: Latest backup is $AGE_HOURS hours old (> $MAX_AGE_HOURS)"
    # Send alert
    # mail -s "RAG Backup Warning" ops@example.com <<< "Latest backup is $AGE_HOURS hours old"
    exit 1
fi

echo "✓ Backup health OK - Latest: $LATEST ($AGE_HOURS hours old)"
exit 0
```

Schedule health checks:

```cron
# Check backup health every 6 hours
0 */6 * * * /utils/agents/scripts/backup/check-backup-health.sh
```

### Backup Metrics for Monitoring

Track these metrics in your monitoring system (Prometheus, Datadog, etc.):

- `backup_success_total` - Total successful backups
- `backup_failure_total` - Total failed backups
- `backup_duration_seconds` - Time taken for backups
- `backup_size_bytes` - Size of backup files
- `backup_age_hours` - Age of latest backup
- `backup_verification_status` - Last verification result

---

## Disaster Recovery

### Disaster Scenarios

#### Scenario 1: Database Corruption

```bash
# Symptoms: Database connection errors, query failures

# 1. Stop services
docker-compose down

# 2. Restore database only
./scripts/backup/restore.sh $(ls -t /backups/full/ | head -1) --database-only

# 3. Start services
docker-compose up -d

# 4. Verify
curl http://localhost:8000/health
```

#### Scenario 2: Complete Host Failure

```bash
# New host setup:

# 1. Install Docker and Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# 2. Clone repository
git clone <repository-url> /utils/agents
cd /utils/agents

# 3. Copy backup from offsite storage
aws s3 sync s3://mycompany-rag-backups/full/20251119-020000/ /backups/full/20251119-020000/

# 4. Restore system
./scripts/backup/restore.sh 20251119-020000

# 5. Verify services
docker-compose ps
./test-remote-access.sh
```

#### Scenario 3: Accidental Data Deletion

```bash
# If data was deleted in last hour:

# 1. Find backup before deletion
ls -lt /backups/full/ | head -5

# 2. Restore specific database
./scripts/backup/restore.sh 20251119-010000 --database-only

# 3. Export recovered data if needed
docker exec rag-postgres pg_dump -U app -d scans > /tmp/recovered-data.sql
```

---

## Troubleshooting

### Common Issues

#### Issue: "PostgreSQL container not running"

```bash
# Check container status
docker ps -a | grep postgres

# Start container
docker-compose up -d rag-postgres

# Check logs
docker logs rag-postgres --tail 100
```

#### Issue: "Backup directory full"

```bash
# Check disk space
df -h /backups

# Clean old backups manually
rm -rf /backups/full/202411*  # Delete November backups

# Or adjust retention in .backup-config.env
BACKUP_RETENTION_DAYS=7  # Reduce to 7 days
```

#### Issue: "Restore failed - pg_restore error"

```bash
# Common causes:
# 1. PostgreSQL version mismatch
docker exec rag-postgres psql -U app -c "SELECT version();"

# 2. Database doesn't exist - create it
docker exec rag-postgres psql -U app -c "CREATE DATABASE scans;"

# 3. Permissions issue
docker exec rag-postgres psql -U app -c "GRANT ALL ON DATABASE scans TO app;"

# Retry restore
./scripts/backup/restore.sh 20251119-020000 --database-only
```

#### Issue: "S3 upload failed"

```bash
# Check AWS credentials
aws sts get-caller-identity

# Check bucket access
aws s3 ls s3://mycompany-rag-backups/

# Check network connectivity
curl -I https://s3.amazonaws.com

# Manual upload
aws s3 sync /backups/full/20251119-020000/ \
    s3://mycompany-rag-backups/full/20251119-020000/
```

---

## Best Practices

### Security

1. **Encrypt Backups**
   ```bash
   ENABLE_ENCRYPTION=true
   ENCRYPTION_RECIPIENT="backup@mycompany.com"
   ```

2. **Secure Configuration**
   ```bash
   chmod 600 .backup-config.env
   chown root:root .backup-config.env
   ```

3. **Offsite Storage**
   - Store backups in geographically separate location
   - Use S3 with versioning enabled
   - Consider S3 Glacier for long-term retention

4. **Access Control**
   ```bash
   # Restrict backup directory
   chmod 700 /backups
   chown backup-user:backup-group /backups
   ```

### Testing

1. **Monthly DR Drills**
   ```bash
   # Test full restore in staging environment
   ./scripts/backup/restore.sh $(ls -t /backups/full/ | head -1) --dry-run
   ```

2. **Automated Verification**
   ```cron
   # Weekly backup verification
   0 4 * * 1 /utils/agents/scripts/dr/test-disaster-recovery.sh
   ```

3. **Document Results**
   - Track RTO/RPO achieved
   - Document any issues encountered
   - Update runbooks

### Optimization

1. **Incremental Backups** (for large databases)
   ```bash
   # Enable WAL archiving for point-in-time recovery
   # Update postgresql.conf:
   # wal_level = replica
   # archive_mode = on
   # archive_command = 'cp %p /backups/wal/%f'
   ```

2. **Parallel Compression**
   ```bash
   # Use pigz (parallel gzip) for faster compression
   apt-get install pigz
   # Update scripts to use pigz instead of gzip
   ```

3. **Storage Optimization**
   ```bash
   # Use S3 lifecycle policies for cost savings
   aws s3api put-bucket-lifecycle-configuration \
       --bucket mycompany-rag-backups \
       --lifecycle-configuration file://lifecycle.json
   ```

---

## FAQs

**Q: How long do backups take?**
A: Database backup: 2-5 minutes. Full backup: 10-30 minutes depending on data size.

**Q: Can I run backups while the system is running?**
A: Yes! All backup scripts are designed to work on a running system without downtime.

**Q: How much storage do I need?**
A: Plan for 50-100GB per full backup. With 30-day retention, you'll need 1.5-3TB.

**Q: How do I restore just one database?**
A: Use individual database dump files:
```bash
docker exec -i rag-postgres pg_restore -U app -d scans \
    < /backups/full/20251119-020000/postgres/scans.dump
```

**Q: Can I backup to multiple locations?**
A: Yes! Enable S3 upload for offsite backup while keeping local copies:
```bash
ENABLE_S3_UPLOAD=true
S3_BUCKET="mycompany-rag-backups"
```

**Q: What happens if a backup fails?**
A: The script will log errors and exit with non-zero status. Set up email notifications to be alerted immediately.

**Q: How do I migrate to a new server?**
A: 1) Backup on old server, 2) Copy backup files to new server, 3) Restore on new server using `restore.sh`.

---

## Additional Resources

- **Disaster Recovery Plan:** `Docs/disaster-recovery/DISASTER_RECOVERY_PLAN.md`
- **Database Failure Runbook:** `Docs/disaster-recovery/RUNBOOK_DATABASE_FAILURE.md`
- **Security Setup:** `SECURITY_SETUP.md`
- **Deployment Guide:** `DEPLOYMENT.md`

---

## Support

For issues or questions:
1. Check logs: `/var/log/rag-backup-*.log`
2. Review backup manifest: `/backups/full/<timestamp>/MANIFEST.md`
3. Contact: ops@example.com

---

**Document Version:** 1.0
**Last Review:** 2025-11-19
**Next Review:** 2026-02-19
