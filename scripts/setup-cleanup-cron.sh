#!/bin/bash
# Setup automated cleanup cron job
# Run this once to enable automatic cleanup

CRON_USER=${CRON_USER:-$(whoami)}
PROJECT_ROOT="/opt/rag-scan-stack"

echo "Setting up cleanup cron job for user: $CRON_USER"

# Create cron job that runs daily at 3 AM
(crontab -l 2>/dev/null; echo "0 3 * * * cd $PROJECT_ROOT && DRY_RUN=0 ./scripts/cleanup-old-files.sh >> /var/log/rag-cleanup.log 2>&1") | crontab -

echo "✓ Cleanup cron job installed"
echo "✓ Will run daily at 3 AM with 120-day retention (default)"
echo "✓ Logs will go to /var/log/rag-cleanup.log"

# Create log file
sudo touch /var/log/rag-cleanup.log
sudo chown $CRON_USER /var/log/rag-cleanup.log

echo ""
echo "To check cron job: crontab -l"
echo "To remove cron job: crontab -e"