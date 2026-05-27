#!/bin/bash
# Check and toggle remote database status in .env file
# This script runs on the host where .env is accessible

ENV_FILE="/opt/rag-scan-stack/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ .env file not found at $ENV_FILE"
    exit 1
fi

echo "🔍 Current Remote Database Status:"
echo "=================================="

# Check if remote DB variables are commented or not
commented_count=0
uncommented_count=0
total_vars=0

remote_db_vars=("REMOTE_DB_HOST" "REMOTE_DB_SSH_USER" "REMOTE_DB_SSH_KEY" "REMOTE_DB_PORT" "REMOTE_DB_USER" "REMOTE_DB_PASSWORD")

for var in "${remote_db_vars[@]}"; do
    if grep -q "^# *$var=" "$ENV_FILE"; then
        echo "🔒 $var = COMMENTED (disabled)"
        ((commented_count++))
    elif grep -q "^$var=" "$ENV_FILE"; then
        value=$(grep "^$var=" "$ENV_FILE" | cut -d'=' -f2-)
        echo "🔓 $var = $value (enabled)"
        ((uncommented_count++))
    else
        echo "❓ $var = NOT FOUND"
    fi
    ((total_vars++))
done

echo
echo "Summary:"
echo "--------"
echo "📊 Total variables: $total_vars"
echo "🔓 Enabled (uncommented): $uncommented_count"
echo "🔒 Disabled (commented): $commented_count"

if [ $uncommented_count -gt 0 ]; then
    echo "✅ Status: REMOTE DATABASE ENABLED (but may need configuration)"
    echo
    echo "Host value:"
    host_value=$(grep "^REMOTE_DB_HOST=" "$ENV_FILE" | cut -d'=' -f2-)
    if [ -z "$host_value" ]; then
        echo "⚠️  REMOTE_DB_HOST is empty - configure it to connect to remote database"
    else
        echo "🏠 REMOTE_DB_HOST: $host_value"
    fi
else
    echo "🔒 Status: REMOTE DATABASE DISABLED (commented out)"
fi

echo
echo "To toggle settings:"
echo "- Enable:  sed -i 's/^# *REMOTE_DB_/REMOTE_DB_/g' $ENV_FILE"
echo "- Disable: sed -i 's/^REMOTE_DB_/# REMOTE_DB_/g' $ENV_FILE"