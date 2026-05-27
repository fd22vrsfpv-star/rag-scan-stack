#!/bin/bash
# Toggle remote database on/off while preserving IP configuration
# Usage: ./toggle-remote-db.sh [on|off|status]

ENV_FILE="/opt/rag-scan-stack/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ .env file not found at $ENV_FILE"
    exit 1
fi

show_status() {
    echo "🔍 Remote Database Status:"
    if grep -q "^REMOTE_DB_HOST=" "$ENV_FILE"; then
        host_value=$(grep "^REMOTE_DB_HOST=" "$ENV_FILE" | cut -d'=' -f2-)
        echo "✅ ENABLED - Host: ${host_value:-'(empty)'}"
        return 0
    elif grep -q "^# *REMOTE_DB_HOST=" "$ENV_FILE"; then
        host_value=$(grep "^# *REMOTE_DB_HOST=" "$ENV_FILE" | cut -d'=' -f2-)
        echo "🔒 DISABLED - Preserved Host: ${host_value:-'(empty)'}"
        return 1
    else
        echo "❓ NOT FOUND in .env"
        return 2
    fi
}

toggle_on() {
    echo "🔓 Enabling remote database (preserving configuration)..."
    sed -i 's/^# *REMOTE_DB_/REMOTE_DB_/g' "$ENV_FILE"
    echo "✅ Remote database enabled!"

    # Emit webhook for change
    curl -s -k -X POST "https://localhost:8000/webhooks/emit" \
        -H "Content-Type: application/json" \
        -H "x-api-key: changeme" \
        -d '{
            "event_type": "database_mode_changed",
            "source": "host_script",
            "data": {
                "enabled": true,
                "mode": "remote",
                "method": "host_toggle_script",
                "config_preserved": true
            }
        }' >/dev/null 2>&1
}

toggle_off() {
    echo "🔒 Disabling remote database (preserving configuration)..."
    sed -i 's/^REMOTE_DB_/# REMOTE_DB_/g' "$ENV_FILE"
    echo "✅ Remote database disabled (configuration preserved for future use)!"

    # Emit webhook for change
    curl -s -k -X POST "https://localhost:8000/webhooks/emit" \
        -H "Content-Type: application/json" \
        -H "x-api-key: changeme" \
        -d '{
            "event_type": "database_mode_changed",
            "source": "host_script",
            "data": {
                "enabled": false,
                "mode": "local",
                "method": "host_toggle_script",
                "config_preserved": true
            }
        }' >/dev/null 2>&1
}

case "${1:-status}" in
    "on"|"enable")
        toggle_on
        show_status
        ;;
    "off"|"disable")
        toggle_off
        show_status
        ;;
    "status"|*)
        show_status
        current_status=$?
        echo
        if [ $current_status -eq 0 ]; then
            echo "💡 Run './scripts/toggle-remote-db.sh off' to disable (preserving IP)"
        elif [ $current_status -eq 1 ]; then
            echo "💡 Run './scripts/toggle-remote-db.sh on' to enable (using preserved IP)"
        fi
        echo "💡 IP configuration is always preserved during toggle"
        ;;
esac