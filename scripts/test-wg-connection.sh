#!/bin/bash
if [ $# -lt 1 ]; then
    echo "Usage: $0 <peer-ip>"
    echo "Example: $0 10.66.0.2"
    exit 1
fi

PEER_IP="$1"
echo "🧪 Testing WireGuard connection to $PEER_IP"

# Test if peer is reachable via WireGuard
if ping -c 1 -W 2 "$PEER_IP" >/dev/null 2>&1; then
    echo "✅ Ping successful"
else
    echo "❌ Ping failed"
fi

# Test SOCKS proxy if available
if curl -s --connect-timeout 5 --socks5 "$PEER_IP:1080" http://httpbin.org/ip >/dev/null 2>&1; then
    echo "✅ SOCKS5 proxy working"
    echo "📍 External IP via proxy:"
    curl -s --socks5 "$PEER_IP:1080" http://httpbin.org/ip | jq -r '.origin'
else
    echo "❌ SOCKS5 proxy not responding"
fi
