#!/bin/bash
echo "🔍 WireGuard Component Health Check"
echo "===================================="

echo "✅ WireGuard Server Status:"
if docker compose ps wg-server | grep -q "Up"; then
    echo "  ✅ Container running"
    echo "  📊 Port 51820: $(ss -ulnp | grep 51820 || echo 'Not listening')"
else
    echo "  ❌ Container not running"
fi

echo -e "\n✅ Database Status:"
if docker compose ps rag-postgres | grep -q "Up"; then
    echo "  ✅ PostgreSQL running" 
else
    echo "  ❌ PostgreSQL not running"
fi

echo -e "\n✅ Node Manager Status:"
if curl -k -s --connect-timeout 2 https://localhost:8027/health >/dev/null 2>&1; then
    echo "  ✅ HTTPS tunnel-manager responding"
elif docker compose ps node-manager | grep -q "Up"; then
    echo "  ⚠️ Container running but not responding to HTTPS"
    echo "  📋 Recent logs:"
    docker logs node-manager --tail 3 | sed 's/^/     /'
    # Check if it's responding on HTTP (misconfiguration)
    if curl -s --connect-timeout 2 http://localhost:8027/health >/dev/null 2>&1; then
        echo "  ⚠️ WARNING: Responding on HTTP instead of HTTPS"
    fi
else
    echo "  ❌ Node manager not running"
fi

echo -e "\n✅ BFF API Status:"
if curl -k -s https://localhost:3002/api/wg/peers >/dev/null 2>&1; then
    echo "  ✅ BFF WireGuard endpoints accessible (HTTPS)"
    # Test SSL certificate validity
    if curl -s https://localhost:3002/api/wg/peers >/dev/null 2>&1; then
        echo "  ✅ SSL certificate valid"
    else
        echo "  ⚠️ SSL certificate issues (using -k flag)"
    fi
else
    echo "  ❌ BFF not responding to WireGuard requests"
fi

echo -e "\n🗂️ WireGuard Server Config:"
if docker exec wg-server test -f /config/wg_confs/wg0.conf 2>/dev/null; then
    echo "  ✅ wg0.conf exists"
    peer_count=$(docker exec wg-server grep -c "\[Peer\]" /config/wg_confs/wg0.conf 2>/dev/null || echo "0")
    echo "  📊 Current peers: $peer_count"
else
    echo "  ❌ wg0.conf not found"
fi

echo -e "\n💡 Recommendation:"
if docker compose ps wg-server | grep -q "Up"; then
    echo "  Use manual WireGuard setup while GUI issues are resolved"
else
    echo "  Start WireGuard server: docker compose --profile optional up -d wg-server"
fi
