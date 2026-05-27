#!/bin/bash
# Update Kong Configuration with API Key from .env
# Run this script after generating new credentials to update Kong gateway configuration

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Update Kong Gateway Configuration                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "   Please run ./generate-credentials.sh first"
    exit 1
fi

# Load environment variables
source .env

# Check if API_KEY is set
if [ -z "$API_KEY" ]; then
    echo "❌ Error: API_KEY not set in .env"
    echo "   Please ensure API_KEY is configured"
    exit 1
fi

# Check if kong.yml exists
if [ ! -f kong/kong.yml ]; then
    echo "❌ Error: kong/kong.yml not found!"
    exit 1
fi

echo "🔄 Updating Kong configuration with API key from .env..."
echo ""

# Backup existing kong.yml
cp kong/kong.yml "kong/kong.yml.backup.$(date +%Y%m%d_%H%M%S)"
echo "✓ Created backup of existing kong.yml"

# Count occurrences before replacement
before_count=$(grep -c 'x-api-key: change-me' kong/kong.yml || true)

# Replace all instances of "change-me" with the actual API key
sed -i "s|x-api-key: change-me|x-api-key: ${API_KEY}|g" kong/kong.yml

# Count occurrences after replacement (should be 0)
after_count=$(grep -c 'x-api-key: change-me' kong/kong.yml || true)

echo "✓ Updated API key in Kong configuration"
echo "  - Replaced $before_count instance(s)"
echo "  - Remaining hardcoded keys: $after_count"
echo ""

if [ $after_count -gt 0 ]; then
    echo "⚠️  WARNING: Some hardcoded keys remain in kong.yml"
    echo "   Please review the file manually"
fi

echo "✓ Kong configuration updated successfully!"
echo ""
echo "📝 Next Steps:"
echo "─────────────────────────────────────────────────────────────"
echo "1. Restart Kong to apply changes:"
echo "   docker-compose restart kong"
echo "2. Verify Kong is working:"
echo "   curl http://localhost:7080/docs"
echo "─────────────────────────────────────────────────────────────"
echo ""
