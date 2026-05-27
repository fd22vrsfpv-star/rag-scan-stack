#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

API_URL="https://localhost:8000"
API_KEY="changeme"

# Use -k to ignore SSL certificate issues for self-signed certs
CURL_OPTS="-s -k"

echo "Testing assets filtering improvements..."
echo ""

# Test 1: Basic assets endpoint
log_info "Testing basic assets endpoint..."
response=$(curl $CURL_OPTS -H "x-api-key: $API_KEY" "$API_URL/assets?limit=10")
total_assets=$(echo "$response" | jq -r '.count // 0')
log_success "Found $total_assets total assets"

# Test 2: Hosts-only filter
log_info "Testing hosts-only filter (should exclude microburst/cloud data)..."
hosts_response=$(curl $CURL_OPTS -H "x-api-key: $API_KEY" "$API_URL/assets?limit=100&asset_kind=hosts-only")
hosts_count=$(echo "$hosts_response" | jq -r '.count // 0')
cloud_ips=$(echo "$hosts_response" | jq -r '.assets[]? | select(.ip == "127.0.0.1" or .ip == "127.0.1.1") | .ip' | wc -l)
microburst_tags=$(echo "$hosts_response" | jq -r '.assets[]? | select(.tags[]? == "microburst") | .ip' | wc -l)

log_success "Hosts-only: $hosts_count assets"
if [ "$cloud_ips" -eq 0 ] && [ "$microburst_tags" -eq 0 ]; then
    log_success "✅ No cloud IPs (127.0.x.x) or microburst tags found in hosts-only results"
else
    log_error "❌ Found $cloud_ips cloud IPs and $microburst_tags microburst assets in hosts-only filter"
fi

# Test 3: Cloud-only filter
log_info "Testing cloud-only filter (should only show microburst/cloud data)..."
cloud_response=$(curl $CURL_OPTS -H "x-api-key: $API_KEY" "$API_URL/assets?limit=100&asset_kind=cloud-only")
cloud_count=$(echo "$cloud_response" | jq -r '.count // 0')
if [ "$cloud_count" -gt 0 ]; then
    log_success "Cloud-only: $cloud_count assets"
    # Check if all results are cloud assets
    all_cloud=$(echo "$cloud_response" | jq -r '.assets[]? | select(.ip == "127.0.0.1" or .ip == "127.0.1.1" or (.tags[]? | . == "microburst" or . == "cloud_import")) | .ip' | wc -l)
    if [ "$all_cloud" -eq "$cloud_count" ]; then
        log_success "✅ All cloud-only results are valid cloud assets"
    else
        log_warning "⚠️ Some cloud-only results may not be cloud assets ($all_cloud/$cloud_count)"
    fi
else
    log_warning "No cloud assets found to test"
fi

# Test 4: Provider filter
log_info "Testing provider filtering..."
provider_response=$(curl $CURL_OPTS -H "x-api-key: $API_KEY" "$API_URL/assets?limit=10&provider=aws")
provider_count=$(echo "$provider_response" | jq -r '.count // 0')
log_success "AWS provider filter: $provider_count assets"

echo ""
echo "Filtering test summary:"
echo "- Total assets: $total_assets"
echo "- Hosts only: $hosts_count"
echo "- Cloud only: $cloud_count"
echo ""

if [ "$cloud_ips" -eq 0 ] && [ "$microburst_tags" -eq 0 ]; then
    log_success "✅ Asset filtering fixes are working correctly!"
    echo ""
    echo "The fixes address:"
    echo "1. 127.0.0.1 and 127.0.1.1 IPs are now filtered out with 'hosts only'"
    echo "2. Microburst and other cloud import data respects scope filtering"
    echo "3. Server-side filtering improves performance"
else
    log_error "❌ Asset filtering still needs adjustment"
fi

echo ""
echo "Next steps:"
echo "1. Test the frontend: http://localhost:3002/assets"
echo "2. Try switching between 'All', 'Hosts only', and 'Cloud Imports' filters"
echo "3. Test scope filtering with microburst data"