# Default Network Interface: eth0

## Summary

All nmap and masscan scans now default to using the **eth0** network interface unless explicitly specified otherwise.

## What Changed

### Before
```python
# scan_tools.py - Old behavior
def start_nmap_scan(ip_address, ports="1-1000"):
    ...
    json={
        "interface": None  # No interface specified
    }
```

Masscan command executed:
```bash
masscan --rate 1000 -oJ output.json -p 1-1000 192.168.1.1
# No -e flag, masscan chooses interface automatically
```

### After
```python
# scan_tools.py - New behavior
def start_nmap_scan(ip_address, ports="1-1000", interface="eth0"):
    ...
    json={
        "interface": "eth0"  # Default to eth0
    }
```

Masscan command executed:
```bash
masscan --rate 1000 -oJ output.json -p 1-1000 -e eth0 192.168.1.1
# Explicitly uses eth0 interface
```

## Technical Flow

### 1. User Request (Claude Desktop)
```
"Scan 192.168.1.1 for open ports"
```

### 2. scan_tools.py (autogen-agents container)
```python
def start_nmap_scan(
    ip_address: str,
    ports: str = "1-1000",
    service_detection: bool = True,
    interface: str = "eth0"  # ✅ NEW DEFAULT
):
    response = httpx.post(
        "http://nmap_scanner:8012/jobs/masscan-then-nmap",
        json={
            "targets": [ip_address],
            "ports": ports,
            "rate": 1000,
            "interface": interface  # ✅ Passed to API
        }
    )
```

### 3. nmap-api.py (nmap_scanner container)
```python
def _run_masscan(targets, ports, rate, interface=None):
    args = ["masscan", "--rate", str(rate), "-oJ", outfile, "-p", ports]

    if interface:  # ✅ interface="eth0" is truthy
        args += ["-e", interface]  # ✅ Adds -e eth0

    args += targets
    subprocess.run(args, check=True)
```

### 4. Final Command Executed
```bash
masscan --rate 1000 -oJ /app/nmap_out/masscan_12345.json -p 1-1000 -e eth0 192.168.1.1
```

## Why eth0?

The `eth0` interface is typically the primary network interface in Docker containers and Linux systems. Using it explicitly ensures:

1. **Predictable behavior**: Scans always use the same interface
2. **No auto-selection**: Masscan won't pick an unexpected interface
3. **Better performance**: Direct interface specification can improve scan speed
4. **Troubleshooting**: Easier to debug network issues when interface is known

## Functions Affected

### 1. start_nmap_scan() - Full scan with service detection
```python
start_nmap_scan(
    ip_address="192.168.1.1",
    ports="1-1000",
    interface="eth0"  # Default, can override
)
```

### 2. start_masscan() - Fast port scan only
```python
start_masscan(
    targets="192.168.1.0/24",
    ports="1-65535",
    rate=1000,
    interface="eth0"  # Default, can override
)
```

## Overriding the Default

If you need to use a different interface, you can override it:

### From Python Code
```python
from scan_tools import scan_tools

# Use a different interface
result = scan_tools.start_nmap_scan(
    ip_address="10.0.0.1",
    ports="80,443",
    interface="wlan0"  # Override to wlan0
)

# Use no interface (let masscan auto-select)
result = scan_tools.start_nmap_scan(
    ip_address="10.0.0.1",
    ports="80,443",
    interface=None  # Override to None
)
```

### From Claude Desktop
Currently, Claude Desktop uses the default `eth0`. To use a different interface, you would need to modify the MCP server to accept interface as a parameter.

## Environment Configuration

You can also set a default interface via environment variable (future enhancement):

```yaml
# docker-compose.yml
autogen-agents:
  environment:
    DEFAULT_SCAN_INTERFACE: "eth0"  # Could be configurable
```

## Container Network Interfaces

To see available interfaces in the nmap_scanner container:

```bash
docker exec nmap_scanner ip link show
```

Typical output:
```
1: lo: <LOOPBACK,UP,LOWER_UP>
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
```

## Verification

### Test that eth0 is being used:

```bash
# Watch nmap_scanner logs during a scan
docker logs -f nmap_scanner

# You should see:
# INFO: scan cmd: masscan --rate 1000 -oJ /app/nmap_out/masscan_12345.json -p 1-1000 -e eth0 192.168.1.1
```

### Manual test from within container:

```bash
# Test masscan with eth0
docker exec nmap_scanner masscan --rate 100 -p 80 -e eth0 scanme.nmap.org

# Verify interface is available
docker exec nmap_scanner ip addr show eth0
```

## Troubleshooting

### Error: "interface not found"

If you see an error about eth0 not being found:

1. **Check available interfaces:**
   ```bash
   docker exec nmap_scanner ip link show
   ```

2. **Use a different interface:**
   Modify `scan_tools.py` to use the correct interface name (e.g., `ens5`, `eno1`, `wlan0`)

3. **Check Docker network mode:**
   The container must be in bridge or host network mode to access network interfaces properly.

### Error: "masscan: failed: using interface eth0"

This usually means:
- The interface exists but has no IP address
- The interface is down
- Permission issues (requires NET_RAW capability)

**Solution:**
```bash
# Check interface status
docker exec nmap_scanner ip addr show eth0

# Verify container has NET_RAW capability
docker inspect nmap_scanner | grep -i cap_add
```

The `docker-compose.yml` already includes:
```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

## Performance Impact

Using `eth0` explicitly can actually **improve** performance:

- **Auto-detection overhead removed**: Masscan doesn't need to probe interfaces
- **Consistent routing**: All packets use the same path
- **Better for automation**: Reproducible results across runs

## Files Modified

1. **`/utils/agents/autogen_agents/scan_tools.py`**
   - Line 107: `interface: str = "eth0"` in `start_masscan_only()`
   - Line 142: `interface: str = "eth0"` in `start_nmap_scan()`
   - Line 129: `"interface": interface` passed to API
   - Line 166: `"interface": interface` passed to API

2. **`/utils/agents/nmap_scanner/nmap-api.py`** (no changes needed)
   - Already supports optional interface parameter
   - Lines 50-52: Properly adds `-e interface` flag when provided

## Rollback

If you need to revert to auto-detection:

```bash
# Edit scan_tools.py
sed -i 's/interface: str = "eth0"/interface: str = None/g' /utils/agents/autogen_agents/scan_tools.py

# Rebuild container
docker-compose build autogen-agents
docker-compose up -d autogen-agents
```

## Related Documentation

- See `/utils/agents/API_ENDPOINTS.md` for complete API reference
- See `/utils/agents/COMMAND_FLOW.md` for scan execution flow
- See `/utils/agents/CLAUDE_DESKTOP_SETUP.md` for Claude Desktop configuration
