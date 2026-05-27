# Fix: AnythingLLM on Windows Cannot Connect to MCP Service

## Problem
AnythingLLM running on Windows is using `http://localhost:8016` to connect to the MCP service, but the MCP server runs inside Docker on WSL2. Due to WSL2's network architecture, `localhost` on Windows and `localhost` in WSL2 are **isolated** - they don't reach each other.

## Solution
Use the WSL2 IP address instead of `localhost` when configuring AnythingLLM on Windows.

### Step 1: Get the WSL2 IP Address

From a WSL2 terminal, run:
```bash
hostname -I | awk '{print $1}'
```

Or from PowerShell on Windows:
```powershell
wsl hostname -I
```

This will return an IP like `172.20.x.x` or `192.168.x.x`.

### Step 2: Verify MCP Server is Accessible

Test from WSL2 first:
```bash
curl http://localhost:8016/health
```

Then test from Windows PowerShell using the WSL2 IP:
```powershell
curl http://<wsl2-ip>:8016/health
```

### Step 3: Update AnythingLLM Configuration

In AnythingLLM's MCP settings, change the URL from:
```
http://localhost:8016
```
to:
```
http://<wsl2-ip>:8016
```

For example: `http://172.20.45.123:8016`

## Important Notes

1. **WSL2 IP changes on reboot** - The WSL2 IP address can change when you restart Windows or WSL. You may need to update AnythingLLM's config after reboots.

2. **Alternative: Set up port forwarding** - For a more permanent solution, you can forward Windows port 8016 to WSL2 (run as Administrator in PowerShell):
   ```powershell
   $wslIp = (wsl hostname -I).Split()[0]
   netsh interface portproxy add v4tov4 listenport=8016 listenaddress=0.0.0.0 connectport=8016 connectaddress=$wslIp
   ```
   This allows `localhost:8016` to work from Windows but needs to be re-run when WSL2 IP changes.

3. **MCP Transport Type** - The MCP server uses **SSE (Server-Sent Events)** transport via HTTP. Ensure AnythingLLM is configured for HTTP/SSE MCP, not stdio.

## Verification
After updating the URL:
1. Test the health endpoint in a browser: `http://<wsl2-ip>:8016/health`
2. Test the tools endpoint: `http://<wsl2-ip>:8016/tools` (lists all 23+ available MCP tools)
3. Try connecting AnythingLLM with the new URL

## Files Reference
- MCP Server: `/opt/rag-scan-stack/mcp/autogen-http-mcp-server.py`
- Docker Compose: `/opt/rag-scan-stack/docker-compose.yml` (lines 318-346)
