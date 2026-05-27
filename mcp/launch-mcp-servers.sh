#!/bin/bash
# Launch category MCP servers in parallel
# Each on a separate port for selective enabling in Open WebUI

echo "Starting built-in MCP category servers..."
python mcp-sessions.py &
python mcp-scanning.py &
python mcp-recon.py &
python mcp-exploit.py &
python mcp-credentials.py &
python mcp-pipelines.py &
python mcp-burp.py &
python mcp-zap.py &

echo "Built-in MCP servers started:"
echo "  Sessions:     port 9016 (17 tools)"
echo "  Scanning:     port 9017 (16 tools)"
echo "  Recon:        port 9018  (9 tools)"
echo "  Exploit:      port 9019  (8 tools)"
echo "  Credentials:  port 9020  (2 tools)"
echo "  Pipelines:    port 9021  (3 tools)"
echo "  Burp:         port 9022 (10 tools)"
echo "  ZAP:          port 9023 (10 tools)"

# ── Launch third-party servers from registry ──
REGISTRY="/app/third_party/registry.yaml"
if [ -f "$REGISTRY" ]; then
    echo ""
    echo "Loading third-party MCP servers from registry..."
    python -c "
import yaml, os, subprocess, sys

with open('$REGISTRY') as f:
    reg = yaml.safe_load(f) or {}

servers = reg.get('servers', [])
if not servers:
    print('  No third-party servers configured')
    sys.exit(0)

for srv in servers:
    if not srv.get('enabled', False):
        continue

    name = srv['name']
    source = srv.get('source', 'local')
    transport = srv.get('transport', 'stdio')
    port = srv.get('port', 9030)
    env_vars = srv.get('env', {})
    package = srv.get('package', '')
    path = srv.get('path', '')
    args = srv.get('args', [])

    # Set environment variables
    for k, v in env_vars.items():
        if v:  # Only set non-empty values
            os.environ[k] = str(v)

    # Build the command
    if source == 'npm':
        cmd = f'npx -y {package}'
        if args:
            cmd += ' ' + ' '.join(str(a) for a in args)
    elif source == 'pip':
        cmd = f'python -m {package}'
        if args:
            cmd += ' ' + ' '.join(str(a) for a in args)
    elif source == 'local':
        cmd = f'python {path}'
        if args:
            cmd += ' ' + ' '.join(str(a) for a in args)
    elif source == 'github':
        repo = srv.get('repo', '')
        entry = srv.get('entry', 'server.py')
        clone_dir = f'/tmp/mcp-{name}'
        os.system(f'git clone --depth 1 {repo} {clone_dir} 2>/dev/null')
        cmd = f'python {clone_dir}/{entry}'
    else:
        print(f'  Unknown source: {source} for {name}')
        continue

    if transport == 'stdio':
        # Wrap with stdio bridge
        full_cmd = f'python /app/stdio_bridge.py --port {port} --name {name} --cmd \"{cmd}\"'
    else:
        # Run directly (assumes it handles its own port)
        full_cmd = cmd

    print(f'  Starting {name} (port {port}, {source}/{transport}): {cmd[:60]}')
    subprocess.Popen(full_cmd, shell=True)

# Keep this script alive so wait -n doesn't trigger on registry loader exit
import time, signal, sys
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
while True:
    time.sleep(3600)
" &
fi

# Wait for any built-in MCP server to exit (not the registry loader)
wait -n
EXIT_CODE=$?
echo "A server exited (code $EXIT_CODE), shutting down..."
kill $(jobs -p) 2>/dev/null
wait
exit $EXIT_CODE
