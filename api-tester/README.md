# API Tester — Standalone Installation

Lightweight container for testing APIs through Burp Suite. Parses Swagger/OpenAPI 3.0 specs, lets you configure parameters once, and fire requests through your proxy.

No database required — everything is stored as JSON files on disk.

## Prerequisites

- Docker (20.10+)
- Burp Suite running on the host (default: `localhost:8080`)

## Quick Start

### 1. Get the files

Copy the `api-tester/` directory to the target machine:

```bash
# From the main repo machine
scp -r api-tester/ user@target:/opt/api-tester/

# Or clone just this directory
git clone --depth 1 --filter=blob:none --sparse https://github.com/raptordoug/rag_scan_stack.git
cd rag_scan_stack
git sparse-checkout set api-tester
cp -r api-tester /opt/api-tester
```

### 2. Build the image

```bash
cd /opt/api-tester
docker build -t api-tester .
```

Build takes ~30 seconds. Final image is ~246MB.

### 3. Create data directory

```bash
mkdir -p /opt/api-tester-data/swagger
```

### 4. Run

```bash
docker run -d \
  --name api-tester \
  --restart unless-stopped \
  -p 8090:8090 \
  -v /opt/api-tester-data:/data \
  --add-host=host.docker.internal:host-gateway \
  api-tester
```

Open **http://localhost:8090** in your browser.

## Loading Swagger Files

Three ways to import API specs:

**Drop files in the swagger directory:**
```bash
cp petstore.json /opt/api-tester-data/swagger/
```
Then click the **Dir** button in the UI to scan and import all files.

**Import from URL:**
Paste a Swagger JSON URL into the URL input field and press Enter.

**Import from clipboard:**
Save your spec to the swagger directory and click Dir.

## Connecting to Burp Suite

1. Start Burp Suite on the host machine (default listener: `127.0.0.1:8080`)
2. In the API Tester auth bar, the proxy field defaults to `http://host.docker.internal:8080`
3. Create a session — all requests will route through Burp

To change the proxy, edit the Proxy URL field in the auth bar before creating/updating your session.

### Proxy on a different host

If Burp runs on a different machine:

```bash
docker run -d \
  --name api-tester \
  -p 8090:8090 \
  -v /opt/api-tester-data:/data \
  api-tester
```

Then set the proxy URL in the UI to `http://<burp-ip>:8080`.

## Usage

### Sessions
- Click **New Session** to create a session (stores your token, proxy, and variable values)
- Switch between sessions with the dropdown
- Sessions persist across container restarts

### Config Tab
- Select a collection, click **Config** tab
- Set common parameter values once (environment IDs, API keys, pagination, etc.)
- Click **Guess All Empty Values** to auto-fill test data
- Configs auto-save after 1.5 seconds of inactivity

### Run All
- Select a collection, click **Run All** tab
- Executes every endpoint with your config values and auth token
- Endpoints with missing required path parameters are skipped
- Results show status codes, response times, and error details

### Import/Export Configs
- **Export**: Downloads all saved configs for the current collection as JSON
- **Import**: Load a previously exported JSON file
- Format is portable — works between standalone and main dashboard versions

## Data Persistence

All data lives in `/data` inside the container (mapped to your host volume):

```
/opt/api-tester-data/
├── swagger/          # Swagger/OpenAPI JSON files
├── collections/      # Parsed collection metadata
├── sessions/         # Test sessions
├── history/          # Request/response history
└── configs/          # Saved parameter configurations
```

To back up: copy the entire data directory.
To reset: delete the data directory contents (keep swagger/).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Path to data storage directory |

## Updating

```bash
cd /opt/api-tester
git pull  # or copy updated files
docker build -t api-tester .
docker stop api-tester && docker rm api-tester
# Re-run the docker run command above
```

Your data persists in the mounted volume — nothing is lost on rebuild.

## Troubleshooting

**Container exits immediately:**
```bash
docker logs api-tester
```

**Can't reach Burp proxy:**
- Verify Burp is listening on all interfaces (not just 127.0.0.1)
- Check `--add-host=host.docker.internal:host-gateway` is in your run command
- On Linux without Docker Desktop, `host.docker.internal` may not resolve — use `--network=host` instead:
  ```bash
  docker run -d --name api-tester --network=host -v /opt/api-tester-data:/data api-tester
  ```
  Then access at http://localhost:8090 and set proxy to `http://127.0.0.1:8080`

**Swagger import fails:**
- Ensure the file is valid OpenAPI 3.0 JSON (not Swagger 2.0)
- Check `docker logs api-tester` for parser errors

**Port conflict:**
```bash
docker run -d --name api-tester -p 9090:8090 -v /opt/api-tester-data:/data --add-host=host.docker.internal:host-gateway api-tester
```
Then access at http://localhost:9090
