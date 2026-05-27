# RAG Stack API Reference

Access the RAG scanning stack from remote machines at: **http://YOUR_HOST**

> Replace `YOUR_HOST` throughout this document with the IP or hostname of the
> machine running the stack (e.g. `localhost` if you're on the same box, or the
> LAN IP `ip -4 addr show | grep inet` reports). All examples below use the
> placeholder so this reference is safe to commit and share.

## Available Services

### Core Services

#### RAG API (Port 8000)
Main API for RAG operations and scan management.

- **Base URL**: `http://YOUR_HOST:8000`
- **Health Check**: `GET http://YOUR_HOST:8000/health`
- **API Key**: Required in headers as `X-API-Key: changeme`

#### LLM Query Service (Port 8002)
Query the LLM for analysis and recommendations.

- **Base URL**: `http://YOUR_HOST:8002`
- **Health Check**: `GET http://YOUR_HOST:8002/healthz`

#### Ollama (Port 11434)
Local LLM inference server.

- **Base URL**: `http://YOUR_HOST:11434`
- **API Docs**: `GET http://YOUR_HOST:11434/api/tags`

### Scanner Services

#### Web Scanner (Port 8010)
Web application vulnerability scanner with ZAP integration.

- **Base URL**: `http://YOUR_HOST:8010`
- **Health Check**: `GET http://YOUR_HOST:8010/health`

#### Nuclei Runner (Port 8011)
Fast vulnerability scanner using Nuclei templates.

- **Base URL**: `http://YOUR_HOST:8011`
- **Health Check**: `GET http://YOUR_HOST:8011/health`

#### Nmap Scanner (Port 8012)
Network port and service discovery scanner.

- **Base URL**: `http://YOUR_HOST:8012`
- **Health Check**: `GET http://YOUR_HOST:8012/health`

#### Scan Recommender (Port 8013)
AI-powered scan recommendation engine.

- **Base URL**: `http://YOUR_HOST:8013`
- **Health Check**: `GET http://YOUR_HOST:8013/health`

#### Playwright Scanner (Port 8014)
Browser-based security testing with Playwright.

- **Base URL**: `http://YOUR_HOST:8014`
- **Health Check**: `GET http://YOUR_HOST:8014/health`

#### Autogen Agents (Port 8015)
Multi-agent system for automated security testing.

- **Base URL**: `http://YOUR_HOST:8015`
- **Health Check**: `GET http://YOUR_HOST:8015/health`

### Security Tools

#### ZAP Proxy (Port 8090)
OWASP ZAP web application security scanner.

- **Base URL**: `http://YOUR_HOST:8090`
- **API Key**: `changeme`
- **Proxy**: Configure proxy to `YOUR_HOST:8090`

### API Gateway

#### Kong (Port 7080)
API Gateway for unified access to all services.

- **Base URL**: `http://YOUR_HOST:7080`
- **Admin API**: `http://localhost:7081` (localhost only)

## VS Code Integration

### Using REST Client Extension

Install the REST Client extension in VS Code and create a `.http` file:

```http
### RAG API Health Check
GET http://YOUR_HOST:8000/health
X-API-Key: changeme

### Query LLM
POST http://YOUR_HOST:8002/query
Content-Type: application/json

{
  "prompt": "Analyze this vulnerability",
  "context": "SQL injection found in login form"
}

### Start Web Scan
POST http://YOUR_HOST:8010/scan
Content-Type: application/json
X-API-Key: changeme

{
  "target": "http://target.example.com",
  "scan_type": "full"
}
```

### Using Thunder Client Extension

1. Install Thunder Client in VS Code
2. Create a new collection
3. Add requests with base URL: `http://YOUR_HOST:8000`
4. Add header: `X-API-Key: changeme`

### Using Python in VS Code

```python
import requests

# Configure base URLs
RAG_API = "http://YOUR_HOST:8000"
OLLAMA_API = "http://YOUR_HOST:11434"

# API Key
API_KEY = "changeme"

# Example: Check RAG API health
response = requests.get(
    f"{RAG_API}/health",
    headers={"X-API-Key": API_KEY}
)
print(response.json())

# Example: Query Ollama
response = requests.post(
    f"{OLLAMA_API}/api/generate",
    json={
        "model": "interstellarninja/hermes-3-llama-3.1-8b-tools",
        "prompt": "Explain SQL injection"
    }
)
print(response.json())
```

### Using JavaScript/TypeScript in VS Code

```javascript
// Configure API client
const RAG_API = 'http://YOUR_HOST:8000';
const API_KEY = 'changeme';

// Example: Check health
fetch(`${RAG_API}/health`, {
  headers: {
    'X-API-Key': API_KEY
  }
})
  .then(res => res.json())
  .then(data => console.log(data));

// Example: Start a scan
fetch(`${RAG_API}/scan/start`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
  },
  body: JSON.stringify({
    target: 'http://target.example.com',
    scan_type: 'full'
  })
})
  .then(res => res.json())
  .then(data => console.log(data));
```

## Authentication

Most services require an API key in the headers:

```
X-API-Key: changeme
```

**Security Note**: Change the default API key in production!

## Troubleshooting

### Cannot Connect from Remote Machine

1. **Check Windows Firewall**: Ensure ports are allowed
2. **Verify Port Forwarding**: Run `netsh interface portproxy show all` on Windows
3. **Check Docker Containers**: Ensure all containers are running
4. **Test Locally First**: Try `http://localhost:8000` on the WSL machine

### Connection Timeout

- Verify the Windows IP hasn't changed
- Check if Docker containers are healthy: `docker ps`
- Restart port forwarding script if WSL restarted

### WSL IP Changed After Reboot

Run the port forwarding script again:
```powershell
.\setup-rag-port-forwarding.ps1
```

## Security Recommendations

1. **Change Default API Keys**: Update `API_KEY` and `ZAP_API_KEY` in docker-compose.yml
2. **Use HTTPS**: Consider adding TLS termination with Kong or nginx
3. **Network Isolation**: Use firewall rules to restrict access to trusted IPs only
4. **Authentication**: Implement proper authentication for production use

## Quick Test Commands

Test all services are accessible:

```bash
# From the remote machine
curl http://YOUR_HOST:8000/health
curl http://YOUR_HOST:8002/healthz
curl http://YOUR_HOST:8010/health
curl http://YOUR_HOST:8011/health
curl http://YOUR_HOST:8012/health
curl http://YOUR_HOST:8013/health
curl http://YOUR_HOST:8014/health
curl http://YOUR_HOST:8015/health
curl http://YOUR_HOST:8090/
curl http://YOUR_HOST:11434/api/tags
```
