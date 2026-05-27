# Autogen Multi-Agent Penetration Testing System

AI-powered autonomous penetration testing using specialized agents that coordinate to plan, execute, analyze, and report security assessments.

## Overview

The Autogen Multi-Agent System uses Microsoft's Autogen framework with local Ollama LLMs to create a team of specialized AI agents that work together to perform comprehensive penetration tests. Each agent has specific expertise and tools, collaborating through natural language to complete complex security assessments.

**Dual Interface Support:**
- **FastAPI REST API** (Port 8015) - For programmatic access and integrations
- **MCP Protocol** (stdio) - For AI assistant integration (Claude Desktop, etc.)

See [MCP_GUIDE.md](MCP_GUIDE.md) for Model Context Protocol integration with Claude Desktop.

## Architecture

### Agent Team

```
┌─────────────────┐
│  Coordinator    │ ← Manages workflow and priorities
│                 │
│  • Plans tasks  │
│  • Assigns work │
│  • Makes decisions│
└────────┬────────┘
         │
    ┌────┴────┬─────────┬────────┐
    ▼         ▼         ▼        ▼
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
│Recon │  │Scanner│ │Analyzer││Reporter│
│      │  │       │  │       │  │       │
│Tools:│  │Tools: │  │Tools: │  │Tools: │
│-Query│  │-Nmap  │  │-RAG DB│  │-Query │
│Assets│  │-Web   │  │-ExplDB│  │All    │
│-Query│  │-Nuclei│  │-Analyze│  │Tables │
│Ports │  │-Playwright│Findings│  │      │
└──────┘  └──────┘  └──────┘  └──────┘
```

### Agent Roles

**Coordinator**
- Orchestrates the penetration testing workflow
- Assigns tasks to specialized agents
- Makes strategic decisions
- Prioritizes targets and scans
- Determines completion criteria

**Reconnaissance Specialist**
- Analyzes target information
- Plans reconnaissance strategy
- Recommends scan types and parameters
- Prioritizes targets
- Queries current asset and port data

**Scanner Orchestrator**
- Executes scans based on recommendations
- Monitors scan progress
- Handles scan failures
- Triggers follow-up scans
- Parses and normalizes results

**Vulnerability Analyzer**
- Analyzes scan results
- Correlates findings across sources
- Queries ExploitDB for exploits
- Assesses risk and exploitability
- Recommends next steps

**Report Generator**
- Compiles findings into reports
- Organizes by severity and asset
- Generates executive summaries
- Provides remediation guidance
- Formats in markdown

### Integration with Scanning Services

```
┌────────────────────┐
│ Autogen Agents     │
└──────────┬─────────┘
           │
     ┌─────┴──────────────┬─────────────┬──────────────┐
     │                    │             │              │
     ▼                    ▼             ▼              ▼
┌─────────┐         ┌──────────┐  ┌─────────┐  ┌──────────┐
│Nmap     │         │Web       │  │Nuclei   │  │Playwright│
│Scanner  │         │Scanner   │  │Runner   │  │Scanner   │
│(8012)   │         │(8010)    │  │(8011)   │  │(8014)    │
└─────────┘         └──────────┘  └─────────┘  └──────────┘
     │                    │             │              │
     └────────┬───────────┴─────────────┴──────────────┘
              │
              ▼
     ┌─────────────────┐
     │   PostgreSQL    │
     │  (scan results) │
     └─────────────────┘
```

## API Endpoints

### Health Check
```bash
GET /health
```

**Response:**
```json
{
  "ok": true,
  "service": "autogen-agents",
  "active_sessions": 2,
  "ollama_url": "http://ollama:11434"
}
```

### Start Pentest Session
```bash
POST /pentest
```

**Request Body:**
```json
{
  "target_description": "192.168.1.0/24 web application subnet",
  "session_name": "WebApp Pentest 2025-01",
  "initial_task": "Perform reconnaissance and identify vulnerabilities in the web application",
  "max_rounds": 200,
  "auto_execute_scans": true
}
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "Pentest session started successfully"
}
```

### Get Session Status
```bash
GET /pentest/{session_id}
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_name": "WebApp Pentest 2025-01",
  "status": "active",
  "target_description": "192.168.1.0/24 web application subnet",
  "started_at": "2025-01-15T10:00:00Z",
  "ended_at": null,
  "message_count": 47,
  "summary": null,
  "configuration": {
    "max_rounds": 200,
    "auto_execute_scans": true
  }
}
```

### Get Session Messages
```bash
GET /pentest/{session_id}/messages?limit=100
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "messages": [
    {
      "agent_name": "Coordinator",
      "role": "assistant",
      "content": "I'll coordinate the team to assess the web application...",
      "timestamp": "2025-01-15T10:00:05Z",
      "metadata": {}
    },
    {
      "agent_name": "Reconnaissance",
      "role": "assistant",
      "content": "Analyzing current assets and open ports...",
      "timestamp": "2025-01-15T10:00:12Z",
      "metadata": {}
    }
  ]
}
```

### Get Final Report
```bash
GET /pentest/{session_id}/report
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_name": "WebApp Pentest 2025-01",
  "target_description": "192.168.1.0/24 web application subnet",
  "report": "# Security Assessment Report\n\n## Executive Summary...",
  "generated_at": "2025-01-15T10:45:00Z",
  "status": "completed"
}
```

### List Sessions
```bash
GET /sessions?status=active&limit=50
```

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "session_name": "WebApp Pentest 2025-01",
      "status": "active",
      "target_description": "192.168.1.0/24 web application subnet",
      "created_at": "2025-01-15T10:00:00Z",
      "end_time": null
    }
  ],
  "total": 1
}
```

### Stop Session
```bash
POST /pentest/{session_id}/stop
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "stopped",
  "message": "Session stopped successfully"
}
```

## Usage Examples

### Basic Pentest Session via Kong Gateway
```bash
curl -X POST http://localhost:7080/agents/pentest \
  -H "Content-Type: application/json" \
  -d '{
    "target_description": "Internal web application at 10.0.1.0/24",
    "session_name": "Internal App Assessment",
    "initial_task": "Discover all web services and test for OWASP Top 10 vulnerabilities",
    "max_rounds": 40,
    "auto_execute_scans": true
  }'
```

### Monitor Session Progress
```bash
# Get current status
curl http://localhost:7080/agents/pentest/550e8400-e29b-41d4-a716-446655440000

# Watch agent conversation
curl "http://localhost:7080/agents/pentest/550e8400-e29b-41d4-a716-446655440000/messages?limit=50"
```

### Get Final Report
```bash
curl http://localhost:7080/agents/pentest/550e8400-e29b-41d4-a716-446655440000/report > report.md
```

### List All Sessions
```bash
# Active sessions only
curl "http://localhost:7080/agents/sessions?status=active"

# All completed sessions
curl "http://localhost:7080/agents/sessions?status=completed&limit=100"
```

### Direct Service Access (Development)
```bash
curl -X POST http://localhost:8015/pentest \
  -H "Content-Type: application/json" \
  -d '{
    "target_description": "192.168.1.100 SSH server",
    "session_name": "SSH Service Test",
    "initial_task": "Test SSH service for common vulnerabilities"
  }'
```

## Agent Tools

Each agent has access to specific tools for their role:

### Reconnaissance Agent Tools
- `query_assets()` - List discovered assets
- `query_open_ports()` - List open ports
- `get_scan_recommendations()` - Get AI scan suggestions

### Scanner Agent Tools
- `start_nmap_scan()` - Launch Nmap scans
- `start_web_scan()` - Launch Gobuster + ZAP
- `start_nuclei_scan()` - Launch Nuclei templates
- `start_playwright_scan()` - Launch browser security tests

### Analyzer Agent Tools
- `query_vulnerabilities()` - Get vulnerability findings
- `query_exploitdb()` - Search ExploitDB via RAG
- `query_open_ports()` - Analyze attack surface

### Reporter Agent Tools
- `query_vulnerabilities()` - Compile all findings
- `query_assets()` - Asset inventory
- `query_open_ports()` - Port summary

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DSN` | `postgresql://app:app@rag-postgres:5432/scans` | Database connection |
| `API_KEY` | `changeme` | API key for service authentication |
| `OLLAMA_URL` | `http://ollama:11434` | Ollama LLM service URL |
| `OLLAMA_MODEL` | `llama3.1:8b` | LLM model for agents |
| `RAG_API_URL` | `http://rag-api:8000` | RAG API service |
| `WEB_SCANNER_URL` | `http://web-scanner:8010` | Web scanner service |
| `NUCLEI_URL` | `http://nuclei-runner:8011` | Nuclei runner service |
| `NMAP_URL` | `http://nmap_scanner:8012` | Nmap scanner service |
| `PLAYWRIGHT_URL` | `http://playwright-scanner:8014` | Playwright scanner |
| `SCAN_RECOMMENDER_URL` | `http://scan-recommender:8013` | Scan recommender |

## Database Schema

### agent_sessions
Stores pentest session metadata.

```sql
CREATE TABLE agent_sessions (
    id                  uuid PRIMARY KEY,
    session_name        text NOT NULL,
    target_description  text NOT NULL,
    status              text CHECK (status IN ('active','completed','failed','stopped')),
    configuration       jsonb,
    summary             text,
    metadata            jsonb,
    created_at          timestamptz,
    updated_at          timestamptz,
    end_time            timestamptz
);
```

### agent_messages
Stores agent conversation history.

```sql
CREATE TABLE agent_messages (
    id          uuid PRIMARY KEY,
    session_id  uuid REFERENCES agent_sessions(id) ON DELETE CASCADE,
    agent_name  text NOT NULL,
    role        text NOT NULL,
    content     text NOT NULL,
    metadata    jsonb,
    created_at  timestamptz
);
```

## Workflow Example

1. **User initiates session**:
   ```
   POST /pentest with target "10.0.1.0/24 web application"
   ```

2. **Coordinator analyzes request**:
   - Breaks down into tasks
   - Assigns Reconnaissance agent to discover assets

3. **Reconnaissance queries database**:
   - Calls `query_assets()` - finds 10.0.1.50, 10.0.1.51
   - Calls `query_open_ports()` - finds ports 80, 443, 8080
   - Recommends: Nmap detailed scan, web application testing

4. **Scanner executes scans**:
   - Calls `start_nmap_scan("10.0.1.50", "1-65535")`
   - Calls `start_web_scan(do_gobuster=true, do_zap=true)`
   - Calls `start_playwright_scan("https://10.0.1.50")`
   - Monitors scan progress

5. **Analyzer reviews results**:
   - Calls `query_vulnerabilities(severity="high")`
   - Finds XSS, SQL injection, missing security headers
   - Calls `query_exploitdb("apache 2.4.41 exploit")`
   - Assesses criticality and exploitability

6. **Reporter generates findings**:
   - Calls `query_vulnerabilities()` for all findings
   - Calls `query_assets()` for inventory
   - Compiles markdown report with:
     - Executive summary
     - Detailed findings per asset
     - Risk ratings
     - Remediation steps

7. **Coordinator reviews completion**:
   - Confirms all critical services tested
   - Validates report completeness
   - Marks session as completed

## Integration with Other Services

### RAG API
- Query vulnerability database
- Access ExploitDB through RAG
- Retrieve scan results

### Scan Services
- Nmap: Port scanning and service detection
- Web Scanner: Directory enum and ZAP testing
- Nuclei: Template-based vulnerability scanning
- Playwright: Browser-based security testing

### Database
- All scan results stored centrally
- Unified vulnerability view
- Historical data for trend analysis

## Configuration

### Agent System Messages

Each agent's behavior is defined by its system message in `agent_config.py:SYSTEM_MESSAGES`. These can be customized to modify agent specialization, tool usage, and communication style.

### LLM Configuration

The system uses Ollama with llama3.1:8b by default. To use a different model:

```bash
# In .env or docker-compose.yml
OLLAMA_MODEL=llama3.1:70b  # For higher quality
# or
OLLAMA_MODEL=mistral:latest  # For faster responses
```

### Scan Parameters

Agents make intelligent decisions about scan parameters, but defaults can be influenced through:
- Initial task description
- Target description specificity
- Session configuration

## Performance

- **Session Duration**: 5-30 minutes depending on scope
- **Typical Rounds**: 15-25 agent interactions
- **Memory Usage**: ~1GB per active session
- **Concurrent Sessions**: Supports multiple simultaneous pentests

## Troubleshooting

### Agents Not Responding
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Check autogen-agents service
docker logs autogen-agents

# Verify database connection
docker exec autogen-agents psql $DB_DSN -c "SELECT 1;"
```

### Session Stuck
```bash
# Stop the session
curl -X POST http://localhost:7080/agents/pentest/{session_id}/stop

# Check agent messages for errors
curl http://localhost:7080/agents/pentest/{session_id}/messages
```

### Scan Tools Not Working
```bash
# Verify service connectivity
docker exec autogen-agents curl http://nmap_scanner:8012/health
docker exec autogen-agents curl http://web-scanner:8010/health
docker exec autogen-agents curl http://playwright-scanner:8014/health
```

## Best Practices

1. **Clear Target Descriptions**: Provide specific IP ranges, hostnames, or URLs
2. **Descriptive Session Names**: Use dates and project names for tracking
3. **Specific Initial Tasks**: Guide the coordinator with clear objectives
4. **Monitor Progress**: Check messages periodically for agent decisions
5. **Review Reports**: Validate findings and add manual observations
6. **Manage Sessions**: Stop inactive sessions to free resources

## Security Considerations

1. **API Key Protection**: Change default API_KEY in production
2. **Network Isolation**: Run in isolated network for testing
3. **Access Control**: Use Kong authentication for production
4. **Scan Authorization**: Only test authorized targets
5. **Data Retention**: Configure database retention policies

## Future Enhancements

- **Custom Agent Roles**: User-defined specialized agents
- **Learning from Results**: Agent fine-tuning on successful findings
- **Collaboration Mode**: Human-in-the-loop approvals
- **Advanced Reporting**: PDF generation with charts
- **Integration APIs**: Webhooks for external systems
- **Multi-LLM Support**: Use different models per agent role

## Modules

### agent_config.py
Agent configuration and Ollama LLM setup:
- `get_ollama_config()` - LLM configuration
- `create_assistant_agent()` - Create AI agents
- `create_group_chat()` - Multi-agent coordination
- `SYSTEM_MESSAGES` - Agent role definitions

### scan_tools.py
Integration with scanning services:
- `ScanTools` - HTTP client for all services
- Function wrappers for Autogen function calling
- Tool registration for agents

### pentest_agents.py
Specialized agent creation:
- `PentestTeam` - Team of specialized agents
- Agent initialization with tools
- Group chat and manager creation

### db_utils.py
Database persistence:
- `create_agent_session()` - Session management
- `add_agent_message()` - Conversation logging
- `get_agent_session()` - Session retrieval
- `link_session_to_scans()` - Scan correlation

### autogen_service.py
FastAPI application:
- `/pentest` - Start sessions
- `/pentest/{id}` - Session status
- `/pentest/{id}/messages` - Conversation history
- `/pentest/{id}/report` - Final report
- `/sessions` - List sessions

## Contributing

When extending the system:
1. Add new tools in `scan_tools.py`
2. Register tools with appropriate agents in `pentest_agents.py`
3. Update agent system messages in `agent_config.py`
4. Document new endpoints in this README
5. Add environment variables to docker-compose.yml
6. Update database schema if needed

## References

- [Microsoft Autogen Documentation](https://microsoft.github.io/autogen/)
- [Ollama Documentation](https://ollama.ai/docs)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
