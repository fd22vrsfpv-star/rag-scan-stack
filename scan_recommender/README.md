# Exploit Recommender with RAG (Retrieval-Augmented Generation)

AI-powered exploit search and recommendation system using vector embeddings to match vulnerabilities with relevant exploits from ExploitDB.

## Overview

The Scan Recommender service uses Retrieval-Augmented Generation (RAG) to intelligently search and recommend exploits from ExploitDB. It combines:

- **Vector embeddings** (via Ollama's embedding models) for semantic search
- **PostgreSQL with pgvector** for efficient similarity matching
- **LLM integration** (Mistral/Llama) for contextual Q&A
- **SearchSploit JSON** as the exploit database source

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Scan Recommender Service               │
│                  (Port 8013)                        │
└──────────────────┬──────────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌────────┐   ┌─────────┐   ┌──────────┐
│Ollama  │   │PostgreSQL│   │ExploitDB │
│(LLM/   │   │(pgvector)│   │Repository│
│Embed)  │   │Exploits  │   │(JSON)    │
│:11434  │   │:5432     │   │          │
└────────┘   └─────────┘   └──────────┘
```

### Components

**Vector Database**
- Stores exploit chunks with embeddings (768-dimensional vectors)
- Uses pgvector extension for similarity search
- Indexed with IVFFlat for fast retrieval

**Embedding Model**
- Default: `nomic-embed-text` (via Ollama)
- Converts text to semantic vectors
- Enables similarity-based search

**LLM Chat Model**
- Default: `mistral` (via Ollama)
- Answers questions using retrieved context
- Provides exploit recommendations

**SearchSploit Integration**
- Ingests ExploitDB JSON exports
- Chunks exploit code/descriptions
- Maintains metadata (CVE, platform, type)

## API Endpoints

### Health Check

```bash
GET /health
```

Returns service status and configuration.

**Response:**
```json
{
  "ok": true,
  "ollama_host": "http://ollama:11434",
  "embed_model": "nomic-embed-text",
  "chat_model": "mistral",
  "db_connected": true
}
```

---

### Update SearchSploit JSON

```bash
POST /rag/update_json
```

Generates fresh SearchSploit JSON by running `searchsploit --json`.

**Request Body:**
```json
{
  "output_path": "/var/lib/searchsploit/searchsploit.json",
  "searchsploit_path": "searchsploit",
  "include_urls": true,
  "include_paths": true,
  "timeout_sec": 240,
  "run_git_pull": true,
  "exploitdb_dir": "/opt/exploitdb"
}
```

**Parameters:**
- `output_path`: Where to save the JSON
- `searchsploit_path`: Searchsploit binary location
- `include_urls`: Add `-w` flag for exploit URLs
- `include_paths`: Add `-p` flag for local file paths
- `timeout_sec`: Command timeout
- `run_git_pull`: Update exploitdb repo before export
- `exploitdb_dir`: Local exploitdb repository location

**Response:**
```json
{
  "ok": true,
  "output_path": "/var/lib/searchsploit/searchsploit.json",
  "file_size": 45678901,
  "entry_count": 52000,
  "elapsed_sec": 125.3
}
```

---

### Ingest Exploits into Vector DB

```bash
POST /rag/ingest
```

Loads SearchSploit JSON and ingests exploits into the vector database.

**Request Body:**
```json
{
  "searchsploit_json": "/var/lib/searchsploit/searchsploit.json",
  "exploit_root": "/opt/exploitdb"
}
```

**Process:**
1. Reads SearchSploit JSON
2. For each exploit:
   - Reads source code from filesystem
   - Chunks into 3000-char segments (200-char overlap)
   - Generates embeddings via Ollama
   - Stores in PostgreSQL with metadata
3. Deduplicates by (edb_id, chunk_id)

**Response:**
```json
{
  "ok": true,
  "inserted": 156789
}
```

---

### Ask Questions (RAG Query)

```bash
GET /rag/ask?q=wordpress+rce&top_k=6
```

Ask natural language questions about exploits using RAG.

**Parameters:**
- `q`: Your question (e.g., "WordPress RCE vulnerabilities")
- `top_k`: Number of similar chunks to retrieve (1-25, default: 6)

**Process:**
1. Embeds your question
2. Finds top-k similar exploit chunks (vector similarity)
3. Constructs context from retrieved chunks
4. Asks LLM to answer using the context
5. Returns answer with source EDB IDs

**Response:**
```json
{
  "answer": "Several WordPress RCE vulnerabilities exist...",
  "sources": [
    {"edb_id": 50420, "title": "WordPress Plugin X - RCE", "similarity": 0.89},
    {"edb_id": 49876, "title": "WordPress Core 5.x RCE", "similarity": 0.85}
  ]
}
```

---

### Refresh (Update + Ingest)

```bash
POST /rag/refresh
```

Convenience endpoint that runs both `update_json` and `ingest` sequentially.

**Request Body:** (combines parameters from both endpoints)
```json
{
  "output_path": "/var/lib/searchsploit/searchsploit.json",
  "exploit_root": "/opt/exploitdb",
  "searchsploit_path": "searchsploit",
  "include_urls": true,
  "include_paths": true,
  "timeout_sec": 240,
  "run_git_pull": true,
  "exploitdb_dir": "/opt/exploitdb"
}
```

**Response:**
```json
{
  "ok": true,
  "update": {
    "file_size": 45678901,
    "entry_count": 52000
  },
  "ingest": {
    "inserted": 156789
  }
}
```

---

### Debug Diagnostics

```bash
GET /rag/debug?json_path=/searchsploit.json&sample=5
```

Provides diagnostics about the JSON file and exploit paths.

**Parameters:**
- `json_path`: SearchSploit JSON file location
- `exploit_root`: ExploitDB repository root
- `sample`: Number of file paths to verify (1-50)

**Response:**
```json
{
  "json": {
    "path": "/var/lib/searchsploit/searchsploit.json",
    "exists": true,
    "size_bytes": 45678901,
    "entry_count": 52000,
    "entries_with_path": 48500,
    "entries_without_path": 3500
  },
  "exploit_root": {
    "path": "/opt/exploitdb",
    "exists": true,
    "is_dir": true
  },
  "database": {
    "connected": true,
    "table_exists": true,
    "row_count": 156789
  },
  "sample_paths": [
    {
      "path": "exploits/linux/local/12345.c",
      "resolved": "/opt/exploitdb/exploits/linux/local/12345.c",
      "exists": true,
      "size": 4567
    }
  ]
}
```

---

## Configuration

### Environment Variables

```bash
# Ollama LLM Configuration
OLLAMA_HOST=http://ollama:11434
EMBED_MODEL=nomic-embed-text        # Embedding model
CHAT_MODEL=mistral                  # Chat/generation model

# Database Configuration
PG_DSN=postgresql://app:password@rag-postgres:5432/exploits

# SearchSploit Paths (in-container defaults)
SEARCHSPLOIT_JSON=/var/lib/searchsploit/searchsploit.json
EXPLOIT_ROOT=/opt/exploitdb
```

### Database Schema

```sql
CREATE TABLE exploit_chunks (
  id BIGSERIAL PRIMARY KEY,
  edb_id INTEGER,                    -- ExploitDB ID
  title TEXT,                        -- Exploit title
  path TEXT,                         -- File path
  platform TEXT,                     -- Target platform
  type TEXT,                         -- Exploit type (remote, local, etc.)
  source_repo TEXT,                  -- 'exploitdb'
  published DATE,                    -- Publication date
  chunk_id INTEGER,                  -- Chunk number within exploit
  chunk TEXT,                        -- Chunk text content
  embedding vector(768),             -- Semantic embedding
  sha256 TEXT,                       -- Chunk hash for deduplication
  UNIQUE (edb_id, chunk_id)
);

-- Vector similarity index
CREATE INDEX exploit_chunks_embedding_idx
  ON exploit_chunks USING ivfflat (embedding vector_l2_ops)
  WITH (lists = 100);
```

---

## Usage Examples

### Example 1: Initial Setup

```bash
# 1. Generate SearchSploit JSON
curl -X POST http://localhost:8013/rag/update_json \
  -H "Content-Type: application/json" \
  -d '{
    "run_git_pull": true,
    "include_urls": true,
    "include_paths": true
  }'

# 2. Ingest into vector database
curl -X POST http://localhost:8013/rag/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "searchsploit_json": "/var/lib/searchsploit/searchsploit.json",
    "exploit_root": "/opt/exploitdb"
  }'
```

### Example 2: Search for Exploits

```bash
# Ask a question
curl "http://localhost:8013/rag/ask?q=Apache+Struts+RCE+2017&top_k=5"

# Output:
{
  "answer": "Apache Struts 2 had a critical RCE vulnerability (CVE-2017-5638)
             in the Jakarta Multipart parser...",
  "sources": [
    {"edb_id": 41570, "title": "Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution"},
    {"edb_id": 41614, "title": "Apache Struts 2 - REST Plugin XStream RCE"}
  ]
}
```

### Example 3: Scheduled Refresh

```bash
# Refresh weekly (cron job)
0 2 * * 0 curl -X POST http://localhost:8013/rag/refresh \
  -H "Content-Type: application/json" \
  -d '{"run_git_pull": true}'
```

---

## Integration with Autogen Agents

The Scan Recommender integrates with the Autogen multi-agent system:

```python
# In Autogen agent tools
def query_exploitdb(vulnerability: str) -> str:
    """Query ExploitDB for relevant exploits"""
    response = requests.get(
        "http://scan-recommender:8013/rag/ask",
        params={"q": vulnerability, "top_k": 5}
    )
    return response.json()["answer"]
```

**Agent Usage:**
- Vulnerability Analyzer uses `/rag/ask` to find exploits
- Scanner Orchestrator checks exploit availability
- Report Generator includes exploit references

---

## Performance Considerations

### Ingestion
- **First run:** ~30-60 minutes for full ExploitDB (~50k entries)
- **Updates:** Only new/changed exploits are inserted (by sha256 hash)
- **Chunking:** Large exploits split into 3000-char chunks

### Query Performance
- **Vector search:** < 100ms for similarity search
- **LLM generation:** 2-10 seconds depending on context size
- **Top-K:** Higher values increase accuracy but slow down LLM

### Optimization Tips
1. Use `top_k=3-6` for best speed/accuracy balance
2. Run ingestion during off-peak hours
3. Periodically vacuum the database
4. Monitor Ollama resource usage

---

## Troubleshooting

### Issue: Slow embeddings
**Solution:** Increase Ollama resources or use faster embedding model

```bash
# Use smaller/faster model
EMBED_MODEL=all-minilm
```

### Issue: Database connection failures
**Check:**
```bash
# Verify pgvector extension
psql $PG_DSN -c "SELECT * FROM pg_extension WHERE extname='vector';"

# Check table exists
psql $PG_DSN -c "\dt exploit_chunks"
```

### Issue: SearchSploit JSON not found
**Solution:** Verify paths and run update_json

```bash
curl -X POST http://localhost:8013/rag/debug \
  -H "Content-Type: application/json" \
  -d '{"json_path": "/var/lib/searchsploit/searchsploit.json"}'
```

---

## Development

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Start service
uvicorn scan_recommender.multi_app:app --host 0.0.0.0 --port 8013
```

### Running with Docker

```bash
docker-compose up scan-recommender
```

### Testing RAG Quality

```bash
# Test with known CVE
curl "http://localhost:8013/rag/ask?q=CVE-2021-44228+log4j"

# Compare with searchsploit
searchsploit log4j
```

---

## Architecture Decisions

### Why pgvector?
- Native PostgreSQL integration (no separate vector DB)
- Efficient similarity search with IVFFlat indexing
- ACID compliance for exploit metadata

### Why Chunking?
- Exploit files can be very large (10k+ lines)
- Embedding models have token limits (~512-2048)
- Overlapping chunks preserve context at boundaries

### Why Ollama?
- Local LLM execution (no external API dependencies)
- Multiple model support (Mistral, Llama, etc.)
- Fast inference with quantized models

---

## Future Enhancements

- [ ] Add exploit categorization/tagging
- [ ] Support for CVE direct lookup
- [ ] Exploit effectiveness scoring
- [ ] Multi-language exploit search
- [ ] Integration with Metasploit modules
- [ ] Cached popular queries
- [ ] Exploit trending/statistics

---

## Related Documentation

- [Autogen Agents README](../autogen_agents/README.md) - AI agent integration
- [API_ENDPOINTS.md](../API_ENDPOINTS.md) - All API endpoints
- [Database Schema](../db_init/setup_alldb.sql) - Complete DB schema

---

## References

- [ExploitDB](https://www.exploit-db.com/) - Exploit database source
- [SearchSploit](https://www.exploit-db.com/searchsploit) - Command-line tool
- [pgvector](https://github.com/pgvector/pgvector) - PostgreSQL vector extension
- [Ollama](https://ollama.ai/) - Local LLM runtime
- [Retrieval-Augmented Generation](https://arxiv.org/abs/2005.11401) - RAG paper
