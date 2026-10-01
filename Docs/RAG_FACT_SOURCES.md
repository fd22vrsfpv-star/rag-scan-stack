# RAG Fact Sources — Contract for Dynamic Data Embedding

Dynamic data (what the platform SAW on a target, what techniques WORKED, which
credentials were discovered) is treated as first-class RAG so retrieval can
answer "have we seen this before on a similar target?" via similarity, not
just exact SQL. This doc is the contract every new embedding source has to
follow.

## Why dynamic facts are first-class

Static knowledge (dispatch rules, methodology YAML, WSTG map) was already
embedded. Observations were not — they lived in `credential_findings`,
`vulns`, `web_findings`, `exploit_store` etc. and were only reachable by
exact SQL. So a build against a new WordPress host had to re-discover
everything we'd already learned about every other WordPress host. The
observed-fact / enum-fact / technique sources below close that gap.

**Flag**: all dynamic-fact embedding is gated on `RAG_OBSERVED_FACTS=1`
(default off — opt-in). When off, every loader is a no-op; when on, every
loader + recall path activates.

## The dedup contract: (source, ip, kind, value_hash)

Every row embedded by a loader in this family MUST carry metadata keys:

| Key | Shape | Purpose |
|---|---|---|
| `source` | str | one of `_RAG_FACT_SOURCES` (see registry below) |
| `ip` | str | target host, OR a pseudo-id (e.g. `azure/user@tenant` for identities, `parent-domain` for subdomain patterns) |
| `kind` | str | sub-type within the source (e.g. `framework`, `admin_path`, `port_443_https`) |
| `value_hash` | str | `sha256(f"{ip}|{kind}|{value}")[:16]` — stable short dedup key |
| `value` | str | the fact itself (truncated to 1000 chars at the loader) |
| `engagement_id` | str/None | engagement scoping for purge |
| `product` | str/None | product family for cross-target recall |
| `observed_at` | ISO 8601 | timestamp for age-based purge |

Writes use the pattern: `DELETE ... WHERE (source, ip, kind, value_hash) match`,
then `INSERT`. Re-embedding the same fact collapses to one row; drifted
facts (same kind, different value) coexist until the operator purges.

**Why this shape**: `(source, ip, kind, value_hash)` is granular enough that
cross-target recall still works via similarity, but dedup catches the common
"we re-ran response_mine and the same framework came back" case.

## Source registry

Defined as module-level constants in `app/rag-api/api.py`; registered in
`_RAG_FACT_SOURCES` so the purge helper covers them automatically.

| Constant | Value | Loader | What it embeds |
|---|---|---|---|
| `RAG_OBSERVED_FACTS_SOURCE` | `observed_target_fact` | `_load_observed_fact_into_rag` (primitive) | base loader all others call |
| `RAG_ENUM_FACT_SOURCE` | `enum_fact_for_exploit` | `_embed_enum_facts_for_target` | ports/web/cred rows for one host |
| `RAG_CREDENTIAL_SOURCE` | `credential_identity` | `_load_credential_into_rag` | one credential_findings row (REDACTED) |
| `RAG_IDENTITY_SOURCE` | `directory_identity` | `_load_identity_into_rag` | one identities row (Azure/AD/etc.) |
| `RAG_VERIFIED_TECHNIQUE_SOURCE` | `verified_exploit_technique` | `_load_verified_technique_into_rag` | one verified exploit_store row |
| `RAG_VULN_FINDING_SOURCE` | `vuln_finding` | `_load_vuln_finding_into_rag` | one vulns row |
| `RAG_SERVICE_FINGERPRINT_SOURCE` | `service_fingerprint` | `_load_service_fingerprint_into_rag` | one ports row (service+banner+version) |
| `RAG_DISCOVERED_ENDPOINT_SOURCE` | `discovered_endpoint` | `_load_discovered_endpoint_into_rag` | one URL/path on one target |
| `RAG_WEB_FINDING_SOURCE` | `web_finding` | `_load_web_finding_into_rag` | one web_findings row |
| `RAG_API_SCHEMA_SOURCE` | `api_schema` | `_load_api_schema_into_rag` | GraphQL/OpenAPI/WSDL discovery |
| `RAG_INFO_DISCLOSURE_SOURCE` | `info_disclosure` | `_load_info_disclosure_into_rag` | accessible .env/.git/README/wp-config |
| `RAG_FAILED_TECHNIQUE_SOURCE` | `failed_technique` | `_load_failed_technique_into_rag` | unverified exploit_store row (negative signal) |
| `RAG_SUBDOMAIN_PATTERN_SOURCE` | `subdomain_pattern` | `_load_subdomain_pattern_into_rag` | recon_findings subdomains |
| `RAG_SESSION_SCHEME_SOURCE` | `session_scheme` | `_load_session_scheme_into_rag` | cookie-name observations |
| `RAG_SHELL_ACCESS_SOURCE` | `shell_access` | `_load_shell_access_into_rag` | shell/session holds |

## Adding a new source

1. **Define the constant**: `RAG_<X>_SOURCE = "<snake_name>"` at module level
2. **Register**: add to `_RAG_FACT_SOURCES` tuple so purge covers it
3. **Write the loader**:
   ```python
   def _load_<x>_into_rag(row_or_data, engagement_id=None, ...):
       if not observed_facts_enabled() or not row_or_data:
           return False
       try:
           ip = ...               # or pseudo-id
           v  = f"...concise summary of the fact..."[:1000]
           kind = "...sub-type..."
           return _load_observed_fact_into_rag(
               RAG_<X>_SOURCE, ip, kind, v,
               engagement_id=engagement_id, product=...)
       except Exception as e:
           logging.debug("<x>->rag load failed: %s", e)
           return False
   ```
4. **Add to compose helper** (`_compose_recall_context` in api.py): a new
   section with a clear header and `  * ` bullet lines. Order by signal
   strength (verified > observed > negative).
5. **Add a backfill function** if there's an existing SQL table to read from
   (`_backfill_<x>_to_rag`), and wire it into `/rag/backfill/{source}`.
6. **Live-embed** on the write path (e.g. `_save_exploit_store` calls
   `_load_verified_technique_into_rag` on verified rows).
7. **Add a test** in `tests/test_rag_observed_facts.py` — one load + recall +
   purge round-trip is enough.

## Non-negotiable: NO PLAINTEXT SECRETS in rag_documents

If a loader could touch tokens / passwords / API keys / private keys, the
loader MUST redact them before embed. Enforced by
`tests/test_rag_redaction_contract.py` which AST-walks every
`_load_*_into_rag` function and fails CI if any passes a sensitive-named
local as `value`.

The pattern (as in `_load_credential_into_rag`): embed a `<known>` or
`<invalid>` marker, keep the plaintext in its origin table
(`credential_findings.recovered_secret`), and let the LLM asks for the
real secret via SQL when it actually needs to use one.

## Cleanup

Three complementary mechanisms:

1. **Scoped manual purge**: `DELETE /rag/observed-facts?ip=X&source=Y&older_than_days=N`
   — all filters optional, idempotent.
2. **Programmatic purge**: `purge_observed_facts(older_than_days, engagement_id, ip, source)`.
3. **Nightly auto-purge daemon**: a background thread in rag-api runs
   `purge_observed_facts(older_than_days=RAG_PURGE_AGE_DAYS)` every
   `RAG_PURGE_INTERVAL_SEC` seconds (defaults: 90 days, 24h). Opt-out
   via `RAG_PURGE_DISABLE=1`.

## Retrieval

- Per-source helpers: `_recall_observed_facts(ip, product)`, `_recall_credentials(ip, product, service, username)`.
- Composed context: `_compose_recall_context(ip, product, limit)` returns ONE
  ordered block of every enabled source for the given target. This is what
  `_synthesize_cve_poc` prepends to synth guidance when the flag is on.

## Why NOT first-class (Tier 4 — explicitly excluded)

For reference, these are intentionally kept in SQL and NEVER embedded:

- Raw scan artifacts (nmap XML, ZAP reports, burp exports) — multi-MB blobs
- Full HTTP response bodies — huge, low signal-density
- Per-request timing / retry logs — operational, not knowledge
- Ephemeral pipeline state (poc trace JSONL) — accessible via trace endpoint
- Individual scan-recommendation rows — high volume, low per-row signal

The AGGREGATED insights from these sources (via extractors / parsers / the
loaders above) ARE embedded. Just not the raw.
