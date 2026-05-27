"""
Vault-import agent — convert recon_findings (cloud secret exposures) into
credential_vault rows. Replaces the dead-end "Navigate to Credentials tab
and add each secret" suggestion in cloud_scan_recommendations.

Approach:
  1. Caller specifies `source` (e.g. 'microburst') and a finding-type filter
     (defaults to azure_secret_exposure / cloud_secret).
  2. We pull the matching recon_findings and ask an LLM to extract structured
     credentials out of each row's `data.row` jsonb. Different MicroBurst
     modules have different column conventions (KeyVault vs StorageAccount
     vs AppServiceCreds vs Get-AzPasswords); LLM normalizes them all.
  3. A deterministic fallback handles the common columns when the LLM is
     unreachable or the response is malformed.
  4. Two-phase API: dry_run=True returns a preview list the operator
     confirms in the UI; dry_run=False does the actual insert.
  5. Idempotent via the credential_vault.source_entity_id pointing back to
     recon_findings.id — re-running won't create duplicates (unique index).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Optional

import requests
from psycopg2.extras import RealDictCursor, Json

log = logging.getLogger("vault_import_agent")
log.setLevel(logging.INFO)

OLLAMA_BASE = (
    os.environ.get("OLLAMA_BASE_URL")
    or os.environ.get("OLLAMA_URL")
    or "http://host.docker.internal:11434"
).rstrip("/")

# Default model — overridable via Settings → LLM Tuning → Agent Models.
DEFAULT_MODEL = os.environ.get(
    "VAULT_IMPORT_MODEL",
    os.environ.get("OLLAMA_MODEL",
                   os.environ.get("LLM_MODEL", "gemma4:31b")),
)
LLM_TIMEOUT_S = int(os.environ.get("VAULT_IMPORT_TIMEOUT_S", "120"))

# credential_vault.credential_type allowed values (from the CHECK constraint)
ALLOWED_CRED_TYPES = {
    "password", "ntlm_hash", "krb_tgs", "krb_tgt",
    "ssh_key", "api_token", "certificate", "other",
}


def _resolve_model(override: Optional[str] = None) -> str:
    """Pick a model. Honors override → DB-backed agent setting → env defaults."""
    if override:
        return override.strip()
    try:
        from api import get_agent_model
        v = (get_agent_model("vault_import_agent") or "").strip()
        if v:
            return v
    except Exception:
        pass
    return DEFAULT_MODEL


def _deterministic_extract(row: dict) -> list[dict]:
    """Best-effort extraction without LLM. Covers the most common MicroBurst /
    CloudFox / Pacu column conventions. Returns one or zero credential dicts."""
    if not isinstance(row, dict):
        return []

    def _gv(*keys: str):
        for k in keys:
            v = row.get(k)
            if v not in (None, ""):
                return v
            for rk in row:
                if rk.lower() == k.lower() and row[rk] not in (None, ""):
                    return row[rk]
        return None

    # Try KeyVault secret shape: VaultName, Name, Type=Secret, Value
    if _gv("VaultName") or _gv("Vault"):
        username = _gv("Name", "SecretName") or "unknown_secret"
        domain = _gv("VaultName", "Vault")
        value = _gv("Value", "SecretValue")
        return [{
            "username": str(username),
            "domain": str(domain) if domain else None,
            "credential_type": "api_token",
            "credential_value": str(value) if value else None,
            "notes": f"KeyVault secret {domain}/{username}",
        }]

    # Storage Account key shape
    if _gv("StorageAccount", "AccountName") and _gv("Key", "KeyValue"):
        return [{
            "username": str(_gv("StorageAccount", "AccountName")),
            "credential_type": "api_token",
            "credential_value": str(_gv("Key", "KeyValue")),
            "notes": "Azure Storage account key",
        }]

    # AppService publishing creds
    if _gv("AppService", "SiteName") and (_gv("PublishingPassword") or _gv("Password")):
        return [{
            "username": str(_gv("UserName", "PublishingUserName") or _gv("AppService", "SiteName")),
            "domain": str(_gv("AppService", "SiteName")),
            "credential_type": "password",
            "credential_value": str(_gv("PublishingPassword", "Password")),
            "notes": "AppService publishing credential",
        }]

    # Generic Get-AzPasswords-style row (Username + Value/Secret/Password)
    user = _gv("Username", "UserName", "User", "Account")
    val = _gv("Value", "Secret", "Password", "Token", "Key")
    if user and val:
        return [{
            "username": str(user),
            "credential_type": "password",
            "credential_value": str(val),
            "notes": "Generic credential (deterministic mapper)",
        }]

    return []


_LLM_PROMPT_TEMPLATE = """You are extracting credentials from a security tool's output row.

Input is a JSON object representing one row from a CSV (typically MicroBurst,
CloudFox, or similar cloud enumeration tools dumping a secret).

Return STRICT JSON ONLY (no prose, no markdown fences) shaped exactly like:
{{
  "credentials": [
    {{
      "username":         "<key/secret name or account>",
      "domain":           "<optional — e.g. KeyVault name, app service site, account>",
      "credential_type":  "password|api_token|ssh_key|certificate|ntlm_hash|other",
      "credential_value": "<the actual secret value if present, else null>",
      "notes":            "<short description of what this secret unlocks>"
    }}
  ]
}}

Rules:
- credential_type MUST be one of: password, api_token, ssh_key, certificate, ntlm_hash, other.
- Return an empty list if the row clearly contains no credential.
- A secret VALUE is not always present. Set credential_value to null if so.
- Multi-credential rows (rare) → return multiple entries.
- Never invent fields. Only extract what's literally in the row.

Row:
{row_json}

Return the JSON now.
"""


def _call_llm(prompt: str, model: str) -> tuple[str, dict]:
    t0 = time.time()
    resp = requests.post(
        f"{OLLAMA_BASE}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False,
              "options": {"temperature": 0.1, "num_predict": 1024}},
        timeout=LLM_TIMEOUT_S, verify=False,
    )
    latency_ms = int((time.time() - t0) * 1000)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", ""), {
        "model": model, "latency_ms": latency_ms,
        "prompt_tokens": data.get("prompt_eval_count", 0),
        "completion_tokens": data.get("eval_count", 0),
    }


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    raw = fence.group(1) if fence else text
    try:
        return json.loads(raw)
    except Exception:
        pass
    start = raw.find("{")
    if start < 0:
        return None
    depth = 0
    for i, ch in enumerate(raw[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[start:i + 1])
                except Exception:
                    return None
    return None


def _llm_extract(row: dict, model: str) -> list[dict]:
    """LLM-driven extraction. Returns [] on any failure (caller falls back)."""
    try:
        raw, _meta = _call_llm(
            _LLM_PROMPT_TEMPLATE.format(row_json=json.dumps(row, default=str)[:4000]),
            model,
        )
        parsed = _extract_json(raw) or {}
        creds = parsed.get("credentials") or []
        if not isinstance(creds, list):
            return []
        # Sanity-check each entry against the schema
        clean: list[dict] = []
        for c in creds:
            if not isinstance(c, dict):
                continue
            ctype = (c.get("credential_type") or "other").lower()
            if ctype not in ALLOWED_CRED_TYPES:
                ctype = "other"
            user = c.get("username")
            if not user:
                continue
            clean.append({
                "username": str(user)[:255],
                "domain": (str(c.get("domain"))[:255] if c.get("domain") else None),
                "credential_type": ctype,
                "credential_value": (str(c.get("credential_value"))[:4096]
                                     if c.get("credential_value") not in (None, "null", "") else None),
                "notes": (str(c.get("notes"))[:1000] if c.get("notes") else None),
            })
        return clean
    except Exception as e:
        log.warning("vault_import LLM extract failed: %s", e)
        return []


def import_secrets_from_recon(cur,
                              engagement_id: Optional[str] = None,
                              source: str = "microburst",
                              finding_types: Optional[list[str]] = None,
                              dry_run: bool = True,
                              limit: int = 200,
                              model: Optional[str] = None) -> dict:
    """Pull cloud-secret recon_findings → propose / insert credential_vault rows.

    `dry_run=True` → return a preview list (no DB writes besides the LLM-cache
    side effects, none here). `dry_run=False` → actually INSERT, idempotently
    via source_entity_id = recon_finding.id (skip if already present)."""
    finding_types = finding_types or [
        "azure_secret_exposure",          # microburst
        "cloud_secret_exposure",          # generic
        "cloudfox_secret",                # cloudfox naming
    ]

    # Pull candidate findings
    where = ["source = %s", "finding_type = ANY(%s)"]
    args: list[Any] = [source, finding_types]
    if engagement_id:
        where.append("engagement_id = %s::uuid")
        args.append(engagement_id)
    args.append(limit)

    cur.execute(f"""
        SELECT id::text AS id, source, finding_type, target, severity,
               data, engagement_id::text AS engagement_id, asset_id::text AS asset_id
        FROM recon_findings
        WHERE {" AND ".join(where)}
        ORDER BY created_at DESC
        LIMIT %s
    """, args)
    findings = cur.fetchall()

    # Already-imported lookup so dry-run shows accurate "skip" counts
    cur.execute("""
        SELECT source_entity_id::text AS sid
        FROM credential_vault
        WHERE source = %s AND source_entity_id IS NOT NULL
    """, (source,))
    already = {r["sid"] for r in cur.fetchall()}

    chosen_model = _resolve_model(model)
    proposals: list[dict] = []
    skipped_existing = 0

    for f in findings:
        if f["id"] in already:
            skipped_existing += 1
            continue
        row_data = (f["data"] or {}).get("row") or {}
        # LLM first (handles weird shapes); deterministic fallback if LLM misses.
        creds = _llm_extract(row_data, chosen_model) if row_data else []
        if not creds:
            creds = _deterministic_extract(row_data)
        for c in creds:
            proposals.append({
                **c,
                "source": source,
                "source_entity_id": f["id"],
                "engagement_id": f.get("engagement_id"),
                "_finding_target": f.get("target"),
                "_finding_type": f.get("finding_type"),
                "_finding_severity": f.get("severity"),
            })

    if dry_run:
        return {
            "dry_run": True,
            "candidates_examined": len(findings),
            "skipped_already_imported": skipped_existing,
            "proposals": proposals[:200],   # cap preview size
            "proposal_count": len(proposals),
            "model": chosen_model,
        }

    # Commit phase
    inserted = 0
    errors: list[str] = []
    for p in proposals:
        try:
            cur.execute("SAVEPOINT cred_sp")
            cur.execute("""
                INSERT INTO credential_vault
                    (engagement_id, username, domain, credential_type,
                     credential_value, source, source_entity_id, status, notes)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s::uuid, 'active', %s)
                ON CONFLICT DO NOTHING
                RETURNING id
            """, (
                p.get("engagement_id"), p["username"], p.get("domain"),
                p["credential_type"], p.get("credential_value"),
                p["source"], p["source_entity_id"], p.get("notes"),
            ))
            if cur.fetchone():
                inserted += 1
            cur.execute("RELEASE SAVEPOINT cred_sp")
        except Exception as e:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT cred_sp")
            except Exception:
                pass
            if len(errors) < 10:
                errors.append(f"{type(e).__name__}: {e}")

    return {
        "dry_run": False,
        "candidates_examined": len(findings),
        "skipped_already_imported": skipped_existing,
        "imported": inserted,
        "proposed": len(proposals),
        "errors": errors,
        "model": chosen_model,
    }
