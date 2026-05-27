"""
Cloud Scan Suggestor — YAML-rule-based recommendation engine.

Evaluates cloud findings in recon_findings + credential_vault and produces
actionable next-step recommendations for pentesters.
"""

import hashlib
import logging
import os
import re
from datetime import datetime, timezone

import yaml

log = logging.getLogger("cloud_suggestor")

CLOUD_SOURCES = {"prowler", "scoutsuite", "pacu", "cloudfox", "azurehound", "microburst"}
RULES_PATH = os.environ.get(
    "CLOUD_SCAN_RULES_PATH",
    "/knowledge/cloud_scan_rules.yaml",
)

_rules_cache: dict | None = None
_rules_mtime: float = 0.0


def load_rules(path: str | None = None) -> dict:
    """Load YAML rules, using mtime-based caching."""
    global _rules_cache, _rules_mtime
    path = path or RULES_PATH
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        log.warning("Cloud scan rules file not found: %s", path)
        return {"bootstrap_rules": [], "finding_rules": [], "credential_rules": []}

    if _rules_cache is not None and mtime == _rules_mtime:
        return _rules_cache

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    _rules_cache = data
    _rules_mtime = mtime
    log.info("Loaded cloud scan rules from %s", path)
    return data


def _fingerprint(rule_id: str, tool: str, trigger_id: str | None, action: str) -> str:
    """Stable dedup fingerprint for a recommendation."""
    raw = f"{rule_id}|{tool}|{trigger_id or ''}|{action}"
    return hashlib.md5(raw.encode()).hexdigest()


def _source_counts(cur) -> dict[str, int]:
    """Count findings per cloud source."""
    cur.execute("""
        SELECT source, count(*) as cnt
        FROM recon_findings
        WHERE source IN ('prowler','scoutsuite','pacu','cloudfox','azurehound','microburst')
        GROUP BY source
    """)
    return {row["source"]: row["cnt"] for row in cur.fetchall()}


def _detect_providers(cur) -> set[str]:
    """Detect which cloud providers appear in findings."""
    providers = set()
    cur.execute("""
        SELECT DISTINCT
            CASE
                WHEN data->>'provider' IS NOT NULL THEN lower(data->>'provider')
                WHEN data->>'cloud_provider' IS NOT NULL THEN lower(data->>'cloud_provider')
                WHEN target ILIKE '%%arn:aws%%' OR data::text ILIKE '%%aws%%' THEN 'aws'
                WHEN target ILIKE '%%azure%%' OR data::text ILIKE '%%azure%%' THEN 'azure'
                WHEN target ILIKE '%%gcp%%' OR data::text ILIKE '%%gcloud%%' THEN 'gcp'
                ELSE NULL
            END as provider
        FROM recon_findings
        WHERE source IN ('prowler','scoutsuite','pacu','cloudfox','azurehound','microburst')
        LIMIT 500
    """)
    for row in cur.fetchall():
        if row["provider"]:
            providers.add(row["provider"])
    return providers


def _safe_query_count(cur, sql: str, params=()) -> int:
    """Run a count query with savepoint protection."""
    try:
        cur.execute("SAVEPOINT _cloud_q")
        cur.execute(sql, params)
        result = cur.fetchone()["cnt"]
        cur.execute("RELEASE SAVEPOINT _cloud_q")
        return result
    except Exception:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT _cloud_q")
        except Exception:
            pass
        return 0


def _cloud_cred_count(cur) -> int:
    """Count active cloud credentials in vault."""
    return _safe_query_count(cur, """
        SELECT count(*) as cnt FROM credential_vault
        WHERE credential_type IN ('aws_key','aws_access_key','aws_sts',
                                  'azure_key','azure_oauth','azure_sp',
                                  'gcp_sa_key')
          AND status != 'revoked'
    """)


def _expiring_cred_count(cur) -> int:
    """Count credentials expiring within 30 minutes."""
    return _safe_query_count(cur, """
        SELECT count(*) as cnt FROM credential_vault
        WHERE expires_at IS NOT NULL
          AND expires_at < now() + interval '30 minutes'
          AND expires_at > now()
          AND status != 'revoked'
    """)


def evaluate_bootstrap(cur, rules: dict, source_counts: dict) -> list[dict]:
    """Evaluate bootstrap rules — suggest tools when sources are missing."""
    recs = []
    present_sources = set(source_counts.keys())
    has_cloud_creds = _cloud_cred_count(cur) > 0
    providers = _detect_providers(cur)

    for rule in rules.get("bootstrap_rules", []):
        rule_id = rule["id"]

        # no_cloud_data: only if zero cloud sources
        if rule_id == "no_cloud_data" and len(present_sources) > 0:
            continue

        # Rules with requires_sources: all must be present
        requires = set(rule.get("requires_sources", []))
        if requires and not requires.intersection(present_sources):
            continue

        # Rules with missing_sources: at least one must be missing
        missing = set(rule.get("missing_sources", []))
        if missing and not missing.difference(present_sources):
            continue

        # Provider filter
        if rule.get("requires_provider") and rule["requires_provider"] not in providers:
            continue

        # Credential requirement
        if rule.get("requires_cloud_creds") and not has_cloud_creds:
            continue

        provider = rule.get("provider", "any")
        for rec in rule.get("recommendations", []):
            recs.append({
                "rule_id": rule_id,
                "rule_name": rule.get("name", rule_id),
                "priority": rule.get("priority", "medium"),
                "tool": rec["tool"],
                "action": rec["action"],
                "command_hint": rec.get("command_hint"),
                "import_as": rec.get("import_as"),
                "trigger_source": None,
                "trigger_finding_id": None,
                "trigger_summary": rule.get("description"),
                "provider": provider,
                "account_id": None,
            })
    return recs


def evaluate_findings(cur, rules: dict) -> list[dict]:
    """Evaluate finding-triggered rules."""
    recs = []
    for rule in rules.get("finding_rules", []):
        rule_id = rule["id"]
        source = rule.get("source")
        pattern = rule.get("finding_type_pattern")

        if not source or not pattern:
            continue

        # Query matching findings
        cur.execute("""
            SELECT id, target, finding_type, severity, source,
                   data->>'provider' as provider,
                   data->>'account_id' as account_id,
                   substring(target || ' ' || coalesce(finding_type,'') for 200) as summary
            FROM recon_findings
            WHERE source = %s
            LIMIT 500
        """, (source,))

        regex = re.compile(pattern, re.IGNORECASE)
        for row in cur.fetchall():
            text = f"{row.get('finding_type', '')} {row.get('target', '')} {row.get('summary', '')}"
            if not regex.search(text):
                continue

            provider = row.get("provider") or rule.get("provider", "aws")
            account_id = row.get("account_id")
            trigger_id = str(row["id"]) if row.get("id") else None

            for rec in rule.get("recommendations", []):
                recs.append({
                    "rule_id": rule_id,
                    "rule_name": rule.get("name", rule_id),
                    "priority": rule.get("priority", "medium"),
                    "tool": rec["tool"],
                    "action": rec["action"],
                    "command_hint": rec.get("command_hint"),
                    "import_as": rec.get("import_as"),
                    "trigger_source": source,
                    "trigger_finding_id": trigger_id,
                    "trigger_summary": (row.get("finding_type") or row.get("target", ""))[:200],
                    "provider": provider,
                    "account_id": account_id,
                })
    return recs


def _safe_query_rows(cur, sql: str, params=()) -> list[dict]:
    """Run a query with savepoint protection, return rows or empty list."""
    try:
        cur.execute("SAVEPOINT _cred_q")
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.execute("RELEASE SAVEPOINT _cred_q")
        return rows
    except Exception as e:
        log.debug("Credential query failed (column may not exist): %s", e)
        try:
            cur.execute("ROLLBACK TO SAVEPOINT _cred_q")
        except Exception:
            pass
        return []


def evaluate_credentials(cur, rules: dict) -> list[dict]:
    """Evaluate credential-triggered rules."""
    recs = []
    for rule in rules.get("credential_rules", []):
        rule_id = rule["id"]
        cred_pattern = rule.get("credential_type_pattern")

        if rule_id == "credential_expiring_soon":
            expires_min = rule.get("expires_within_minutes", 30)
            rows = _safe_query_rows(cur, """
                SELECT id, username, credential_type, domain,
                       expires_at, source
                FROM credential_vault
                WHERE expires_at IS NOT NULL
                  AND expires_at < now() + interval '%s minutes'
                  AND expires_at > now()
                  AND status != 'revoked'
                LIMIT 50
            """, (expires_min,))
            for row in rows:
                if cred_pattern and not re.search(cred_pattern, row.get("credential_type", ""), re.I):
                    continue
                for rec in rule.get("recommendations", []):
                    recs.append({
                        "rule_id": rule_id,
                        "rule_name": rule.get("name", rule_id),
                        "priority": rule.get("priority", "critical"),
                        "tool": rec["tool"],
                        "action": rec["action"],
                        "command_hint": rec.get("command_hint"),
                        "import_as": rec.get("import_as"),
                        "trigger_source": "credential_vault",
                        "trigger_finding_id": str(row["id"]),
                        "trigger_summary": f"{row.get('credential_type', '')} for {row.get('username', 'unknown')} expires soon",
                        "provider": rule.get("provider", "any"),
                        "account_id": row.get("domain"),
                    })

        elif rule_id == "stale_key_suggest_rotation":
            stale_days = rule.get("stale_days", 90)
            rows = _safe_query_rows(cur, """
                SELECT id, username, credential_type, domain,
                       created_at, source
                FROM credential_vault
                WHERE created_at < now() - interval '%s days'
                  AND status != 'revoked'
                LIMIT 50
            """, (stale_days,))
            for row in rows:
                if cred_pattern and not re.search(cred_pattern, row.get("credential_type", ""), re.I):
                    continue
                for rec in rule.get("recommendations", []):
                    recs.append({
                        "rule_id": rule_id,
                        "rule_name": rule.get("name", rule_id),
                        "priority": rule.get("priority", "medium"),
                        "tool": rec["tool"],
                        "action": rec["action"],
                        "command_hint": rec.get("command_hint"),
                        "import_as": rec.get("import_as"),
                        "trigger_source": "credential_vault",
                        "trigger_finding_id": str(row["id"]),
                        "trigger_summary": f"{row.get('credential_type', '')} for {row.get('username', 'unknown')} is >{stale_days} days old",
                        "provider": rule.get("provider", "any"),
                        "account_id": row.get("domain"),
                    })
    return recs


def evaluate_all(cur) -> list[dict]:
    """Run all rule categories and return merged recommendations."""
    rules = load_rules()
    source_counts = _source_counts(cur)
    all_recs = []
    all_recs.extend(evaluate_bootstrap(cur, rules, source_counts))
    all_recs.extend(evaluate_findings(cur, rules))
    all_recs.extend(evaluate_credentials(cur, rules))
    return all_recs


def get_posture(cur) -> dict:
    """Cloud posture summary."""
    source_counts = _source_counts(cur)
    providers = _detect_providers(cur)

    total = sum(source_counts.values())
    cloud_creds = _cloud_cred_count(cur)
    expiring = _expiring_cred_count(cur)

    # Severity breakdown
    cur.execute("""
        SELECT severity, count(*) as cnt
        FROM recon_findings
        WHERE source IN ('prowler','scoutsuite','pacu','cloudfox','azurehound','microburst')
        GROUP BY severity
    """)
    by_severity = {row["severity"]: row["cnt"] for row in cur.fetchall()}

    # Open recommendations count
    open_recs = {}
    try:
        cur.execute("SAVEPOINT _cloud_recs")
        cur.execute("""
            SELECT priority, count(*) as cnt
            FROM cloud_scan_recommendations
            WHERE status = 'open'
            GROUP BY priority
        """)
        open_recs = {row["priority"]: row["cnt"] for row in cur.fetchall()}
        cur.execute("RELEASE SAVEPOINT _cloud_recs")
    except Exception:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT _cloud_recs")
        except Exception:
            pass

    return {
        "providers": sorted(providers),
        "sources_imported": source_counts,
        "total_cloud_findings": total,
        "by_severity": by_severity,
        "active_cloud_creds": cloud_creds,
        "expiring_creds": expiring,
        "open_recommendations": open_recs,
        "total_open_recommendations": sum(open_recs.values()),
    }


def refresh(cur) -> dict:
    """Re-evaluate all rules and insert new recommendations (dedup by fingerprint)."""
    recs = evaluate_all(cur)
    inserted = 0
    skipped = 0

    for rec in recs:
        fp = _fingerprint(rec["rule_id"], rec["tool"], rec.get("trigger_finding_id"), rec["action"])
        try:
            cur.execute("""
                INSERT INTO cloud_scan_recommendations
                    (rule_id, rule_name, priority, tool, action, command_hint,
                     import_as, trigger_source, trigger_finding_id, trigger_summary,
                     provider, account_id, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (fingerprint) DO NOTHING
            """, (
                rec["rule_id"], rec["rule_name"], rec["priority"], rec["tool"],
                rec["action"], rec.get("command_hint"), rec.get("import_as"),
                rec.get("trigger_source"),
                rec.get("trigger_finding_id"),
                rec.get("trigger_summary"),
                rec.get("provider"), rec.get("account_id"), fp,
            ))
            if cur.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            log.warning("Failed to insert recommendation: %s", e)
            skipped += 1

    return {"evaluated": len(recs), "inserted": inserted, "skipped": skipped}
