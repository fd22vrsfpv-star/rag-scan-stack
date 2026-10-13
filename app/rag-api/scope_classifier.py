"""Scope auto-classification: deterministic rules + embedding similarity."""

import json
import logging
import os
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

SCOPE_RULES_DIR = os.environ.get("SCOPE_RULES_DIR", "/knowledge/scope_rules")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")


@dataclass
class ScopeSuggestion:
    scope: str
    confidence: float
    reasoning: str
    method: str  # 'rule' | 'similarity'
    rule_id: Optional[str] = None
    similar_decision_ids: Optional[list] = None


class ScopeClassifier:
    def __init__(self):
        self._yaml_rules: list[dict] = []
        self._loaded = False

    def load_rules(self, cur=None):
        """Load rules from YAML files + DB."""
        self._yaml_rules = []

        # Load YAML rules
        rules_dir = Path(SCOPE_RULES_DIR)
        if rules_dir.exists():
            for f in sorted(rules_dir.glob("**/*.yaml")) + sorted(rules_dir.glob("**/*.yml")):
                try:
                    with open(f) as fh:
                        docs = yaml.safe_load(fh)
                        if isinstance(docs, list):
                            self._yaml_rules.extend(docs)
                        elif isinstance(docs, dict):
                            self._yaml_rules.append(docs)
                except Exception as e:
                    logger.warning(f"Failed to load scope rule {f}: {e}")

        # Load DB rules
        db_rules = []
        if cur:
            try:
                cur.execute("SELECT id, name, scope_name, priority, rule_type, conditions, auto_apply FROM scope_classification_rules WHERE enabled = true ORDER BY priority")
                for row in cur.fetchall():
                    db_rules.append({
                        "id": str(row["id"]),
                        "name": row["name"],
                        "scope_name": row["scope_name"],
                        "priority": row["priority"],
                        "rule_type": row["rule_type"],
                        "conditions": row["conditions"],
                        "auto_apply": row["auto_apply"],
                        "source": "db",
                    })
            except Exception as e:
                logger.warning(f"Failed to load DB scope rules: {e}")

        # Merge: DB rules override YAML rules with same id
        db_ids = {r["id"] for r in db_rules}
        merged = db_rules + [r for r in self._yaml_rules if r.get("id") not in db_ids]
        self._yaml_rules = sorted(merged, key=lambda r: r.get("priority", 100))
        self._loaded = True
        return len(self._yaml_rules)

    def get_rules(self) -> list[dict]:
        return self._yaml_rules

    def classify_target(self, target: str, context: dict, cur=None) -> Optional[ScopeSuggestion]:
        """Classify a target using rules then similarity. Returns best suggestion or None."""
        if not self._loaded:
            self.load_rules(cur)

        # 1. Deterministic rules
        result = self._check_rules(target, context)
        if result and result.confidence >= 0.9:
            return result

        # 2. Similarity search
        if cur:
            sim_result = self._check_similarity(target, context, cur)
            if sim_result and sim_result.confidence >= 0.6:
                # If both rule and similarity agree, boost confidence
                if result and result.scope == sim_result.scope:
                    sim_result.confidence = min(0.98, sim_result.confidence + 0.1)
                    sim_result.reasoning += f" (also matched rule: {result.reasoning})"
                return sim_result

        return result  # may be low-confidence rule match or None

    def classify_rules_only(self, target: str, context: Optional[dict] = None) -> Optional[ScopeSuggestion]:
        """Rule-only classification — no embedder, no DB round-trip per host.

        This is the fast path for bulk work (classifying thousands of discovered
        hosts at ingest). `classify_target` adds embedding-similarity, which costs
        one embedder call per host and is wrong to run 5,000 times in a loop.
        """
        if not self._loaded:
            self.load_rules()
        return self._check_rules(target, context or {})

    def _check_rules(self, target: str, context: dict) -> Optional[ScopeSuggestion]:
        """Evaluate deterministic rules against target + context."""
        for rule in self._yaml_rules:
            if not rule.get("enabled", True):
                continue
            try:
                if self._evaluate_rule(rule, target, context):
                    return ScopeSuggestion(
                        scope=rule["scope_name"],
                        confidence=0.95,
                        reasoning=f"Rule '{rule['name']}': {rule['rule_type']} match",
                        method="rule",
                        rule_id=rule.get("id"),
                    )
            except Exception as e:
                logger.warning(f"Rule evaluation error for {rule.get('id')}: {e}")
        return None

    def _evaluate_rule(self, rule: dict, target: str, context: dict) -> bool:
        """Evaluate a single rule's conditions."""
        rt = rule["rule_type"]
        cond = rule.get("conditions", {})

        if rt == "domain_pattern":
            pattern = cond.get("pattern", "")
            return fnmatch(target.lower(), pattern.lower())

        elif rt == "whois_org":
            return _str_match(context.get("whois_org", ""), cond)

        elif rt == "asn":
            field = cond.get("field", "asn_name")
            return _str_match(context.get(field, ""), cond)

        elif rt == "tls_issuer":
            return _str_match(context.get("tls_issuer", ""), cond)

        elif rt == "ip_cidr":
            try:
                return ip_address(target) in ip_network(cond.get("cidr", "0.0.0.0/32"), strict=False)
            except (ValueError, TypeError):
                return False

        elif rt == "asset_state":
            # What we OBSERVED about the host, rather than what its name looks
            # like: did it resolve, and is anything listening.
            #
            # `probed` is the load-bearing condition. "No open ports" is
            # ambiguous on its own — a host with no asset row has never been
            # looked at, and a host we scanned and found nothing on is a
            # different animal. Filing the first as "no services" buries it
            # before anyone has checked, so the default REQUIRES evidence that
            # we looked, and a rule has to ask for the other behaviour on
            # purpose.
            #
            # Conditions (all optional, ANDed):
            #   unresolved:      true  -> ip is 0.0.0.0 / ::  / absent
            #   max_open_ports:  N     -> at most N listening ports
            #   probed:          true  -> an asset row exists (default true)
            #   port_scanned:    true  -> the host HAS port rows, i.e. something
            #                             actually looked at its ports
            #
            # port_scanned is the difference between "we scanned it and nothing
            # was listening" and "nobody has looked". Measured here: 16 resolved
            # assets have port rows with none open, and 1562 have no port rows
            # at all. Filing the second group as "no services" would bury 1562
            # hosts that might be serving anything, and they would never be
            # scanned again to find out.
            if cond.get("probed", True) and not context.get("has_asset"):
                return False
            if cond.get("port_scanned") and not context.get("port_scanned"):
                return False
            if cond.get("unresolved") and not context.get("unresolved"):
                return False
            mx = cond.get("max_open_ports")
            if mx is not None:
                try:
                    if int(context.get("open_ports") or 0) > int(mx):
                        return False
                except (TypeError, ValueError):
                    return False
            # An all-empty condition set must not match everything.
            return any(k in cond for k in ("unresolved", "max_open_ports",
                                           "probed", "port_scanned"))

        elif rt == "composite":
            op = cond.get("op", "and").lower()
            sub_conditions = cond.get("conditions", [])
            results = []
            for sub in sub_conditions:
                sub_rule = {"rule_type": sub.get("rule_type", "domain_pattern"), "conditions": sub}
                results.append(self._evaluate_rule(sub_rule, target, context))
            if op == "or":
                return any(results)
            return all(results)

        return False

    def _check_similarity(self, target: str, context: dict, cur) -> Optional[ScopeSuggestion]:
        """Find similar past scope decisions using pgvector embedding similarity."""
        import requests as _req

        # Build context text and embed
        parts = [f"target={target}"]
        for key in ("whois_org", "asn_name", "tls_issuer", "http_title", "http_server"):
            val = context.get(key)
            if val:
                parts.append(f"{key}={val}")
        tech = context.get("http_tech")
        if tech and isinstance(tech, list):
            parts.append(f"tech={','.join(str(t) for t in tech[:10])}")
        ctx_text = " ".join(parts)

        try:
            # app/embedder's contract is {"texts": [...]} -> {"embeddings": [[...]]}.
            # This used to send {"text": ...} and read ["embedding"], so the
            # request was a 422 and the response key never existed — the except
            # swallowed it and returned None every single time. That is why
            # scope_decisions accumulated 1151 rows with 0 embeddings while
            # looking like a working classifier.
            resp = _req.post(f"{EMBEDDER_URL}/embed", json={"texts": [ctx_text]},
                             timeout=10)
            if resp.status_code != 200:
                logger.warning("embedder returned HTTP %s for scope embedding: %s",
                            resp.status_code, resp.text[:200])
                return None
            vectors = resp.json().get("embeddings") or []
            embedding = vectors[0] if vectors else None
            if not embedding:
                logger.warning("embedder returned no vector for scope embedding")
                return None
        except Exception as e:
            # Logged, not silent: a permanently unreachable embedder previously
            # looked identical to "nothing similar found".
            logger.warning("scope embedding failed via %s: %s: %s",
                           EMBEDDER_URL, type(e).__name__, e)
            return None

        # Search for similar decisions
        try:
            cur.execute("""
                SELECT id, to_scope, target, context_text,
                       1 - (embedding <=> %s::vector) as similarity
                FROM scope_decisions
                WHERE embedding IS NOT NULL
                ORDER BY embedding <=> %s::vector
                LIMIT 5
            """, (str(embedding), str(embedding)))
            results = cur.fetchall()
        except Exception as e:
            logger.warning(f"Similarity search failed: {e}")
            return None

        if not results:
            return None

        # Check if top results agree on scope
        top = results[0]
        top_sim = float(top["similarity"])
        if top_sim < 0.6:
            return None

        # Count how many of top 5 agree with the top result's scope
        top_scope = top["to_scope"]
        agreeing = [r for r in results if r["to_scope"] == top_scope and float(r["similarity"]) >= 0.6]

        if len(agreeing) >= 2 or (len(agreeing) == 1 and top_sim >= 0.85):
            avg_sim = sum(float(r["similarity"]) for r in agreeing) / len(agreeing)
            examples = [r["target"] for r in agreeing[:3]]
            return ScopeSuggestion(
                scope=top_scope,
                confidence=round(min(0.95, avg_sim), 2),
                reasoning=f"Similar to {len(agreeing)} past decisions → {top_scope} (e.g., {', '.join(examples)})",
                method="similarity",
                similar_decision_ids=[str(r["id"]) for r in agreeing],
            )

        return None


def _str_match(value: str, cond: dict) -> bool:
    """Match a string value against a condition {op, value}."""
    if not value:
        return False
    op = cond.get("op", "contains").lower()
    cmp = cond.get("value", "")
    if not cmp:
        return False
    value_lower = value.lower()
    cmp_lower = cmp.lower()
    if op == "contains":
        return cmp_lower in value_lower
    elif op == "equals":
        return value_lower == cmp_lower
    elif op == "startswith":
        return value_lower.startswith(cmp_lower)
    elif op == "endswith":
        return value_lower.endswith(cmp_lower)
    elif op == "regex":
        return bool(re.search(cmp, value, re.IGNORECASE))
    return False


_classifier_instance: Optional[ScopeClassifier] = None


def get_classifier() -> ScopeClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = ScopeClassifier()
    return _classifier_instance


# ── Self-learning: turn seed scope + accepted decisions into reusable rules ──
#
# The point of these helpers is that a classification made ONCE — by a human
# seeding scope, or by the LLM/similarity path judging one host — becomes a
# deterministic `scope_classification_rules` row. Every later host that fits the
# same pattern is then a rule hit (fnmatch, no model), so the expensive path is
# never walked twice for the same shape. This is the "make a tool you can reuse
# without going back to the LLM" requirement, made concrete.

# A small set of multi-label public suffixes so `foo.co.uk` distils to
# `example.co.uk`, not `co.uk`. Not exhaustive — the common ones a pentest hits.
_MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "co.in", "co.kr",
}


def registrable_domain(host: str) -> Optional[str]:
    """Best-effort registrable domain (eTLD+1). Returns None for IPs/blanks."""
    if not host:
        return None
    h = host.strip().lower().rstrip(".")
    if not h or "/" in h:
        return None
    try:
        ip_address(h)
        return None  # an IP has no registrable domain
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) < 2:
        return None
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def target_type_of(host: str) -> str:
    """Classify a bare target as ip / cidr / domain — matches scope_targets CHECK."""
    t = (host or "").strip().lower()
    if "/" in t and any(c.isdigit() for c in t.split("/")[-1]):
        return "cidr"
    try:
        ip_address(t)
        return "ip"
    except ValueError:
        return "domain"


def generate_seed_rules(cur, engagement_id: str) -> int:
    """Create auto_apply domain_pattern rules from an engagement's manual seeds.

    Every operator-entered domain seed (examplecorp.com, legacycorp.net, …) becomes a
    `*.{domain}` rule mapped to that seed's scope name, so newly discovered
    subdomains classify deterministically. Idempotent: a rule with the same
    (name, scope_name, pattern) is not recreated.
    """
    cur.execute(
        """SELECT DISTINCT name, target FROM scope_targets
            WHERE engagement_id = %s::uuid AND target_type = 'domain'
              AND target <> '' AND COALESCE(source, '') NOT LIKE 'auto-%%'""",
        (engagement_id,),
    )
    seeds = cur.fetchall()
    created = 0
    for row in seeds:
        scope_name = row["name"] if isinstance(row, dict) else row[0]
        dom = (row["target"] if isinstance(row, dict) else row[1]).strip().lower().rstrip(".")
        if not dom:
            continue
        pattern = f"*.{dom}"
        rule_name = f"auto:{pattern}->{scope_name}"
        cur.execute(
            """SELECT 1 FROM scope_classification_rules
                WHERE name = %s AND scope_name = %s AND rule_type = 'domain_pattern'
                  AND conditions->>'pattern' = %s""",
            (rule_name, scope_name, pattern),
        )
        if cur.fetchone():
            continue
        cur.execute(
            """INSERT INTO scope_classification_rules
                 (id, name, scope_name, priority, enabled, rule_type, conditions,
                  auto_apply, engagement_id)
               VALUES (gen_random_uuid(), %s, %s, 50, true, 'domain_pattern',
                       %s::jsonb, true, %s::uuid)""",
            (rule_name, scope_name, json.dumps({"pattern": pattern, "seed": dom}),
             engagement_id),
        )
        created += 1
    return created


# Recon tools whose findings' `target` column is a hostname worth scoping.
_HOST_SOURCES = ("subfinder", "dnsx", "httpx", "amass", "assetfinder", "tlsx",
                 "gowitness", "whatweb", "dns-enum")


def classify_and_assign_engagement(cur, engagement_id: str,
                                   unknown_scope: str = "unknown_scope",
                                   limit: Optional[int] = None) -> dict:
    """Assign every discovered host to a scope UNDER this engagement.

    In-scope (a rule matches) → that rule's scope name, source 'auto-classified'.
    No match → `unknown_scope`, source 'auto-discovery'. Both carry
    engagement_id, which is the whole point: engagement-less scope rows are
    invisible to the Recon Agent, so classifying without stamping the engagement
    left everything unscannable. In-scope hosts also get their asset stamped so
    findings show under the engagement.
    """
    clf = get_classifier()
    clf.load_rules(cur)

    lim = f"LIMIT {int(limit)}" if limit else ""
    cur.execute(
        f"""SELECT t AS target FROM (
              SELECT DISTINCT target t FROM recon_findings
                WHERE source = ANY(%s) AND target IS NOT NULL AND target <> ''
              UNION
              SELECT DISTINCT hostname t FROM assets
                WHERE hostname IS NOT NULL AND hostname <> ''
            ) x
            WHERE t NOT IN (SELECT target FROM scope_targets
                             WHERE engagement_id = %s::uuid)
            {lim}""",
        (list(_HOST_SOURCES), engagement_id),
    )
    hosts = [r["target"] if isinstance(r, dict) else r[0] for r in cur.fetchall()]

    # Observed state per host, fetched ONCE for the whole batch. Without this
    # every rule saw an empty context, so a rule could only ever match on the
    # NAME — there was no way to express "this host resolved to nothing and has
    # nothing listening". Two queries beat 909 round trips.
    state: dict = {}
    if hosts:
        cur.execute(
            # Ports follow the IP, not the hostname — masscan reports an IP, so
            # its findings land on an IP-keyed asset row with a NULL hostname
            # and the hostname's own row reads as dead. The sentinel IPs are
            # excluded from the self-join or every unresolved host would
            # inherit every other unresolved host's ports, since they all share
            # 0.0.0.0.
            """SELECT a.hostname,
                      bool_or(host(a.ip) IN ('0.0.0.0', '::')) AS unresolved,
                      count(p.id) FILTER (WHERE p.is_open)     AS open_ports,
                      count(p.id)                              AS port_rows
                 FROM assets a
                 LEFT JOIN assets a2
                        ON a2.ip = a.ip
                       AND host(a.ip) NOT IN ('0.0.0.0', '::')
                 LEFT JOIN ports p ON p.asset_id = a2.id
                WHERE a.hostname = ANY(%s)
                GROUP BY a.hostname""",
            (hosts,),
        )
        for r in cur.fetchall():
            hn = r["hostname"] if isinstance(r, dict) else r[0]
            unres = r["unresolved"] if isinstance(r, dict) else r[1]
            opn = r["open_ports"] if isinstance(r, dict) else r[2]
            prows = r["port_rows"] if isinstance(r, dict) else r[3]
            state[hn] = {"has_asset": True, "unresolved": bool(unres),
                         "open_ports": int(opn or 0),
                         "port_scanned": int(prows or 0) > 0}

        # Port rows prove a scan only when the scan FOUND something. masscan
        # reports open ports only, so a host that answered nothing produces no
        # asset and no port row and is indistinguishable from one nobody ever
        # scanned. scope_coverage records the scan itself, which is what makes
        # an empty result usable evidence.
        cur.execute(
            """SELECT target FROM scope_coverage
                WHERE engagement_id = %s::uuid AND status = 'completed'
                  AND stage_name = 'discovery' AND target = ANY(%s)""",
            (engagement_id, hosts),
        )
        for r in cur.fetchall():
            tgt = r["target"] if isinstance(r, dict) else r[0]
            st = state.setdefault(tgt, {"has_asset": False, "unresolved": False,
                                        "open_ports": 0})
            st["port_scanned"] = True

    in_scope = unknown = 0
    per_scope: dict = {}
    for h in hosts:
        # A host with no asset row has never been probed — has_asset False, and
        # the asset_state rule refuses it unless a rule opts in explicitly.
        sug = clf.classify_rules_only(
            h, state.get(h, {"has_asset": False, "unresolved": False, "open_ports": 0}))
        if sug and sug.confidence >= 0.9:
            scope, src = sug.scope, "auto-classified"
            in_scope += 1
            per_scope[scope] = per_scope.get(scope, 0) + 1
        else:
            scope, src = unknown_scope, "auto-discovery"
            unknown += 1
        cur.execute(
            """INSERT INTO scope_targets (id, engagement_id, name, target,
                                          target_type, source)
               VALUES (gen_random_uuid(), %s::uuid, %s, %s, %s, %s)
               ON CONFLICT (engagement_id, name, target) DO NOTHING""",
            (engagement_id, scope, h, target_type_of(h), src),
        )

    # Findings-by-engagement: stamp assets for hosts we just put in a REAL scope
    # (not the unknown bucket). The Recon Agent reads scope_targets, but the
    # findings UI reads assets.engagement_id.
    cur.execute(
        """UPDATE assets a SET engagement_id = %s::uuid
            WHERE a.engagement_id IS NULL
              AND a.hostname IN (SELECT target FROM scope_targets
                                  WHERE engagement_id = %s::uuid AND name <> %s)""",
        (engagement_id, engagement_id, unknown_scope),
    )
    assets_stamped = cur.rowcount

    return {"candidates": len(hosts), "in_scope": in_scope, "unknown": unknown,
            "by_scope": per_scope, "assets_stamped": assets_stamped}


def distill_rule_from_decision(cur, target: str, scope: str,
                               engagement_id: Optional[str] = None,
                               method: str = "manual") -> Optional[str]:
    """Persist a reusable rule from a one-off classification (LLM/similarity/manual).

    A host judged in-scope by the model or a human implies its whole registrable
    domain is in scope, so we create a `*.{registrable}` auto_apply rule. The
    next host under that domain is then a deterministic rule hit — the model is
    never asked again for the same shape. Idempotent by (name, scope, pattern).
    Returns the pattern created, or None when nothing worth distilling (an IP,
    or a rule that already exists).
    """
    reg = registrable_domain(target)
    if not reg or not scope or scope == "unknown_scope":
        return None
    pattern = f"*.{reg}"
    rule_name = f"learned:{pattern}->{scope}"
    cur.execute(
        """SELECT 1 FROM scope_classification_rules
            WHERE name = %s AND scope_name = %s AND rule_type = 'domain_pattern'
              AND conditions->>'pattern' = %s""",
        (rule_name, scope, pattern),
    )
    if cur.fetchone():
        return None
    cur.execute(
        """INSERT INTO scope_classification_rules
             (id, name, scope_name, priority, enabled, rule_type, conditions,
              auto_apply, engagement_id)
           VALUES (gen_random_uuid(), %s, %s, 60, true, 'domain_pattern',
                   %s::jsonb, true, %s::uuid)""",
        (rule_name, scope, json.dumps({"pattern": pattern, "learned_from": target,
                                       "via": method}), engagement_id),
    )
    return pattern
