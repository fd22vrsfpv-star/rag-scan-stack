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
            resp = _req.post(f"{EMBEDDER_URL}/embed", json={"text": ctx_text}, timeout=5)
            if resp.status_code != 200:
                return None
            embedding = resp.json().get("embedding")
            if not embedding:
                return None
        except Exception:
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
