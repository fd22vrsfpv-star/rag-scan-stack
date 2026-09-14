"""Generic output-vs-findings reconciliation for scan ingestion.

Every `/ingest/*` endpoint in rag-api parses a tool's output and returns a stats
dict, then calls `_emit_ingest_event(tool, stats)`. This module turns those
heterogeneous stats into one honest answer: did any record the tool reported fail
to become a finding? If so it is surfaced (a `scan_count_mismatch` webhook + a
warning), instead of passing silently — the same class of bug that let a
credential check report 11 while storing 8.

WHY A NORMALIZER, not a raw count compare
-----------------------------------------
`raw output count > stored findings` is NORMAL: dedup and scope/false-positive
filtering legitimately drop rows. So the loss signal is NOT "fewer findings than
output lines" — it is the parser's OWN report of records it could not process:
`errors` (a count or a list) and non-dedup `skipped`. Dedup-style skips
(`skipped_duplicate`, `skipped_false_positive`, `out_of_scope`) are expected and
never counted as loss. `total`/`inserted` gaps are dedup, not loss.

Parser stat shapes this maps (all real, all different):
  nuclei : total, inserted, errors(int)
  nmap   : hosts, ports, services, vulns, errors(list)
  zap    : total_alerts, inserted, skipped_duplicate, skipped_false_positive,
           out_of_scope, errors(list)
  nessus : hosts, ports, vulns, skipped_zero_port, errors(list)
  brutus : records_seen, credentials_found, skipped, errors(int)
"""
from typing import Any, Dict, Optional

# Skip categories that are LEGITIMATE (dedup / scope / false-positive), never a
# loss. Anything else containing "skip" is a record the parser could not use.
_LEGIT_SKIP = ("duplicate", "false_positive", "false-positive", "dedup",
               "out_of_scope", "out-of-scope", "already", "existing")

_SEEN_KEYS = ("records_seen", "seen", "total", "total_alerts", "records")
_STORED_KEYS = ("inserted", "imported", "stored", "credentials_found",
                "created", "findings")


def _n(v: Any) -> int:
    """A count from an int, or the length of a list/tuple (parsers report
    `errors` both ways); anything else contributes nothing."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, (list, tuple)):
        return len(v)
    return 0


def normalize_ingest_stats(stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Fold a parser's stats into {seen, stored, dropped, deduped, drop_detail}.

    `dropped` is the loss signal (errors + non-dedup skips). `deduped` is the
    legitimate reduction. `seen`/`stored` are best-effort (nmap/nessus report
    neither — for them the only signal is `errors`)."""
    seen = stored = dropped = deduped = 0
    drop_detail: Dict[str, int] = {}
    for k, v in (stats or {}).items():
        kl = str(k).lower()
        n = _n(v)
        if kl in _SEEN_KEYS:
            seen = max(seen, n)
        elif kl in _STORED_KEYS:
            stored += n
        elif "error" in kl:
            if n:
                dropped += n
                drop_detail[k] = n
        elif any(s in kl for s in _LEGIT_SKIP):
            deduped += n
        elif "skip" in kl:
            if n:
                dropped += n
                drop_detail[k] = n
    return {"seen": seen, "stored": stored, "dropped": dropped,
            "deduped": deduped, "drop_detail": drop_detail}


def reconcile_ingest(source: str, stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Reconcile one ingest. Returns the normalized counts plus `matched` and,
    when it does not match, human-readable `reasons`.

    Mismatch when:
      * the parser dropped record(s) to errors / non-dedup skips, OR
      * the output clearly had records (seen > 0) but NONE were stored and NONE
        were deduped (a silent total-ingestion failure).
    """
    n = normalize_ingest_stats(stats)
    reasons = []
    if n["dropped"] > 0:
        bits = ", ".join(f"{k}={v}" for k, v in n["drop_detail"].items()) \
            or str(n["dropped"])
        reasons.append(f"{n['dropped']} record(s) not ingested ({bits})")
    if n["seen"] > 0 and n["stored"] == 0 and n["deduped"] == 0 and n["dropped"] == 0:
        reasons.append(f"output held {n['seen']} record(s) but none were stored")
    return {**n, "source": source, "matched": not reasons, "reasons": reasons}
