"""Recommendation dispatch must tolerate NULL columns in scan_recommendations.

`scan_recommendations` has nullable `action`, `script`, `template` and `banner`
columns — of 144 pending rows on a live engagement, 32 had a NULL action and 128
a NULL template. Rows reach the dispatcher as dicts straight from the driver, so
a NULL column arrives as a key that IS PRESENT with the value None.

That breaks the `dict.get(key, "")` idiom, whose default applies only when the
key is ABSENT. `rec.get("action", "")` returned None, and the next line called
`action.lower()`:

    AttributeError: 'NoneType' object has no attribute 'lower'

Every nmap recommendation with a NULL action failed that way. The failures were
reported as status="failed" with no traceback, and the recon agent counted a
failed result as neither dispatched nor skipped — so cycles logged
"dispatched=0" while the queue sat at 144 pending and never moved. The fetch is
ORDER BY priority, created_at, so the same broken rows came back first every
cycle and consumed the whole budget indefinitely.

The fix is `(rec.get(key) or "")`, which collapses both absent and NULL to "".
"""
import re
from pathlib import Path

import pytest

ASSETS = Path(__file__).parent.parent / "dashboard" / "bff" / "routers" / "assets.py"

# Columns that are nullable in scan_recommendations and are read off the rec dict
# during dispatch.
NULLABLE_REC_COLUMNS = ("action", "script", "template", "banner", "scanner",
                        "service", "ip")


@pytest.mark.unit
def test_dict_get_default_does_not_apply_to_a_present_none():
    """The exact Python semantic that caused the outage.

    Pinned as a test because the two expressions look interchangeable at a
    glance, which is why the bug survived review.
    """
    rec = {"action": None}                 # a NULL column, key present
    assert rec.get("action", "") is None   # default NOT applied
    assert (rec.get("action") or "") == ""  # the idiom that is safe

    with pytest.raises(AttributeError):
        rec.get("action", "").lower()

    assert (rec.get("action") or "").lower() == ""


@pytest.mark.unit
def test_dispatch_reads_no_nullable_column_with_a_get_default():
    """Static guard: the unsafe idiom must not come back for these columns.

    A behavioural test cannot reach `dispatch_rec` — it is defined inside the
    router function and closes over request-scoped state — so this asserts on
    the source instead. It is deliberately narrow: only the nullable columns
    above, only the `.get(col, "")` form.
    """
    src = ASSETS.read_text()
    pattern = re.compile(
        r'rec\.get\(\s*["\'](' + "|".join(NULLABLE_REC_COLUMNS) + r')["\']\s*,\s*["\']["\']\s*\)'
    )
    offenders = []
    for lineno, line in enumerate(src.splitlines(), start=1):
        m = pattern.search(line)
        if not m:
            continue
        # `x.get(col, "").split(...) if x.get(col) else ...` is guarded by its
        # own truthiness check, so the unsafe read can never execute.
        if re.search(r'if\s+rec\.get\(\s*["\']' + m.group(1) + r'["\']\s*\)', line):
            continue
        offenders.append(f"{ASSETS.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        "Unguarded rec.get(<nullable column>, \"\") found — returns None when the "
        "DB column is NULL. Use (rec.get(col) or \"\").\n" + "\n".join(offenders)
    )


@pytest.mark.unit
def test_nmap_script_skip_predicate_survives_a_null_action():
    """The specific expression that raised, reproduced over real row shapes.

    An nmap rec naming an NSE script but carrying no action is the single most
    common shape in the queue (15 of 20 nmap rows were script='banner',
    action=NULL). It must be classified as already-covered, not crash.
    """
    def is_already_covered(rec):
        script = rec.get("script") or ""
        action = rec.get("action") or ""
        return bool(script) and not any(
            kw in action.lower()
            for kw in ("port scan", "discovery", "full scan")
        )

    assert is_already_covered({"script": "banner", "action": None}) is True
    assert is_already_covered({"script": "smb-enum-shares"}) is True
    # A real port scan still dispatches rather than being skipped.
    assert is_already_covered(
        {"script": "nmap -p- {target}", "action": "Full scan of all ports"}
    ) is False
    # No script at all: nothing to skip, falls through to a normal dispatch.
    assert is_already_covered({"script": None, "action": None}) is False
