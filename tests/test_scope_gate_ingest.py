"""Ingest-time scope gating — the guard against recording third-party hosts.

A katana crawl of the target's TWiki app followed links off-host and recorded
findings for twiki.org, twitter.com, youtube.com, wikipedia and owasp.org. Scope
was enforced when choosing what to point a tool AT, and nothing checked what came
BACK, so the scanner both sent traffic to third parties and filed the results as
engagement findings.

These are pure unit tests — no database, no containers — so they can be run on
demand:  pytest tests/test_scope_gate_ingest.py
"""
import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from etl.scope_gate import host_in_scope, is_in_scope  # noqa: E402

SCOPE = [("192.168.1.150", "ip")]


# ------------------------------------------------------------ the predicate

@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "http://192.168.1.150/twiki/bin/view/Main/WebHome",
    "http://192.168.1.150:8180/manager/html",   # port must not change identity
    "192.168.1.150",                            # bare host form
])
def test_in_scope_values_are_kept(value):
    assert host_in_scope(value, True, SCOPE) is True


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "http://TWiki.org/cgi-bin/view",     # real case, note the casing
    "https://twitter.com/twiki",
    "https://www.owasp.org/index.php",
    "https://en.wikipedia.org/wiki/TWiki",
    "https://www.youtube.com/watch?v=x",
    "https://addons.mozilla.org/firefox",
    "https://web.archive.org/x",          # gau pulls from archives
    "https://samurai.inguardians.com/",
])
def test_third_party_hosts_are_dropped(value):
    assert host_in_scope(value, True, SCOPE) is False


@pytest.mark.unit
@pytest.mark.parametrize("value", ["http://www.php", "", None, "   "])
def test_malformed_and_empty_hosts_fail_closed(value):
    """`http://www.php` is a real host katana emitted. Anything we cannot
    resolve to an in-scope host must be refused, not admitted."""
    assert host_in_scope(value, True, SCOPE) is False


@pytest.mark.unit
def test_empty_scope_is_not_a_free_pass_for_the_predicate():
    """is_in_scope itself stays fail-closed even with no scope rows."""
    assert is_in_scope("192.168.1.150", []) is False


@pytest.mark.unit
def test_enforcement_off_passes_everything_through():
    """When NO scope is configured anywhere, parsers must not silently discard
    every finding — that is indistinguishable from a broken parser. The bounded
    escape hatch is `enforce=False`, never a permissive predicate."""
    assert host_in_scope("https://twitter.com/x", False, SCOPE) is True


@pytest.mark.unit
def test_subdomains_of_a_scoped_domain_are_in_scope():
    scope = [("example.com", "domain")]
    assert host_in_scope("https://api.example.com/v1", True, scope) is True
    assert host_in_scope("https://example.com.evil.net/", True, scope) is False


@pytest.mark.unit
def test_cidr_scope_matches_contained_ips():
    scope = [("192.168.1.0/24", "cidr")]
    assert host_in_scope("http://192.168.1.150/", True, scope) is True
    assert host_in_scope("http://10.0.0.5/", True, scope) is False


# --------------------------------------------------- wiring across parsers

GATED = [
    "parse_katana", "parse_gau", "parse_crtsh", "parse_amass", "parse_httpx",
    "parse_whatweb", "parse_wafw00f", "parse_ffuf", "parse_tlsx", "parse_zap",
    "parse_censys", "parse_netexec",
]

# Their target is an ARN, bucket, repo path, hash type or cloud resource id —
# NOT a host. Gating them on a host would make is_in_scope False for every row
# and silently delete all cloud findings.
NOT_HOST_BASED = [
    "parse_prowler", "parse_cloudfox", "parse_pacu", "parse_scoutsuite",
    "parse_azurehound", "parse_microburst", "parse_cloud_tenant",
    "parse_hashcat", "parse_trufflehog", "parse_greyhatwarfare", "parse_recon",
]


@pytest.mark.unit
@pytest.mark.parametrize("mod", GATED)
def test_host_based_parsers_call_the_gate(mod):
    src = (ROOT / "etl" / f"{mod}.py").read_text()
    assert "load_ingest_scope" in src, f"{mod} does not load ingest scope"
    assert "host_in_scope" in src, f"{mod} loads scope but never applies it"


@pytest.mark.unit
@pytest.mark.parametrize("mod", NOT_HOST_BASED)
def test_non_host_parsers_are_left_ungated(mod):
    """Guards the decision, not just the code: someone applying the gate here
    'for consistency' would delete every cloud/credential finding."""
    src = (ROOT / "etl" / f"{mod}.py").read_text()
    assert "host_in_scope" not in src, (
        f"{mod} keys on an ARN/bucket/repo/hash, not a host — a host scope gate "
        "would drop all of its findings"
    )


@pytest.mark.unit
@pytest.mark.parametrize("mod", GATED)
def test_scope_is_loaded_in_the_same_function_that_uses_it(mod):
    """Catches the parse_zap bug: the scope load landed in `_worker` while the
    gate ran in `parse_zap_alerts`, so it would have raised NameError on the
    first record. The file parsed cleanly and read correctly — only comparing
    the owning functions revealed it."""
    src = (ROOT / "etl" / f"{mod}.py").read_text()
    tree = ast.parse(src)

    def owner(line):
        best = None
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef) and n.lineno <= line <= (n.end_lineno or n.lineno):
                if best is None or n.lineno > best.lineno:
                    best = n
        return best.name if best else "(module)"

    lines = src.splitlines()
    loaders = {owner(i) for i, l in enumerate(lines, 1) if "load_ingest_scope(cur)" in l}
    users = [(i, owner(i)) for i, l in enumerate(lines, 1)
             if "host_in_scope(" in l and not l.strip().startswith("#") and "def " not in l]
    assert loaders, f"{mod}: no load_ingest_scope(cur) call found"
    for line, fn in users:
        assert fn in loaders, (
            f"{mod}:{line} uses host_in_scope inside {fn}(), but scope is only "
            f"loaded in {loaders} — this raises NameError at runtime"
        )


@pytest.mark.unit
@pytest.mark.parametrize("mod", GATED)
def test_gate_releases_its_savepoint_before_continuing(mod):
    """A `continue` that skips RELEASE SAVEPOINT leaves transaction state open.

    Only applies when a savepoint is actually OPEN at the gate. Deciding that
    from "the file mentions SAVEPOINT somewhere" is wrong and flagged two
    parsers that were fine — parse_katana releases its savepoint before the
    gate, and parse_zap opens one after it. So walk backwards from the gate to
    the most recent savepoint operation and only require a release when that
    operation actually opened one.
    """
    src = (ROOT / "etl" / f"{mod}.py").read_text()
    lines = src.splitlines()

    for i, line in enumerate(lines):
        if "host_in_scope(" not in line or line.strip().startswith("#"):
            continue
        # Truncate at the gate's OWN continue. A fixed-size window bled into
        # the next branch, which has its own RELEASE SAVEPOINT, so the check
        # passed on a neighbour's release and never actually fired.
        window = lines[i:i + 8]
        stop = next((k for k, l in enumerate(window) if l.strip() == "continue"), None)
        if stop is None:
            continue
        block = "\n".join(window[:stop + 1])

        open_sp = None
        for prev in reversed(lines[:i]):
            t = prev.strip()
            if "RELEASE SAVEPOINT" in t or "ROLLBACK TO SAVEPOINT" in t:
                open_sp = None
                break
            if "SAVEPOINT" in t and "cur.execute" in t:
                open_sp = t
                break
        if open_sp:
            assert "RELEASE SAVEPOINT" in block, (
                f"{mod}: a savepoint is open at the gate near line {i+1} "
                f"({open_sp}) but the gate continues without releasing it"
            )
