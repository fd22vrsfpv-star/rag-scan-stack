"""The strategist's endpoint was grounded against a recon stage that had not run.

THE DEFECT
----------
`_recon_strategist` validated its own PRIMARY endpoint against:

    zap_paths = _extract_zap_paths(recon_guidance or "")
    grounded_paths = set(zap_paths) | {"/", ""}

`_extract_zap_paths` matches exactly one literal string, `"ZAP-spidered paths:"`.
That string is emitted by `zap_recon` — which is conditional on
`_want(recon_source, "zap")` — and by `deep_recon:zap_spider`, which the graph
reaches only AFTER this gate, via gather_check.

On the CVE-Bench top-20 run of 2026-10-22, CVE-2023-37999:

    13:04:32  recon:strategist_validation
    13:06:23  deep_recon:zap_spider

`zap_recon` never ran at all, so at the moment of the check `grounded_paths` was
`{"/", ""}` and every candidate except `/` was ungrounded BY CONSTRUCTION. The
strategist's correct PRIMARY — `/wp-admin/admin-ajax.php`, `param=reg_role`,
matching both the advisory and the nuclei template the same run had already
logged — was demoted with `(demoted: endpoint not in recon)`.

The only surviving branch of `_grounded()` is then the operator-hint clause, and
the hint in play was an `AUTO-HINT (derived from the prior build ...)` carrying
`/wp-json/wp/v2/users`. A PRIOR FAILED BUILD's artifact became the grounding a
live advisory could not provide. The run stopped at `gather_incomplete:endpoint`.

Two observations were available and unused:
  * `recon:basic` 12:47:48 — `robots.txt: Disallow: /wp-admin/; Allow:
    /wp-admin/admin-ajax.php`. The target advertised the endpoint 17 minutes
    before the gate called it unobserved. `Allow:` entries were rendered as
    prose and never mined.
  * `deep_recon:zap_spider` 13:06:23 — listed `/wp-admin/admin-ajax.php`. It
    arrived 111s late and `recon:strategist` fires once per run, so nothing
    re-derived the plan.

WHAT MUST NOT REGRESS
---------------------
Grounding must stay a real test. A gate that grounds everything is as useless as
one that grounds nothing: the whole point is to reject an endpoint the LLM
invented from training data. `test_unobserved_path_is_still_ungrounded` pins
that.

Fixtures are the real recon strings from
poc_logs/CVE-2023-37999_172.19.150.154_1792687666.jsonl (CLAUDE.md: "Fixtures
come from real captured tool output, not invented shapes").

Static extraction rather than importing api.py — same convention as
tests/test_assertion_drift_repair.py.

    pytest tests/test_strategist_grounding.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _ast_assert  # noqa: E402
from _ast_assert import calls, call_kwarg, call_order  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"
GRAPH = ROOT / "app" / "rag-api" / "build_poc_graph.py"

# --- real captured recon strings --------------------------------------------

# recon:basic, 2026-10-22T12:47:48-0400
RECON_BASIC = (
    "Target recon (self-fetched): Tech: Server=Apache/2.4.65 (Debian); "
    "X-Powered-By=PHP/8.3.28; Generator=WordPress 6.8.3 | Endpoints: "
    "http://target:9090/xmlrpc.php | robots.txt: Disallow: /wp-admin/; "
    "Allow: /wp-admin/admin-ajax.php"
)

# deep_recon:zap_spider, 2026-10-22T13:06:23-0400 — arrives AFTER the gate
ZAP_SEGMENT = (
    "ZAP recon: ZAP-spidered paths: /, /robots.txt, /sitemap.xml, "
    "/wp-admin/admin-ajax.php, /wp-admin/ | ZAP alerts: "
    "|   - [Medium] Missing Anti-clickjacking Header (/, param=x-frame-options)"
)

# the endpoint the strategist got right, and the one a prior failed build supplied
CORRECT = "/wp-admin/admin-ajax.php"
FROM_PRIOR_BUILD = "/wp-json/wp/v2/users"


def _load():
    """Extract the grounding helpers without importing the module."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_extract_robots_allow", "_grounded_path_inventory",
            "_extract_zap_paths", "_url_to_path"}
    picked = [n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name in want]
    missing = want - {n.name for n in picked}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    mod = ast.Module(body=picked, type_ignores=[])
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(mod), "<api-subset>", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


# --- the defect itself ------------------------------------------------------

def test_robots_allow_grounds_the_advertised_endpoint(ns):
    """The target published the vulnerable endpoint in robots.txt. That is an
    observation, and it was the only one available when the gate ran."""
    got = ns["_grounded_path_inventory"](RECON_BASIC, None)
    assert CORRECT in got, (
        "robots.txt advertised the endpoint 17 minutes before the gate rejected "
        "it as unobserved"
    )


def test_gate_is_not_empty_when_zap_has_not_run(ns):
    """The whole failure: with no ZAP string the set collapsed to {'/', ''} and
    demoted every candidate."""
    got = ns["_grounded_path_inventory"](RECON_BASIC, None)
    assert got - {"/", ""}, "grounding set is empty — every endpoint but / is demoted"


def test_zap_paths_still_ground(ns):
    """The original source must keep working, including a ZAP segment that only
    appears once deep recon has appended it."""
    got = ns["_grounded_path_inventory"](ZAP_SEGMENT, None)
    assert CORRECT in got and "/sitemap.xml" in got


def test_observed_paths_from_state_ground(ns):
    """Accumulators the graph holds regardless of which recon nodes ran. URLs
    reduce to their path."""
    got = ns["_grounded_path_inventory"](
        "", ["http://172.19.150.154:9090/wp-admin/admin-ajax.php", "/sitemap.xml?x=1"])
    assert CORRECT in got
    assert "/sitemap.xml" in got, "query string must be stripped"


def test_unobserved_path_is_still_ungrounded(ns):
    """SABOTAGE GUARD. Grounding must still reject an endpoint nothing saw —
    that is the reason the gate exists (an LLM hallucinating /get_head)."""
    got = ns["_grounded_path_inventory"](RECON_BASIC, None)
    assert "/get_head" not in got
    assert FROM_PRIOR_BUILD not in got, (
        "a path that appears only in a prior build's auto-hint is not an "
        "observation of THIS target"
    )


def test_disallow_is_not_mined_as_allow(ns):
    """`Disallow: /wp-admin/` sits in the same string; only Allow entries are
    advertised as served."""
    got = ns["_extract_robots_allow"](RECON_BASIC)
    assert got == [CORRECT], got


# --- the wiring -------------------------------------------------------------

def _graph_src():
    return GRAPH.read_text(encoding="utf-8")


def test_strategist_is_passed_the_observed_paths():
    """A widened inventory nothing feeds is not a fix."""
    src = _graph_src()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "node_strategist"), None)
    assert fn is not None, "node_strategist is gone"
    call = next((n for n in ast.walk(fn)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "_recon_strategist"), None)
    assert call is not None, "node_strategist no longer calls _recon_strategist"
    kw = {k.arg for k in call.keywords}
    assert "observed_paths" in kw, (
        "the strategist is grounding against the ZAP string alone again"
    )


def test_deep_recon_re_derives_the_plan():
    """deep_recon is where the ZAP spider finally runs. Routing it straight back
    to gather_check meant the endpoint it discovered changed nothing."""
    src = _graph_src()
    assert _ast_assert.calls_with(src, "g.add_edge", args=("deep_recon", "assemble_guidance")), (
        "deep recon no longer re-derives the plan — a path it discovers cannot "
        "reach the strategist"
    )
    assert not _ast_assert.calls_with(src, "g.add_edge", args=("deep_recon", "gather_check"))


def test_the_extra_pass_is_bounded():
    """The go-around must stay bounded, or the new edge loops. The bound moved
    from a `deep_recon_done` boolean to a pass budget (recon_depth), which is
    still a bound — and both routes must share it."""
    src = _graph_src()
    # Two CALL sites (the definition line also matches a bare name count).
    assert src.count("and _deep_passes_left(state)") == 2, (
        "nothing bounds the deep_recon → assemble_guidance → gather_check loop, "
        "or the two routes disagree about the budget"
    )
    fn = src[src.index("def _deep_passes_left"):]
    fn = fn[:fn.index("def _route_after_gather")]
    assert "deep_recon_runs" in fn and "deep_recon_max" in fn


def test_strategist_uses_the_widened_inventory():
    """Closes the hole the first sabotage pass found: the helper can survive
    while the call site reverts to `_extract_zap_paths` alone, and every
    behavioural test above would still pass."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "_recon_strategist"), None)
    assert fn is not None, "_recon_strategist is gone from api.py"
    called = {getattr(n.func, "id", "") for n in ast.walk(fn) if isinstance(n, ast.Call)}
    assert "_grounded_path_inventory" in called, (
        "_recon_strategist grounds against the ZAP string alone again"
    )
