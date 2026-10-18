"""ATT&CK coverage: every Initial Access technique has a decision, and every
technique id used anywhere in knowledge/ is defined in the map.

Run standalone:  pytest tests/test_attack_coverage.py -q

WHY THIS EXISTS
---------------
On 2026-10-18 knowledge/ referenced 51 distinct ATT&CK ids and
knowledge/mitre/attack_map.yaml defined 19. The other 32 (mostly from
ad_attacks.yaml) had no name and no tactic, so app/rag-api/attack_vectors.py
gave them no tactic_position in the risk score. The existing guard only checked
vuln_classes.yaml.

Initial Access (TA0001) is what the PoC workbench answers for -- it builds the
first foothold -- so each of its techniques must be explicitly covered (naming
what tests it), out of scope (with a reason), or a listed gap.

The id list below is PINNED to ATT&CK Enterprise v20.0 (generated from MITRE's
enterprise-attack STIX bundle) so this runs without network access. When ATT&CK
is upgraded, regenerate it and decide every new id.
"""
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MAP = REPO / "knowledge" / "mitre" / "attack_map.yaml"

ATTACK_VERSION = "20.0"
INITIAL_ACCESS_V20 = {
    "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004", "T1091",
    "T1133", "T1189", "T1190", "T1195", "T1195.001", "T1195.002", "T1195.003",
    "T1199", "T1200", "T1566", "T1566.001", "T1566.002", "T1566.003",
    "T1566.004", "T1659", "T1669",
}
STATUSES = {"covered", "out_of_scope", "gap"}


def _map():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(MAP.read_text(encoding="utf-8"))


def test_every_initial_access_technique_has_a_decision():
    cov = {str(k) for k in (_map().get("initial_access_coverage") or {})}
    missing, extra = INITIAL_ACCESS_V20 - cov, cov - INITIAL_ACCESS_V20
    assert not missing, "Initial Access technique(s) with no decision: %s" % sorted(missing)
    assert not extra, ("decision(s) for ids that are not v%s Initial Access: %s"
                       % (ATTACK_VERSION, sorted(extra)))


def test_each_decision_is_well_formed_and_cites_something_real():
    for tid, d in (_map().get("initial_access_coverage") or {}).items():
        st = d.get("status")
        assert st in STATUSES, "%s: status %r" % (tid, st)
        if st == "covered":
            cites = d.get("covered_by") or []
            assert cites, "%s is 'covered' but names nothing that covers it" % tid
            for c in cites:
                f = REPO / "knowledge" / str(c).split("#", 1)[0]
                assert f.exists(), "%s cites %s, which does not exist" % (tid, c)
        else:
            assert (d.get("reason") or "").strip(), "%s is %s with no reason" % (tid, st)


def test_every_coverage_id_is_a_defined_technique():
    m = _map()
    defined = {str(k) for k in m["techniques"]}
    undefined = {str(k) for k in m.get("initial_access_coverage") or {}} - defined
    assert not undefined, "decided but not defined in techniques: %s" % sorted(undefined)


def _referenced_ids():
    """Every ATT&CK id in knowledge/ text files. Walks the tree directly -- no
    git dependency, so it runs (rather than errors) in a bare container."""
    out = {}
    for f in sorted((REPO / "knowledge").rglob("*")):
        if f.suffix not in (".yaml", ".yml", ".md", ".json") or not f.is_file():
            continue
        try:
            txt = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for t in set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", txt)):
            out.setdefault(t, set()).add(str(f.relative_to(REPO)))
    return out


def test_every_referenced_technique_is_defined_in_the_map():
    m = _map()
    defined = {str(k) for k in m["techniques"]} | {str(t) for t in m.get("retired_techniques") or []}
    missing = {t: sorted(fs) for t, fs in _referenced_ids().items() if t not in defined}
    assert not missing, (
        "technique id(s) used in knowledge/ but not defined in attack_map.yaml "
        "techniques (no name, no tactic, no risk weight): %s" % missing)


def test_every_rule_technique_is_defined():
    m = _map()
    defined = {str(k) for k in m["techniques"]}
    bad = [r.get("technique") for r in m.get("rules") or []
           if str(r.get("technique")) not in defined]
    assert not bad, "rule(s) map to undefined technique(s): %s" % bad


def test_every_defined_tactic_exists():
    m = _map()
    tactics = set(m.get("tactics") or {})
    bad = {k: v.get("tactic") for k, v in m["techniques"].items()
           if v.get("tactic") not in tactics}
    assert not bad, "technique(s) with a tactic the map does not define: %s" % bad


def test_retired_techniques_are_really_absent_and_still_referenced():
    """A retired id must not also be defined (pick one), and must still be
    referenced somewhere -- an unreferenced entry is stale and gets deleted."""
    m = _map()
    retired = {str(t) for t in m.get("retired_techniques") or []}
    assert not retired & {str(k) for k in m["techniques"]}, "retired AND defined"
    stale = retired - set(_referenced_ids())
    assert not stale, "retired_techniques no longer referenced (delete them): %s" % sorted(stale)
