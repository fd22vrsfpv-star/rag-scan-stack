"""Directory-discovery enumeration followup: cewl-enriched docs/backup gobuster.

Run on demand:

    pytest tests/test_directory_followup.py -v

WHY THIS EXISTS
---------------
When the crawl discovers a directory (a listing, or the parent folder of a
crawled file such as `/my documents/JohnSmith/Bank Site Documents/`), a STANDARD
followup must run gobuster over it with a docs/backup wordlist enriched by
site-harvested (cewl) words, to surface leaked documents/backups a link-only
crawl walked past. The dispatch is TAGGED as a follow-up (scanner='dir_followup')
and auto-fires on the safe lane. cewl must be installed + allowlisted.

SABOTAGE PROOF
--------------
- Drop the extensions from _gobuster_command and test_gobuster_command fails.
- Change scanner from 'dir_followup' in queue_directory_followup and
  test_dispatch_is_tagged_followup fails.
- Remove the post_enumeration call and test_post_enum_invokes_followup fails.
- Remove cewl from the Dockerfile/allowlist and test_cewl_installed_and_allowlisted fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "etl", "directory_followup.py")
POSTENUM = os.path.join(REPO, "etl", "post_enumeration.py")
YAML = os.path.join(REPO, "knowledge", "directory_followups.yaml")
DOCKERFILE = os.path.join(REPO, "kali_listener", "Dockerfile")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
WORDLIST = os.path.join(REPO, "wordlists", "docs-backup.txt")


def _src(p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing")
    return open(p, encoding="utf-8").read()


def _import_mod():
    import sys
    sys.path.insert(0, os.path.join(REPO, "etl"))
    try:
        import directory_followup as m
    except Exception as e:  # pragma: no cover
        pytest.skip(f"directory_followup import unavailable: {e}")
    return m


def test_yaml_defines_the_followup():
    import yaml
    d = yaml.safe_load(_src(YAML))["directory_followup"]
    assert d.get("extensions"), "must define docs/backup extensions"
    assert any(x in d["extensions"] for x in ("pdf", "bak", "zip")), "doc/backup exts expected"
    srcs = d.get("wordlist_sources") or []
    kinds = {k for s in srcs if isinstance(s, dict) for k in s}
    assert {"repo_list", "site_corpus"} <= kinds, "must merge repo docs list + site corpus"
    assert any("cewl_live" in s for s in srcs if isinstance(s, dict)), "must allow live cewl enrichment"
    assert d.get("followup_tag") == "dir_followup"


def test_docs_backup_wordlist_ships():
    words = _src(WORDLIST).split()
    for w in ("backup", "documents", "passwords", "admin"):
        assert w in words, f"docs-backup.txt should include {w!r}"


def test_gobuster_command():
    m = _import_mod()
    cfg = {"extensions": ["pdf", "bak", "txt"], "gobuster": {"threads": 8, "status_codes_blacklist": "404"}}
    cmd = m._gobuster_command("http://x/my docs/", "/wordlists/w.txt", cfg)
    assert cmd.startswith("gobuster dir -u http://x/my docs/"), cmd
    assert "-w /wordlists/w.txt" in cmd
    assert "-x pdf,bak,txt" in cmd, "extensions must be passed to gobuster"
    # a dir_url without trailing slash gets one
    assert m._gobuster_command("http://x/d", "/w", cfg).count("http://x/d/") == 1


def test_dispatch_is_tagged_followup():
    """queue_directory_followup records scanner='dir_followup' with extra.followup."""
    src = _src(MOD)
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef) and n.name == "queue_directory_followup"), None)
    assert fn, "queue_directory_followup missing"
    body = ast.get_source_segment(src, fn)
    assert "scan_recommendations" in body and "'pending'" in body
    assert '"followup": True' in body, "the queued row must be tagged as a follow-up"
    assert "/tools/execute" in body, "auto-fire must dispatch to the safe lane"
    assert "check_dispatch" in body, "must scope-gate before dispatch (fail-closed)"


def test_merges_three_sources():
    src = _src(MOD)
    for fn_name in ("_repo_docs_backup_words", "_site_corpus_words", "_live_cewl_words"):
        assert f"def {fn_name}" in src, f"{fn_name} (a wordlist source) missing"
    build = next(n for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.FunctionDef) and n.name == "build_merged_wordlist")
    b = ast.get_source_segment(src, build)
    assert "_repo_docs_backup_words()" in b and "_site_corpus_words(" in b and "_live_cewl_words(" in b, \
        "build_merged_wordlist must merge all three sources"


def test_existence_check_wired():
    import yaml
    src = _src(MOD)
    assert "def _probe_directory_status" in src, "existence probe missing"
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "queue_directory_followup")
    body = ast.get_source_segment(src, fn)
    assert "_probe_directory_status" in body and "== 404" in body, \
        "queue_directory_followup must skip a directory that 404s"
    assert yaml.safe_load(_src(YAML))["directory_followup"].get("verify_exists") is True


def test_existence_check_skips_404(monkeypatch):
    m = _import_mod()
    monkeypatch.setattr(m, "_probe_directory_status", lambda *a, **k: 404)
    res = m.queue_directory_followup(None, "1.2.3.4", "http://x/phantom/", dispatch=False)
    assert res.get("skipped") is True and res.get("queued") == 0, res


def test_existing_directory_proceeds_past_check(monkeypatch):
    m = _import_mod()
    monkeypatch.setattr(m, "_probe_directory_status", lambda *a, **k: 200)
    # short-circuit right after the existence check so no DB/network is needed
    monkeypatch.setattr(m, "build_merged_wordlist", lambda *a, **k: None)
    res = m.queue_directory_followup(None, "1.2.3.4", "http://x/real/", dispatch=False)
    assert res.get("skipped") is not True, res
    assert res.get("reason") == "no wordlist words available", res  # got past the 404 check


def test_post_enum_invokes_followup():
    src = _src(POSTENUM)
    assert "_directory_enumeration_followups(" in src, "post_enumeration must run the followup"
    assert "def _directory_enumeration_followups" in src


def test_cewl_installed_and_allowlisted():
    df = _src(DOCKERFILE)
    assert re.search(r"^\s*cewl \\", df, re.M), "cewl must be apt-installed in the kali Dockerfile"
    ls = _src(LISTENER)
    assert '"cewl"' in ls, "cewl must be in the tool allowlist"
