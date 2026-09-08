"""Every declared wordlist must exist in the image that uses it.

Run on demand:

    pytest tests/test_wordlists_exist.py -v

WHY THIS EXISTS
---------------
A wordlist alias that resolves to nothing is indistinguishable, from the
outside, from a scan that found nothing.

Measured: a full pipeline scan of demo.testfire.net ran wafw00f, katana,
playwright, nikto, nuclei and ZAP — then failed its content-discovery stage with

    gobuster: {'status': 'failed',
               'error': 'wordlist not found:
                         /opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'}

The image ships `DirBuster-2007_directory-list-2.3-medium.txt`. The operator's
`WORDLIST` in .env had the un-prefixed name and had been wrong since boot;
nothing checked it until gobuster ran, so it cost ten minutes of real traffic to
learn a config typo. docker-compose's own default was correct the whole time.

Two guards, deliberately different in kind:

* **Static** — the declared paths agree with each other and with the compose
  default. Runs anywhere, including CI with no containers.
* **Live** — the files are actually present in the running web-scanner. This is
  the one that would have caught it, and it SKIPS (not fails) when the container
  is absent, because "cannot check here" is not "broken".

Sabotage check: point WORDLISTS["big"] at a name the image lacks -> RED (live).
"""
import ast
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _container import ERR, container_exec       # noqa: E402

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")
COMPOSE = os.path.join(REPO, "docker-compose.yml")
CONTAINER = "web-scanner"


def _src(path=WEB_SCAN):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _wordlists() -> dict:
    for n in ast.walk(ast.parse(_src())):
        if isinstance(n, ast.Assign) and any(
                getattr(t, "id", "") == "WORDLISTS" for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError("WORDLISTS not found — this guard would pass vacuously")


def _compose_default() -> str:
    m = re.search(r"WORDLIST:\s*\$\{WORDLIST:-([^}]+)\}", _src(COMPOSE))
    if not m:
        pytest.skip("no WORDLIST default in docker-compose.yml")
    return m.group(1).strip()


# ── static ────────────────────────────────────────────────────────────────────

def test_aliases_are_well_formed():
    wl = _wordlists()
    assert len(wl) >= 5, "suspiciously few aliases — did the parse work?"
    for name, path in wl.items():
        assert path.startswith("/opt/seclists/"), (
            f"alias {name!r} points outside /opt/seclists ({path!r}); "
            "validate_wordlist would reject it as a custom path"
        )


def test_the_compose_default_is_one_the_image_actually_ships():
    """The compose default and the alias table must not disagree.

    They did not here — .env did — but a drift between these two is the same
    failure with a different origin, and nothing else compares them.
    """
    default = _compose_default()
    known = set(_wordlists().values())
    assert default in known, (
        f"docker-compose's WORDLIST default {default!r} is not any of the "
        f"declared aliases. If it is a deliberate extra path it must still exist "
        f"in the image; if it is a typo it fails only when gobuster runs.\n"
        f"declared: {sorted(known)}"
    )


# ── live ──────────────────────────────────────────────────────────────────────

def _container_ls(paths):
    """Return {path: exists} from inside the scanner, or None if unreachable.

    Uses the shared tests/_container.py helper rather than its own docker call:
    "unreachable" and "ran and failed" are different answers, and getting that
    distinction right in one place is what test_ci_baseline's DIRECT_EXEC ratchet
    exists to enforce. This guard originally rolled its own and the ratchet
    caught it.
    """
    script = "; ".join(f'test -f "{p}" && echo "OK {p}" || echo "NO {p}"'
                       for p in paths)
    out = container_exec(script, container=CONTAINER, runner=("sh", "-c"), timeout=60)
    if out is None:
        return None                     # container/daemon unreachable -> SKIP
    if out.startswith(ERR):
        return None                     # `sh -c` itself failed -> nothing to judge
    return {line[3:]: line.startswith("OK ")
            for line in out.splitlines() if line[:3] in ("OK ", "NO ")}


def test_every_declared_wordlist_is_present_in_the_image():
    wl = _wordlists()
    paths = sorted(set(wl.values()) | {_compose_default()})
    found = _container_ls(paths)
    if found is None:
        pytest.skip(f"{CONTAINER} not reachable — cannot check the image here")
    assert found, "the existence probe returned nothing"

    missing = {name: p for name, p in wl.items() if not found.get(p, False)}
    if not found.get(_compose_default(), False):
        missing["<compose default>"] = _compose_default()
    assert not missing, (
        "these wordlists are declared but absent from the image, so selecting "
        "one fails the gobuster stage AFTER the crawl has already run:\n  "
        + "\n  ".join(f"{k} -> {v}" for k, v in missing.items())
    )


def test_the_scanner_reports_missing_wordlists_at_boot():
    """Discovering this mid-scan is the actual defect; booting quiet repeats it."""
    src = _src()
    assert "def missing_wordlists(" in src, (
        "no boot-time wordlist check — a bad path is found only when gobuster runs"
    )
    assert "missing_wordlists()" in src.split("def missing_wordlists(", 1)[1], (
        "missing_wordlists() is defined but never called at startup"
    )


# ── a timeout must not throw the work away ────────────────────────────────────
#
# Fixing the wordlist path exposed the defect behind it. `big` is 1,273,832
# entries and the stage runs it with -x php,html,txt — roughly 5.1M requests. At
# the 600s default, through a SOCKS proxy, a timeout is not an edge case, it is
# the expected outcome:
#
#   subprocess.TimeoutExpired: Command '[gobuster, dir, -u, http://demo.testfire.net/,
#   -w .../DirBuster-2007_directory-list-2.3-big.txt, ...]' timed out after 600 seconds
#
# The exception propagated past the parse and past the DB write, so a run that
# had already discovered paths recorded exactly nothing — ten minutes of real
# traffic to the target, discarded. Same class as the ZAP progressive drain.


def _gobuster_body():
    src = _src()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.FunctionDef) and n.name == "gobuster_dir_with_paths":
            return ast.get_source_segment(src, n) or ""
    raise AssertionError("gobuster_dir_with_paths not found")


def test_a_gobuster_timeout_keeps_the_paths_already_found():
    body = _gobuster_body()
    assert "except subprocess.TimeoutExpired" in body, (
        "proc.wait's TimeoutExpired still propagates, so every path found "
        "before the deadline is discarded"
    )
    # The catch has to sit BEFORE the parse, or it saves nothing.
    assert body.index("except subprocess.TimeoutExpired") < body.index("# Save to database"), (
        "the timeout is caught after the DB write, which keeps nothing"
    )


def test_a_partial_gobuster_run_says_so():
    """A caller that reads a partial run as complete concludes 'nothing here'."""
    body = _gobuster_body()
    assert '"timed_out": timed_out' in body and '"complete": not timed_out' in body, (
        "the result does not distinguish a complete run from a truncated one"
    )


def test_a_killed_gobuster_is_not_judged_by_its_exit_code():
    """We kill it, so its return code is ours, not a real failure signal."""
    body = _gobuster_body()
    assert "if not timed_out and proc.returncode not in (0, 1)" in body, (
        "a process we killed on timeout is still checked for a clean exit code, "
        "so the partial-result path raises anyway"
    )
