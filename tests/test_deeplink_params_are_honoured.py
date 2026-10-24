"""A deep link must land on a tab that READS the parameter it carries.

The Exploits page folded its `store`, `build` and `research` tabs into one
unified Workbench. The links pointing at them were never updated, and because
the Workbench is also the DEFAULT tab, every one of them still "worked":
navigation happened, a page rendered, and nothing responded to the parameter.
Reported as "when I click on the 1 PoC in purple it doesn't do anything".

Six links were affected, all landing on the Workbench:

    AssetBrowser  "N to approve"   ?ip=            read only by PendingTab
    AssetBrowser  "spray"          ?ip=            read only by PendingTab
    AssetBrowser  "N PoC"          ?tab=store&ip=  tab folded; ip read by nobody
    AssetBrowser  "Open in /exploits"  ?open=      read by NOTHING, anywhere
    AssetBrowser  host drill-down  ?ip=            read only by PendingTab
    AttackMap     "Exploits"       ?ip=            read only by PendingTab

This is the UI version of a defect this codebase keeps finding in its backend:
a value is produced, handed somewhere, and never read — and because the happy
path still renders, nothing reports it. A dead query parameter is a 404 that
returns 200.

The guard reads TypeScript with a regex, which the repo already does elsewhere
(tests/test_severity_scale.py, tests/test_credential_secret_visibility.py), so
it needs no node toolchain.

Sabotage check: drop `tab=pending` from any pending-queue link and
`test_ip_links_target_a_tab_that_reads_ip` fails by file and line; reintroduce
`?open=` and `test_no_link_passes_a_parameter_nobody_reads` fails.

    pytest tests/test_deeplink_params_are_honoured.py -q
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "dashboard" / "frontend" / "src"
EXPLOIT_MANAGER = SRC / "pages" / "ExploitManager.tsx"

# Which component reads each param on the Exploits page, and which tab renders
# that component. A link carrying the param must select that tab.
PARAM_TAB = {"ip": ("pending", "workbench")}

# BOTH routes: /exploits and the chromeless /exploits-popout, which mounts the
# SAME ExploitManager and therefore reads the same params. A guard that knew
# only the first would have left every pop-out deep link unchecked — and the
# pop-out is where the PoC-build links now point.
# Matches the URL WHEREVER it is written, not only inline in `to=`/`href=`.
# The first version anchored on the attribute and silently missed every link
# built into a variable first (`const wbHref = \`/exploits-popout?...\``) or
# returned from a helper — which is how all the PoC-build links are written.
# An unseen link is an unchecked one, so the matcher must not depend on the
# shape of the call site.
LINK_RE = re.compile(r"""(/exploits(?:-popout)?\?[^`'"\s)}]*)""")


def _tsx_files():
    if not SRC.is_dir():
        pytest.skip("frontend sources not present")
    return sorted(SRC.rglob("*.tsx"))


def _exploit_links():
    """[(file, line, url)] for every deep link into /exploits."""
    out = []
    for f in _tsx_files():
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for m in LINK_RE.finditer(line):
                out.append((f.relative_to(REPO), i, m.group(1)))
    return out


def _params(url: str) -> dict:
    q = url.split("?", 1)[1] if "?" in url else ""
    out = {}
    for part in q.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v
    return out


def test_popout_links_are_covered_too():
    """The pop-out mounts the same component and reads the same params."""
    urls = [u for _, _, u in _exploit_links()]
    assert any(u.startswith("/exploits-popout?") for u in urls), (
        "no /exploits-popout deep link was found. Either they were removed, "
        "or the matcher stopped seeing them — and an unseen link is an "
        "unchecked one")


def test_there_are_links_to_check():
    """A guard that finds nothing is not a guard."""
    links = _exploit_links()
    assert len(links) >= 6, (
        f"only {len(links)} /exploits deep links found — the link syntax "
        "changed and this guard is inspecting almost nothing")


def test_the_manager_still_reads_the_params_we_assume():
    src = EXPLOIT_MANAGER.read_text(encoding="utf-8")
    assert "get('tab')" in src, "the Exploits page no longer honours ?tab="
    assert "get('ip')" in src, "the Exploits page no longer honours ?ip="


def test_ip_links_target_a_tab_that_reads_ip():
    """?ip= is read by PendingTab, ResultsTab and the Workbench — but NOT by
    whatever tab happens to be default. The link must say which."""
    bad = []
    for f, line, url in _exploit_links():
        p = _params(url)
        if "ip" not in p:
            continue
        tab = p.get("tab")
        if tab not in PARAM_TAB["ip"]:
            bad.append(f"{f}:{line} -> {url} (tab={tab!r})")
    assert not bad, (
        "these links carry ?ip= without selecting a tab that reads it, so "
        "they land on the default Workbench and the filter is silently "
        "dropped:\n  " + "\n  ".join(bad))


def test_no_link_targets_a_folded_tab():
    """`store`, `build` and `research` were folded into `workbench`."""
    folded = {"store", "build", "research"}
    bad = [f"{f}:{line} -> {url}" for f, line, url in _exploit_links()
           if _params(url).get("tab") in folded]
    assert not bad, (
        "these links target a tab that no longer exists; it silently "
        "redirects to the Workbench, which is also the default, so the click "
        "appears to do nothing:\n  " + "\n  ".join(bad))


def test_no_link_passes_a_parameter_nobody_reads():
    """A dead query parameter is a 404 that returns 200."""
    src = "".join(f.read_text(encoding="utf-8") for f in _tsx_files())
    read = set(re.findall(r"(?:params|urlParams|searchParams)\.get\('([a-z_]+)'\)", src))
    bad = []
    for f, line, url in _exploit_links():
        for k in _params(url):
            if k not in read:
                bad.append(f"{f}:{line} -> ?{k}= in {url}")
    assert not bad, (
        "these links pass a parameter that nothing in the frontend reads:\n  "
        + "\n  ".join(bad)
        + f"\nParameters actually read: {sorted(read)}")


def test_the_store_listing_honours_the_ip_it_is_sent():
    """The PoC badge's whole purpose is 'show me this host's PoCs'."""
    src = EXPLOIT_MANAGER.read_text(encoding="utf-8")
    i = src.find("const { data: storeRowsAll }")
    assert i > 0, (
        "the PoC Store listing no longer separates the fetched rows from the "
        "filtered ones, so ?ip= cannot be applied to it")
    # Not a fixed window: an unfiltered counts query now sits between the
    # fetch and the filter, and the point is that the filter EXISTS, not that
    # it is within N characters of the fetch.
    window = src[i:]
    assert "storeIp" in window and "target_host" in window, (
        "the PoC Store list does not filter by the ?ip= it was sent, so the "
        "'N PoC' badge opens an unfiltered list of every saved PoC — which is "
        "indistinguishable from the click doing nothing")
