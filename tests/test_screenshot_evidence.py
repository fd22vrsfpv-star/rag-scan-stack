"""Screenshot evidence must be the FINDING's, and the thumbnail must be an image.

Run standalone:  pytest tests/test_screenshot_evidence.py -q

Reported 2026-10-19, from a CVE-2024-4320 PoC finding on 172.19.18.3: the
"Screenshots (6)" panel showed six captures of 192.168.1.150, and each tile was
a wall of text rather than a page preview. Two unrelated causes.

1. WRONG EVIDENCE. `useScreenshots(undefined)` lists EVERY screenshot on the
   box (3087 of them). A finding with no hostname / ip / url -- an exploit-store
   PoC row is one -- fell through to that and rendered the first six, which
   belong to whichever host sorts first. Showing another host's evidence is
   worse than showing none: the operator cannot tell that it is wrong.

2. NOT AN IMAGE. nginx ranks a REGEX location above a plain prefix one, and
   `location /api/` is deliberately plain (the `^~` was removed so the bakeoff
   regex could be reached). So `location ~* \\.(png|...)$` captured every API
   path ending in an image extension and served it off the frontend disk:
       open() "/app/frontend/dist/api/screenshots/<dir>/<file>.png" failed
   The BFF returned the PNG fine on :8050 the whole time; the browser got a 404
   and rendered the <img> alt text, which was the long filename.

3. The status code under each tile comes from GoWitness's own JSONL
   (`response_code`), which is authoritative -- the same tool wrote the PNG and
   the record. A screenshot with no surviving record gets NO badge rather than a
   borrowed one.

Static (`ast` / text) -- no DB, no running stack, no browser.

    pytest tests/test_screenshot_evidence.py -q
"""
import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
NGINX = REPO / "dashboard" / "nginx.conf"
PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "FindingsExplorer.tsx"
THUMB = REPO / "dashboard" / "frontend" / "src" / "components" / "common" / "ScreenshotThumbnail.tsx"
RUNNER = REPO / "osint_runner" / "osint_runner.py"


def _read(p):
    if not p.exists():
        pytest.skip(f"{p.name} not present in this checkout")
    return p.read_text(encoding="utf-8")


# ── 1. nginx must not swallow /api/ paths ───────────────────────────────

@pytest.mark.unit
def test_static_regex_locations_exclude_api():
    """Both static-asset regexes must refuse /api/, or every API route serving
    a file with one of those extensions 404s off the frontend disk."""
    conf = _read(NGINX)
    regexes = re.findall(r"location\s+~\*\s+(\S+)\s*\{", conf)
    asset_regexes = [r for r in regexes if "png" in r or "js|css" in r or "jpg" in r]
    assert asset_regexes, "the static-asset regex locations are gone from nginx.conf"
    for r in asset_regexes:
        assert "(?!/api/)" in r, (
            f"{r} matches /api/ paths. nginx ranks a regex location above the "
            "plain `location /api/`, so this captures API responses — it is how "
            "every GoWitness screenshot 404'd through the dashboard")


@pytest.mark.unit
def test_api_location_is_still_a_plain_prefix():
    """The `^~` removal on /api/ is deliberate (the bakeoff regex needs to be
    reachable). If someone 'fixes' the above by restoring `^~`, that regex dies
    again — so pin the intent here rather than letting the two fight."""
    conf = _read(NGINX)
    assert re.search(r"location\s+/api/\s*\{", conf), "the /api/ location is gone"
    assert not re.search(r"location\s+\^~\s+/api/\s*\{", conf), (
        "/api/ became a ^~ prefix; that suppresses regex locations and kills "
        "the exploit-store bakeoff route")


# ── 2. a finding shows only ITS OWN host's screenshots ──────────────────

@pytest.mark.unit
def test_no_host_means_no_screenshots():
    """An empty search must not become 'list everything'."""
    page = _read(PAGE)
    m = re.search(r"const matchingScreenshots = (.*?)\n\n", page, re.S)
    assert m, "matchingScreenshots is gone from FindingsExplorer"
    block = m.group(1)
    assert "if (!screenshotSearch) return []" in block, (
        "with no hostname/ip/url the panel falls back to every screenshot on "
        "the box and shows another host's pages as this finding's evidence")


@pytest.mark.unit
def test_results_are_rechecked_against_the_host():
    """The server search is a substring match over GoWitness filenames; the
    client must re-check before calling the result evidence."""
    page = _read(PAGE)
    m = re.search(r"const matchingScreenshots = (.*?)\n\n", page, re.S)
    block = m.group(1)
    assert "filename" in block and "includes(" in block, (
        "results are used unfiltered — a loose server-side substring match can "
        "return another host")
    assert "replace(" in block, (
        "GoWitness dashes the host (`.` -> `-`), so a verbatim-only check "
        "misses the encoded form and hides real evidence")


@pytest.mark.unit
def test_url_parse_cannot_throw():
    """`new URL(...)` on a malformed finding.url used to take the whole panel
    down with it."""
    page = _read(PAGE)
    m = re.search(r"const screenshotSearch = (.*?)\n  const \{ data: screenshotsData", page, re.S)
    assert m, "screenshotSearch is gone"
    assert "try {" in m.group(1) and "catch" in m.group(1), (
        "new URL() is unguarded; a malformed url throws during render")


# ── 3. the tile is a preview with a status code under it ────────────────

@pytest.mark.unit
def test_thumbnail_renders_an_image_not_a_filename():
    thumb = _read(THUMB)
    assert re.search(r"<img\b", thumb), "the thumbnail no longer renders an image"
    assert 'alt=""' in thumb, (
        "a long filename in alt= is what rendered as a wall of text when the "
        "image 404'd; keep alt empty and put the label in its own row")


@pytest.mark.unit
def test_thumbnail_shows_the_status_code():
    thumb = _read(THUMB)
    assert "statusCode" in thumb, "the status code is not rendered under the preview"
    assert "statusTone" in thumb, "the status code is not distinguishable by class"
    # Unknown must render nothing rather than a fabricated code.
    assert "statusCode ?" in thumb, (
        "an unknown status must render nothing — a borrowed or defaulted code "
        "is a claim about a page nobody probed")


# ── 4. the status comes from GoWitness's own record ─────────────────────

@pytest.mark.unit
def test_runner_builds_the_status_index():
    src = _read(RUNNER)
    tree = ast.parse(src)
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert "_gowitness_status_index" in names, "the status index helper is gone"
    assert "_gowitness_name_variants" in names, "the filename matcher is gone"
    fn = [n for n in tree.body
          if isinstance(n, ast.FunctionDef) and n.name == "list_screenshots"]
    assert fn, "list_screenshots is gone"
    body = ast.get_source_segment(src, fn[0]) or ""
    assert "_gowitness_status_index" in body, (
        "the listing does not consult the index, so no tile can show a code")
    assert "status_code" in body, "rows carry no status_code"


@pytest.mark.unit
def test_name_variants_cover_the_measured_forms():
    """1227 files match the plain encoding, 1332 with the trailing slash
    stripped, 1374 with non-filename characters sanitised (of 1598). All three
    forms must be produced or coverage silently drops."""
    src = _read(RUNNER)
    tree = ast.parse(src)
    fn = [n for n in tree.body
          if isinstance(n, ast.FunctionDef) and n.name == "_gowitness_name_variants"]
    ns = {}
    exec(compile(ast.Module(body=fn, type_ignores=[]), str(RUNNER), "exec"), ns)
    out = ns["_gowitness_name_variants"]("http://10.0.0.1:9090/a b/")
    assert "http---10.0.0.1-9090-a b-.png" in out, "plain encoding missing"
    assert "http---10.0.0.1-9090-a b.png" in out, "trailing-slash form missing"
    assert any("a-b" in o for o in out), "sanitised form missing"
    assert len(out) == len(set(out)), "duplicate candidates waste every lookup"
