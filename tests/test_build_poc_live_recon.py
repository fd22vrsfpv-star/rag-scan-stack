"""2026-10-09: the build-poc gather check must consume the run's OWN recon.

Post-mortem of the focused-10 + other-30 CVE-Bench rounds: 20/33 runs halted at
the gather gate while their own recon segments held the answer — the login
form's fields (`Form GET process.php fields=['username', 'password']`), 40
Playwright-crawled URLs, Arjun's honored parameter names, the verb sweep.
`_gather_manifest` read only the OpenAPI line and the JSON-body endpoints line
out of `recon_text`; the input-field chain never read it at all.

Dynamic for the pure parser (`_parse_recon_segments`, real producer strings);
structural for the wiring into `_gather_manifest` / `node_gather_check`.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_live_recon.py -v'
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"

_CONSTS = ("_RECON_STATIC_EXT", "_RECON_DYNAMIC_EXT")


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names) -> dict:
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {}
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in _CONSTS for t in node.targets):
            exec(_ast.get_source_segment(src, node), ns)
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


@pytest.fixture(scope="module")
def parse():
    return _load(["_parse_recon_segments"])["_parse_recon_segments"]


# ── real producer strings (copied from /app/poc_logs traces, 2026-10-08/09) ──

FORM_37849 = ("Target recon (self-fetched): Tech: Server=Apache/2.4.68 (Debian); X-Powered-By=PHP/8.3.33 "
              "| Form GET process.php fields=['username', 'password']")

FORM_5314 = ("Target recon (self-fetched): Tech: Server=Apache/2.4.54 (Debian); X-Powered-By=PHP/7.4.33 "
             "| Form POST /index.php?mainmenu=home fields=['token', 'loginfunction', 'tz', 'username', 'password'] "
             "| robots.txt: Disallow: /")

PLAYWRIGHT_5084 = """Playwright SPA crawl discovered 40 URLs through ZAP's proxy (456 dynamic routes, 192 static). Dynamic routes are the real attack surface — the HTML spider never sees them because they fire via JS/XHR after page load:
  - /
  - /#wp--skip-link--target
  - http://172.18.0.11:9090
  - /%22+$src+%22
  - /*
  - /*/modules/*.gif
  - /*&back=
  - /*controller=address
  - /wp-login.php
  - /wp-admin/admin-ajax.php
  - /wp-content/themes/twentytwentyfour/style.css
  - /wp-json/wp/v2/users
  - http://172.18.0.11:9090/index.php?rest_route=/wp/v2/posts"""

PLAYWRIGHT_5314 = """Playwright SPA crawl discovered 40 URLs through ZAP's proxy (157 dynamic routes, 120 static). Dynamic routes are the real attack surface — the HTML spider never sees them because they fire via JS/XHR after page load:
  - /
  - /index.php?mainmenu=home
  - /support/helpcenter.png
  - /support/index.php
  - /theme/dolibarr_logo.png
  - /user/passwordforgotten.php
  - http://172.18.0.11:9090
  - /api
  - /core/js"""

ARJUN_DEEP_22120 = """Arjun deep-scan (params honored per endpoint):
  /: print, request
  /index.php: print, request
  /admin/dict.php: sortfield, sortorder"""

ARJUN_RECON_22120 = ("Arjun recon on http://172.18.0.40:8080/ (2 honored params — the app reacts differently "
                     "when these are set): print, request. Try these as injection points before guessing at param names.")

CLASSIFIED_4443 = """Arjun deep-scan (params honored per endpoint):
  /: attachment_id, cat, year
  /sitemap.xml: attachment, cat

CLASSIFIED HIGH-SIGNAL PARAMS (strongest suspects — try these FIRST):
  / param `attachment_id` → likely SQL injection. try `?attachment_id=1' OR 1=1-- -` or UNION-based on this param
  / param `cat` → likely SQL injection. try `?cat=1' OR 1=1-- -` or UNION-based on this param
  /sitemap.xml param `attachment` → likely File upload / XXE. try `POST` with multipart file field `attachment` (webshell) or XML with external entity"""

ZAP_2359 = ("ZAP recon: ZAP-spidered paths: /legacy/includes/jstz, /theme, /dtale/static/fonts, "
            "/includes/jstz/jstz.min.js, /legacy, /list_databases, /login, /dist/main.5b0dc093602d3118.js, "
            "/ical_server.php | ZAP alerts: |   - [Low] Server Leaks Version Information via \"Server\" HTTP "
            "Response Header Field (/dist/main.5b0dc093602d3118.js) evidence: Apache/2.4.65 (Debian)")

# No run has ever traced a verb sweep (deep_recon:<step> recorded only a count
# until 2026-10-09). Built from the producer format at _deep_recon_for_gaps
# ("VERB SWEEP (deep recon; method:status per path):\n  {tp} -> GET:200 POST:302").
VERB_SWEEP_SYNTHETIC = """VERB SWEEP (deep recon; method:status per path):
  /admin/dict.php -> GET:200 POST:302
  /api/items -> POST:401 PUT:405
  /dead -> DELETE:501"""

OPENAPI_4320 = ("Target recon (self-fetched): Tech: Server=uvicorn | OpenAPI paths (112 at /openapi.json): "
                "GET /get_generation_status; POST /lollms_tokenize; POST /install_extension; GET /docs")

JSONBODY_37388 = ("{\"message\": \"The request to /upload endpoint should be a POST request with a file parameter "
                  "named as 'file'.\", \"status\": \"ok\"} | Endpoints (from JSON body): /upload | Tech: Server=gunicorn")

HREFS = "Target recon (self-fetched): Tech: Server=Apache | Endpoints: login.php, search.php | robots.txt: none"


# ── parser: forms ───────────────────────────────────────────────────────────

def test_form_relative_action_is_rooted_and_fields_kept(parse):
    r = parse([FORM_37849])
    assert r["form_fields"] == [{"path": "/process.php", "method": "GET",
                                 "fields": ["username", "password"], "raw_action": "process.php"}]


def test_form_action_with_query_is_normalised_to_path(parse):
    r = parse([FORM_5314])
    f = r["form_fields"][0]
    assert f["path"] == "/index.php" and f["method"] == "POST"
    assert f["fields"] == ["token", "loginfunction", "tz", "username", "password"]
    assert f["raw_action"] == "/index.php?mainmenu=home"


def test_duplicate_forms_across_segments_are_collapsed(parse):
    r = parse([FORM_37849, FORM_37849])
    assert len(r["form_fields"]) == 1


# ── parser: crawl ───────────────────────────────────────────────────────────

def test_playwright_crawl_keeps_dynamic_paths_drops_junk_and_static(parse):
    r = parse([PLAYWRIGHT_5084])
    urls = r["crawl_urls"]
    assert "/wp-login.php" in urls and "/wp-admin/admin-ajax.php" in urls and "/wp-json/wp/v2/users" in urls
    # absolute URL on the same host → path(+query)
    assert "/index.php?rest_route=/wp/v2/posts" in urls
    # glob / template / fragment junk never becomes a probe target
    assert not any("*" in u or "%22" in u or "#" in u or "$" in u for u in urls)
    # the bare root and static assets are not candidates
    assert "/" not in urls and not any(u.endswith(".css") for u in urls)


def test_playwright_crawl_dolibarr(parse):
    r = parse([PLAYWRIGHT_5314])
    assert "/support/index.php" in r["crawl_urls"] and "/user/passwordforgotten.php" in r["crawl_urls"]
    assert not any(u.endswith(".png") for u in r["crawl_urls"])
    assert r["counts"]["crawl_urls"] == len(r["crawl_urls"])


# ── parser: arjun ───────────────────────────────────────────────────────────

def test_arjun_deep_scan_block_maps_path_to_param_names(parse):
    r = parse([ARJUN_DEEP_22120])
    assert r["arjun_params"] == {"/": ["print", "request"], "/index.php": ["print", "request"],
                                 "/admin/dict.php": ["sortfield", "sortorder"]}
    assert r["counts"]["arjun_params"] == 6 and r["counts"]["arjun_paths"] == 3


def test_arjun_single_url_form_is_parsed(parse):
    r = parse([ARJUN_RECON_22120])
    assert r["arjun_params"] == {"/": ["print", "request"]}


def test_classified_params_are_extracted_with_class_and_hint(parse):
    r = parse([CLASSIFIED_4443])
    cl = r["classified_params"]
    assert cl[0] == {"path": "/", "param": "attachment_id", "class": "SQL injection",
                     "hint": "`?attachment_id=1' OR 1=1-- -` or UNION-based on this param"}
    assert any(c["path"] == "/sitemap.xml" and c["param"] == "attachment" and "XXE" in c["class"] for c in cl)
    # the deep-scan block above the CLASSIFIED block is still parsed, and stops at it
    assert r["arjun_params"]["/"] == ["attachment_id", "cat", "year"]


# ── parser: zap / verb sweep / openapi / endpoints ──────────────────────────

def test_zap_spidered_paths_drop_static_and_stop_at_alerts(parse):
    r = parse([ZAP_2359])
    assert "/list_databases" in r["zap_paths"] and "/login" in r["zap_paths"] and "/ical_server.php" in r["zap_paths"]
    assert not any(p.endswith(".js") for p in r["zap_paths"])
    assert not any("alerts" in p.lower() or "[Low]" in p for p in r["zap_paths"])


def test_verb_sweep_statuses_are_ints_per_method(parse):
    r = parse([VERB_SWEEP_SYNTHETIC])
    assert r["verb_sweep"]["/admin/dict.php"] == {"GET": 200, "POST": 302}
    assert r["verb_sweep"]["/api/items"] == {"POST": 401, "PUT": 405}
    assert r["verb_sweep"]["/dead"] == {"DELETE": 501}


def test_openapi_and_endpoint_lines(parse):
    r = parse([OPENAPI_4320, JSONBODY_37388, HREFS])
    assert {"method": "POST", "path": "/install_extension"} in r["openapi"]
    assert r["json_body_endpoints"] == ["/upload"]
    assert r["href_endpoints"] == ["/login.php", "/search.php"]


def test_parser_is_total_on_garbage(parse):
    r = parse([None, "", 42, "Playwright SPA crawl discovered", "Arjun deep-scan (params honored per endpoint):"])
    assert r["form_fields"] == [] and r["crawl_urls"] == [] and r["arjun_params"] == {}


# ── wiring (structural, sabotage-provable) ──────────────────────────────────

def test_gather_manifest_takes_segments_and_consults_live_recon():
    src = _func_src("_gather_manifest")
    assert src, "_gather_manifest missing"
    assert "segments=None" in src.split(")", 1)[0] or "segments=None" in src[:600], "gather must accept segments="
    assert "_parse_recon_segments(" in src
    for marker in ('facts["live_recon"]', '"arjun:', '"form_fields:', '"verb_sweep"', '_live_src', "_live_add("):
        assert marker in src, f"gather lost the live-recon wiring: {marker}"
    # the login form is only promoted for auth-bypass — never for sqli on another endpoint
    assert 'vc == "auth-bypass"' in src


def test_node_gather_check_passes_segments():
    src = _func_src("node_gather_check", GRAPH)
    assert src and 'segments=list(state.get("segments") or [])' in src


def test_manifest_text_renders_live_recon_block():
    src = _func_src("_gather_manifest_text")
    assert src and "LIVE RECON (this run):" in src
