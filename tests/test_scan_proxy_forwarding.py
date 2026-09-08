"""A scan gated on "must use a proxy" must actually use one.

Run on demand:

    pytest tests/test_scan_proxy_forwarding.py -v

WHY THIS EXISTS
---------------
`block_local_scans` is an OPSEC control: with it on, every active scan must
route through a proxy/tunnel. The BFF enforces it in `_check_proxy_required`,
which is satisfied by the `proxy` parameter being PRESENT, then injects it into
the payload (`payload["proxy"] = req.proxy`) and records it in the job file.

Pydantic's default is `extra="ignore"`. A receiving request model that does not
DECLARE `proxy` therefore drops it in silence — no error, no warning, nothing in
any log. The gate passes, the job file says `"proxy": "socks5://..."`, and the
traffic leaves from the host's own address.

Measured, not theorised. A pipeline scan of an external target was launched with
`proxy=socks5://node-manager:10120` and:

    docker exec web-scanner env | grep -i proxy        -> (nothing)
    docker exec web-scanner curl https://api.ipify.org -> 199.168.198.186  (host)
    curl --socks5-hostname node-manager:10120 ...      -> 3.15.200.93      (node)

The proxy worked perfectly. `PipelineReq` just had no field for it. `GobusterReq`
and `NiktoReq` had the same hole.

This is worse than an ungated dispatch, because every surface an operator would
check says the scan was proxied.

Static — no stack needed, runs in CI.

Sabotage check: delete `proxy` from PipelineReq -> RED.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")
BFF_SCANS = os.path.join(REPO, "dashboard", "bff", "routers", "scans.py")

#: Scan payload keys the BFF injects generically, which every receiving model
#: must therefore declare or silently discard. Add a key here when the BFF
#: starts injecting one.
INJECTED_KEYS = ("proxy",)


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _request_models(src):
    """Map '/jobs/x' -> the Pydantic model its handler accepts."""
    tree = ast.parse(src)
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and dec.args):
                continue
            path = getattr(dec.args[0], "value", None)
            if not isinstance(path, str):
                continue
            for arg in node.args.args:
                ann = getattr(arg, "annotation", None)
                if isinstance(ann, ast.Name) and ann.id.endswith("Req"):
                    out[path] = ann.id
    return out


def _model_fields(src):
    return {
        cls.name: {
            st.target.id for st in cls.body
            if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)
        }
        for cls in ast.walk(ast.parse(src)) if isinstance(cls, ast.ClassDef)
    }


def _web_scanner_routes(bff_src):
    """The '/jobs/...' paths SCAN_ROUTES sends to the web scanner."""
    import re
    m = re.search(r"SCAN_ROUTES\s*(?::[^=]*)?=\s*\{", bff_src)
    if not m:
        pytest.skip("SCAN_ROUTES not found")
    start = m.end() - 1
    depth = 0
    for i in range(start, len(bff_src)):
        if bff_src[i] == "{":
            depth += 1
        elif bff_src[i] == "}":
            depth -= 1
            if depth == 0:
                break
    body = bff_src[start:i + 1]
    return [(st, path) for st, svc, path in
            re.findall(r'"([\w.-]+)":\s*\(\s*"(\w+)",\s*"([^"]+)"', body)
            if svc == "web_scanner_url"]


def test_the_bff_still_injects_the_keys_this_file_checks():
    """If the BFF stops injecting `proxy`, this whole file is checking nothing."""
    src = _src(BFF_SCANS)
    assert 'payload["proxy"] = req.proxy' in src, (
        "the BFF no longer injects proxy into scan payloads — either the "
        "mechanism changed or INJECTED_KEYS is stale, and these guards are now "
        "vacuous"
    )


def test_every_gated_scan_route_declares_the_injected_keys():
    """The actual invariant: declared, or silently dropped."""
    bff, ws = _src(BFF_SCANS), _src(WEB_SCAN)
    routes = _web_scanner_routes(bff)
    assert routes, "no web-scanner scan routes found — guard would pass vacuously"

    models, fields = _request_models(ws), _model_fields(ws)
    missing = []
    for scan_type, path in routes:
        model = models.get(path)
        if not model:
            continue          # handler takes no request model (query params)
        for key in INJECTED_KEYS:
            if key not in fields.get(model, set()):
                missing.append(f"{scan_type} -> {path} ({model}) drops {key!r}")

    assert not missing, (
        "these routes pass the block-local-scans gate and then silently discard "
        "the proxy, so the scan egresses from this host's own address:\n  "
        + "\n  ".join(missing)
    )


def test_the_proxy_helper_fails_closed():
    """Unproxied egress when a proxy was requested is worse than no scan.

    The original code wrapped ZAP proxy setup in `except Exception:
    logger.warning(...)` and scanned on regardless.
    """
    ws = _src(WEB_SCAN)
    fn = None
    for node in ast.walk(ast.parse(ws)):
        if isinstance(node, ast.FunctionDef) and node.name == "proxied_scan":
            fn = ast.get_source_segment(ws, node) or ""
    assert fn, "proxied_scan() not found — this guard would pass vacuously"

    assert "raise RuntimeError" in fn, (
        "proxied_scan does not raise when the proxy cannot be established, so a "
        "scan continues unproxied after the operator asked for a proxy"
    )
    assert "_probe_socks" in fn, (
        "the proxy is never probed, so an unreachable node is only discovered "
        "once traffic has already gone somewhere"
    )


def test_the_proxy_helper_restores_global_state():
    """ALL_PROXY and ZAP's SOCKS setting are global and outlive the job."""
    ws = _src(WEB_SCAN)
    fn = [ast.get_source_segment(ws, n) for n in ast.walk(ast.parse(ws))
          if isinstance(n, ast.FunctionDef) and n.name == "proxied_scan"][0]
    assert "finally" in fn, "global proxy state is not restored on the error path"
    assert "useSocksProxy" in fn and '"false"' in fn, (
        "ZAP keeps routing through the node after the job ends, so the NEXT "
        "scan is proxied through something it never asked for"
    )


def test_every_scan_job_that_takes_a_proxy_applies_it():
    """A declared field that nothing reads is the same bug one layer down.

    Two patterns are legitimate:

    * `proxied_scan(proxy, job_id)` — sets ALL_PROXY (with a NO_PROXY bypass for
      internal services) and ZAP's upstream SOCKS for the whole job. Used where
      the tools have no proxy flag of their own.
    * threading `proxy` into each tool invocation — `_run_content_recon` does
      this, passing `--proxy` / `-proxy` / `--chrome-proxy` to gobuster, katana
      and gowitness respectively.

    Logging the proxy is NOT applying it, which is why an audit-dict mention
    does not satisfy this.
    """
    ws = _src(WEB_SCAN)
    tree = ast.parse(ws)
    offenders = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("_run_")):
            continue
        if "proxy" not in {a.arg for a in node.args.args}:
            continue
        body = ast.get_source_segment(ws, node) or ""
        applied = (
            "proxied_scan" in body            # whole-job
            or "proxy=proxy" in body          # passed to a helper
            or "proxy {proxy}" in body        # katana/gobuster/gowitness flags
            or "-proxy {proxy}" in body
        )
        if not applied:
            offenders.append(node.name)
    assert not offenders, (
        "these jobs accept a proxy and never apply it: " + ", ".join(offenders)
    )


def test_internal_service_calls_bypass_the_scan_proxy():
    """ALL_PROXY applies to EVERY host, internal ones included.

    Without a NO_PROXY the scanner's own calls to playwright-scanner,
    nuclei-runner, rag-api and ZAP are sent to the operator's egress node, which
    cannot resolve Docker-internal names. Two failures at once: the pipeline
    stages break, and the internal hostnames are handed to the remote node in
    SOCKS CONNECT requests.

    Verified: with ALL_PROXY set and no NO_PROXY,
    `Session.merge_environment_settings('https://playwright-scanner:8014/...')`
    returns `{'all': 'socks5://node-manager:10120'}`.
    """
    ws = _src(WEB_SCAN)
    fn = [ast.get_source_segment(ws, n) for n in ast.walk(ast.parse(ws))
          if isinstance(n, ast.FunctionDef) and n.name == "proxied_scan"][0]
    # Anchor on the ASSIGNMENT, not the word: the surrounding comment explains
    # NO_PROXY at length, so `"NO_PROXY" in fn` stays true after the code that
    # sets it is deleted. That version of this guard passed its own sabotage.
    assert 'os.environ["NO_PROXY"]' in fn and 'os.environ["no_proxy"]' in fn, (
        "proxied_scan sets ALL_PROXY without assigning a NO_PROXY bypass, so "
        "internal service traffic is tunnelled through the operator's egress node"
    )
    assert "_internal_no_proxy()" in fn, (
        "the bypass list is not computed from the stack's own service URLs"
    )
    helper = [ast.get_source_segment(ws, n) for n in ast.walk(ast.parse(ws))
              if isinstance(n, ast.FunctionDef) and n.name == "_internal_no_proxy"]
    assert helper, "_internal_no_proxy() not found"
    for svc in ("PLAYWRIGHT_URL", "API_BASE", "ZAP_ADDR", "localhost"):
        assert svc in helper[0], f"{svc} is not in the proxy bypass list"
