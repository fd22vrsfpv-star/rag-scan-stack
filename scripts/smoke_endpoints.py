#!/usr/bin/env python3
"""Call every parameterless GET endpoint and report the ones that break.

    python3 scripts/smoke_endpoints.py                 # BFF via localhost
    python3 scripts/smoke_endpoints.py --json out.json
    python3 scripts/smoke_endpoints.py --base https://localhost:3002 --timeout 20

Exit code is 1 if any endpoint returns 5xx (excluding allowed ones), else 0.

WHY THIS EXISTS
---------------
There are ~1,150 distinct endpoints and roughly 11% are mentioned by any test.
Writing a case per endpoint is not realistic; calling them all is. The first run
of this sweep found four broken endpoints in under two minutes:

  * /api/exploits/results/all           500 — SELECT on a column that does not exist
  * /api/nodes/implants, /nodes/sessions 500 — shadowed by /api/nodes/{node_id}
  * (+6 more node routes unreachable for the same reason)

WHAT IT DOES NOT COVER
----------------------
Only GET, and only routes with no path or required query parameters. POST, PUT
and DELETE are excluded deliberately: this must be safe to run against a live
engagement, and those endpoints launch scans, delete data and execute tools.
A 4xx is NOT a failure here — an endpoint that requires parameters correctly
rejects a bare GET.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Endpoints allowed to return 5xx, with the reason. Anything else is a failure.
EXPECTED_5XX = {
    "/api/burp/scans": "503 when Burp Suite is not running — optional component",
}

# Prefixes allowed to return 5xx, with the reason. Burp is an optional external
# component: with BURP_API_URL unset every route under it answers 503, which is
# the correct answer, not a defect.
EXPECTED_5XX_PREFIXES = {
    "/api/burp/": "503 when BURP_API_URL is unset — optional external component",
}

# Paths to skip entirely: expensive, or they mutate state despite being GET.
SKIP = {
    "/api/maintenance/export",          # streams a full backup archive
    "/api/maintenance/export/estimate", # walks every mounted volume
}

DECORATOR = re.compile(r'@router\.(get)\(\s*[\'"]([^\'"]+)[\'"]')

# ---------------------------------------------------------------------------
# Parameterised GETs (68 routes, 30 distinct parameter names).
#
# IDs are resolved at RUNTIME from list endpoints rather than hardcoded, so the
# sweep does not rot the moment a fixture UUID is deleted. Anything we cannot
# resolve is reported as "unsampled" rather than quietly dropped — a sweep that
# silently skips half its routes reads as coverage it does not have.
# ---------------------------------------------------------------------------

# param -> (list endpoint, keys to look under, keys that hold the id)
SAMPLE_FROM = {
    "eid":           ("/api/engagements", ["engagements", "items", "data"], ["id", "engagement_id"]),
    "node_id":       ("/api/nodes", ["nodes", "items", "data"], ["id", "node_id"]),
    "session_id":    ("/api/agent-sessions", ["sessions", "items", "data"], ["id", "session_id"]),
    "collection_id": ("/api/api-collections", ["collections", "items", "data"], ["id", "collection_id"]),
    "pipeline_id":   ("/api/pipelines", ["pipelines", "items", "data"], ["id", "pipeline_id"]),
    "artifact_id":   ("/api/artifacts", ["artifacts", "items", "data"], ["id", "artifact_id"]),
    "exploit_id":    ("/api/exploits/pending", ["exploits", "pending", "items", "data"], ["id", "exploit_id"]),
    "credential_id": ("/api/credentials", ["credentials", "findings", "items", "data"], ["id"]),
    "scope_name":    ("/api/scope/names", ["names", "scopes", "items", "data"], ["name", "scope_name"]),
    "test_id":       ("/api/security-tests", ["tests", "items", "data"], ["id", "test_id"]),
}

# Params with a safe, stable literal. A 404 on these is a fine result — it
# proves the route resolved and the handler ran.
SAMPLE_STATIC = {
    "source": "web",                       # findings source discriminator
    "key_name": "ollama_active_model",      # a real config key
    "ip": "127.0.0.1",
    "target": "127.0.0.1",
    "domain": "example.com",
    "container_name": "rag-api",
    "name": "default",
    "filename": "none.txt",
    # Opaque ids with no list endpoint to draw from. A well-formed uuid that
    # does not exist should 404, never 500.
    "job_id": "00000000-0000-0000-0000-000000000000",
    "task_id": "00000000-0000-0000-0000-000000000000",
    "fid": "00000000-0000-0000-0000-000000000000",
    "exec_id": "00000000-0000-0000-0000-000000000000",
    "run_id": "00000000-0000-0000-0000-000000000000",
    "item_id": "00000000-0000-0000-0000-000000000000",
    "rule_id": "00000000-0000-0000-0000-000000000000",
    "preset_id": "00000000-0000-0000-0000-000000000000",
    "identity_id": "00000000-0000-0000-0000-000000000000",
    "peer_id": "00000000-0000-0000-0000-000000000000",
    "droplet_id": "00000000-0000-0000-0000-000000000000",
    "instance_id": "00000000-0000-0000-0000-000000000000",
}

# Catch-all proxies: the parameter is an arbitrary forwarded path, so there is
# no representative value to substitute.
SKIP_PARAMS = {"path:path"}


def discover_parameterised(root="dashboard/bff"):
    """GET routes that carry path parameters."""
    found = set()
    base = os.path.join(REPO, root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = DECORATOR.search(line)
                    if m and "{" in m.group(2):
                        found.add(m.group(2))
    return sorted(found - SKIP)


def _first_id(payload, list_keys, id_keys):
    """Pull the first plausible id out of a list-endpoint response."""
    rows = None
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in list_keys:
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
    if not rows:
        return None
    for row in rows:
        if isinstance(row, dict):
            for key in id_keys:
                if row.get(key):
                    return str(row[key])
        elif isinstance(row, str) and row:
            return row
    return None


def resolve_samples(base, timeout, api_key):
    """Build param -> value, drawing live ids where a list endpoint offers them."""
    samples = dict(SAMPLE_STATIC)
    for param, (endpoint, list_keys, id_keys) in SAMPLE_FROM.items():
        # ?limit=1 keeps the response inside probe()'s read cap. Without it
        # /api/artifacts returned 276 rows, blew past 20KB, and arrived
        # truncated — so json.loads failed and the id silently went unresolved.
        # Endpoints that do not implement `limit` ignore the extra query param.
        sep = "&" if "?" in endpoint else "?"
        # Generous read cap here, NOT the default. Routes that ignore `limit`
        # still return everything: /api/exploits/pending came back at 36KB and
        # arrived truncated, so json.loads failed and exploit_id went
        # unresolved while looking like an empty table.
        _, status, body = probe(base, f"{endpoint}{sep}limit=1", timeout, api_key,
                                read_bytes=4_000_000)
        if status != 200 or not body:
            continue
        try:
            found = _first_id(json.loads(body), list_keys, id_keys)
        except (ValueError, TypeError):
            continue
        if found:
            samples[param] = found
    return samples


def fill(path, samples):
    """Substitute a concrete path, or None if any parameter is unsampled."""
    names = re.findall(r"\{([^}]+)\}", path)
    if any(n in SKIP_PARAMS for n in names):
        return None
    out = path
    for name in names:
        key = name.split(":")[0]
        if key not in samples:
            return None
        out = out.replace("{%s}" % name, str(samples[key]))
    return out


def discover(root="dashboard/bff"):
    """Parameterless GET routes declared in the BFF."""
    found = set()
    base = os.path.join(REPO, root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = DECORATOR.search(line)
                    if m and "{" not in m.group(2):
                        found.add(m.group(2))
    return sorted(found - SKIP)


def probe(base, path, timeout, api_key=None, read_bytes=20000):
    url = base.rstrip("/") + path
    ctx = ssl.create_default_context()
    # The stack uses a self-signed internal cert; this checks liveness, not TLS.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET")
    if api_key:
        req.add_header("x-api-key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            # The body is needed on success too: resolve_samples() reads ids out
            # of list endpoints to build path parameters. Capped so a large
            # response cannot blow up the sweep — but the cap must not truncate
            # a list endpoint mid-JSON, or the id silently fails to resolve.
            return path, r.status, r.read(read_bytes).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(300).decode("utf-8", "replace")
        except Exception:
            pass
        return path, e.code, body
    except Exception as e:
        # A transport failure is a real result: the endpoint did not answer.
        return path, 0, f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=os.environ.get("SMOKE_BASE", "https://localhost:3002"))
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--workers", type=int, default=6,
                    help="parallel probes; keep modest so the sweep does not "
                         "itself look like a load test")
    ap.add_argument("--json", help="write the full result set here")
    ap.add_argument("--no-params", action="store_true",
                    help="skip parameterised GETs (bare-path routes only)")
    args = ap.parse_args()

    paths = discover()
    if not paths:
        print("No endpoints discovered — has the BFF layout changed?", file=sys.stderr)
        return 1
    api_key = os.environ.get("API_KEY")

    print(f"Probing {len(paths)} parameterless GET endpoint(s) at {args.base}")

    unsampled = []
    param_probed = set()
    if not args.no_params:
        parameterised = discover_parameterised()
        samples = resolve_samples(args.base, args.timeout, api_key)
        live = sum(1 for p in SAMPLE_FROM if p in samples and samples[p] not in SAMPLE_STATIC.values())
        concrete = []
        for route in parameterised:
            filled = fill(route, samples)
            if filled:
                concrete.append(filled)
            else:
                unsampled.append(route)
        print(f"Probing {len(concrete)} of {len(parameterised)} parameterised GET "
              f"endpoint(s) ({live} id(s) resolved live, {len(unsampled)} unsampled)")
        param_probed = set(concrete)
        paths = paths + concrete

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda p: probe(args.base, p, args.timeout, api_key), paths))

    buckets = {}
    failures = []
    for path, status, body in results:
        buckets[status] = buckets.get(status, 0) + 1
        if status == 0 or status >= 500:
            if path in EXPECTED_5XX:
                continue
            if any(path.startswith(pre) for pre in EXPECTED_5XX_PREFIXES):
                continue
            failures.append((path, status, body[:200]))

    for status in sorted(buckets):
        label = "unreachable" if status == 0 else str(status)
        print(f"  {buckets[status]:>4}  {label}")

    # A 422 means the sample value had the wrong shape, so the handler never
    # really ran. Not a failure of the endpoint, but not coverage either — say
    # so, rather than letting it count as a pass.
    #
    # Only substituted paths count. A bare route returning 422 is just an
    # endpoint with required QUERY parameters correctly rejecting a bare GET
    # (12 of these: /api/software/*, /api/nuclei/templates/search). Lumping
    # those in blamed the sample table for endpoints it never touched.
    bad_samples = [p for p, s, _ in results if s == 422 and p in param_probed]
    if bad_samples:
        print(f"\n  {len(bad_samples)} endpoint(s) rejected the sample value (422) — "
              "not covered, fix the SAMPLE_* entry:")
        for path in sorted(bad_samples)[:12]:
            print(f"      {path}")

    if unsampled:
        print(f"\n  {len(unsampled)} parameterised route(s) had no sample value "
              "and were NOT probed:")
        for route in unsampled[:12]:
            print(f"      {route}")
        if len(unsampled) > 12:
            print(f"      ... and {len(unsampled) - 12} more")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"path": p, "status": s, "body": b[:500]} for p, s, b in results],
                      fh, indent=2)
        print(f"  wrote {args.json}")

    for path, reason in EXPECTED_5XX.items():
        if any(p == path and (s == 0 or s >= 500) for p, s, _ in results):
            print(f"  tolerated: {path} — {reason}")

    if failures:
        print(f"\n{len(failures)} endpoint(s) failing:")
        for path, status, body in failures:
            print(f"  ✗ {status:>3}  {path}")
            if body.strip():
                print(f"          {body.strip()[:160]}")
        print("\nA 4xx is fine — those endpoints need parameters. A 5xx or no answer "
              "means the endpoint is broken.")
        return 1

    print("\n✅ no endpoint returned 5xx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
