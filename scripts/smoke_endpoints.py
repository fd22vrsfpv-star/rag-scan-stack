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

# Paths to skip entirely: expensive, or they mutate state despite being GET.
SKIP = {
    "/api/maintenance/export",          # streams a full backup archive
    "/api/maintenance/export/estimate", # walks every mounted volume
}

DECORATOR = re.compile(r'@router\.(get)\(\s*[\'"]([^\'"]+)[\'"]')


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


def probe(base, path, timeout, api_key=None):
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
            return path, r.status, ""
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
    args = ap.parse_args()

    paths = discover()
    if not paths:
        print("No endpoints discovered — has the BFF layout changed?", file=sys.stderr)
        return 1
    api_key = os.environ.get("API_KEY")

    print(f"Probing {len(paths)} parameterless GET endpoint(s) at {args.base}")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda p: probe(args.base, p, args.timeout, api_key), paths))

    buckets = {}
    failures = []
    for path, status, body in results:
        buckets[status] = buckets.get(status, 0) + 1
        if status == 0 or status >= 500:
            if path in EXPECTED_5XX:
                continue
            failures.append((path, status, body[:200]))

    for status in sorted(buckets):
        label = "unreachable" if status == 0 else str(status)
        print(f"  {buckets[status]:>4}  {label}")

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
