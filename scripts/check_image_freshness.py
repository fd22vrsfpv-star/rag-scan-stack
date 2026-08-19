#!/usr/bin/env python3
"""Is the code in each running container the code in this working tree?

WHY THIS EXISTS

Most services bake their source into the image — only `etl/` and a couple of
others are bind-mounted. `docker compose restart` therefore re-runs the OLD code
with no error and no warning. A scope-enforcement fix was committed, reviewed
and believed live for hours while the container kept ingesting out-of-scope
hosts, because osint_runner.py is baked and the image was never rebuilt.

Nothing in the stack reported that. This does.

    python3 scripts/check_image_freshness.py            # every running service
    python3 scripts/check_image_freshness.py rag-api    # just one

Exit code 1 if any service is stale, so it can gate a deploy or a test run.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# service -> build context. Only services that BAKE their source; bind-mounted
# ones (etl/) cannot go stale.
SERVICES = {
    "rag-api": "app/rag-api",
    "pentest-dashboard": "dashboard/bff",
    "autogen-agents": "autogen_agents",
    "osint-runner": "osint_runner",
    "pd-runner": "pd_runner",
    "web-scanner": "web_scanner",
    "nuclei-runner": "nuclei",
    "nmap_scanner": "nmap_scanner",
    "scan-recommender": "scan_recommender",
    "playwright-scanner": "playwright_scanner",
    "brutus-runner": "brutus_runner",
    "exploit-runner": "exploit_runner",
    "kali-listener": "kali_listener",
    "node-manager": "node_manager",
    "news-runner": "news_runner",
}

# Directories inside an image that are never our source. Matching on basename
# alone is wrong — an image holds dozens of main.py/util.py under site-packages,
# and taking the first hit reports a false STALE. Paths are matched by suffix.
SKIP = ("/proc/", "/__pycache__/", "/site-packages/", "/dist-packages/",
        "/usr/lib/python", "/usr/local/lib/python", "/node_modules/")

FIND = (
    "find / -name '*.py' -type f "
    "-not -path '*/proc/*' -not -path '*/__pycache__/*' "
    "-not -path '*/site-packages/*' -not -path '*/dist-packages/*' "
    "2>/dev/null | xargs -r md5sum 2>/dev/null"
)


def _sh(args, timeout=120):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def running():
    return set(_sh(["docker", "ps", "--format", "{{.Names}}"]).split())


def container_hashes(svc):
    """path -> md5 for every source file in the image, skipping vendored code."""
    out = _sh(["docker", "exec", svc, "sh", "-c", FIND])
    table = {}
    for line in out.splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            continue
        digest, path = parts[0].strip(), parts[1].strip()
        if any(s in path for s in SKIP):
            continue
        table[path] = digest
    return table


def md5(path):
    return hashlib.md5(path.read_bytes()).hexdigest()


def _container_root(host_files, ctx_dir, table):
    """Where this build context landed inside the image.

    Anchoring matters. Matching each file by path SUFFIX looks fine until a
    top-level `__init__.py` matches /usr/share/gcc/python/libstdcxx/__init__.py
    and the service is reported stale on a file it shares a name with. So pick
    the most distinctive file — the deepest relative path, which is least likely
    to collide — resolve THAT one, and derive a single root from it. Everything
    else is then compared at an exact path.
    """
    candidates = sorted(host_files, key=lambda f: len(f.relative_to(ctx_dir).parts),
                        reverse=True)
    for f in candidates:
        rel = f.relative_to(ctx_dir).as_posix()
        hits = [p for p in table if p.endswith("/" + rel)]
        if len(hits) == 1:
            return hits[0][: -len(rel)]          # keeps the trailing slash
    return None


def check(svc, ctx, live):
    if svc not in live:
        return None
    ctx_dir = ROOT / ctx
    if not ctx_dir.is_dir():
        return None

    table = container_hashes(svc)
    if not table:
        print(f"?      {svc}: could not read source from the container")
        return None

    host_files = [f for f in sorted(ctx_dir.rglob("*.py"))
                  if "__pycache__" not in f.parts]
    if not host_files:
        return None

    root = _container_root(host_files, ctx_dir, table)
    if root is None:
        print(f"?      {svc}: could not locate this build context inside the image")
        return None

    drift, checked = [], 0
    for f in host_files:
        rel = f.relative_to(ctx_dir).as_posix()
        digest = table.get(root + rel)
        if digest is None:
            continue          # not shipped in this image; not drift
        checked += 1
        if md5(f) != digest:
            drift.append(rel)

    if drift:
        print(f"STALE  {svc} — {len(drift)} of {checked} file(s) differ from the image")
        for d in drift[:8]:
            print(f"         {d}")
        if len(drift) > 8:
            print(f"         ... and {len(drift) - 8} more")
        print(f"       fix: docker compose build {svc} && docker compose up -d {svc}")
    else:
        print(f"ok     {svc} ({checked} file(s) match, root {root})")
    return bool(drift)


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else None
    live = running()
    if not live:
        print("No running containers — nothing to compare.")
        return 0

    results = []
    for svc, ctx in SERVICES.items():
        if want and svc != want:
            continue
        r = check(svc, ctx, live)
        if r is not None:
            results.append((svc, r))

    stale = [s for s, bad in results if bad]
    print()
    if stale:
        print(f"{len(stale)} service(s) running stale code: {', '.join(stale)}")
        print("A restart will NOT fix this — these images must be rebuilt.")
        return 1
    print(f"All {len(results)} running built service(s) match this working tree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
