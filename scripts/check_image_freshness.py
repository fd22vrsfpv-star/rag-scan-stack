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
import os
import hashlib
import re
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

# Extensions worth comparing. Python was not enough: a stale frontend bundle, a
# changed requirements.txt (dependencies differ from the image) or an edited SQL
# migration are all invisible to a .py-only check. Binaries under bin/ and the
# .agentic-security/ tool state are excluded as noise rather than source.
EXTENSIONS = (".py", ".sql", ".sh", ".json", ".yaml", ".yml", ".conf",
              ".ini", ".toml", ".txt", ".md", ".html", ".css")

_NAME_EXPR = " -o ".join(f"-name '*{e}'" for e in EXTENSIONS)

FIND = (
    f"find / \\( {_NAME_EXPR} \\) -type f "
    "-not -path '*/proc/*' -not -path '*/__pycache__/*' "
    "-not -path '*/site-packages/*' -not -path '*/dist-packages/*' "
    "-not -path '*/node_modules/*' -not -path '*/.git/*' "
    "2>/dev/null | xargs -r md5sum 2>/dev/null"
)


def _noise(path):
    """Files that live in a build context but are not shipped source.

    .agentic-security/ is scanner state that changes constantly, bin/ holds
    vendored tool binaries, and Dockerfile itself is a build input rather than
    something copied in — comparing them produces drift that means nothing.
    """
    parts = set(path.parts)
    return bool(parts & {"__pycache__", ".agentic-security", "bin", "node_modules",
                         ".git", "dist", "build"}) or path.name == "Dockerfile"


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


def _resolve_layout(host_files, ctx_dir, table):
    """Where this build context landed, and in what shape.

    Returns (root, flattened, hits) or None.

    Two shapes exist in this repo:

      structured  host `bff/main.py`      -> container `/app/bff/main.py`
      flattened   host `node_manager.py`  -> container `/app/node_manager.py`
                  (node_manager/Dockerfile COPYs each file to /app/<name>.py)

    Scoring beats requiring a unique anchor. node-manager's image contains the
    source TWICE — once flattened by the Dockerfile at /app/*.py and once via a
    bind mount at /app/node_manager/* — so every anchor had two candidates and
    the earlier version refused to guess, leaving the service unchecked.

    Which copy is right is not a toss-up: `uvicorn node_manager:app` imports
    /app/node_manager.py, and /app/node_manager/ has no __init__.py so it is
    never imported. Preferring the root that matches the MOST files, and
    breaking ties toward the shallower root, lands on the code that actually
    runs.
    """
    rels = [f.relative_to(ctx_dir).as_posix() for f in host_files]
    roots = {}
    for path in table:
        for rel in rels:
            if path.endswith("/" + rel):
                roots.setdefault(path[: -len(rel)], set()).add(("structured", rel))
            elif path.endswith("/" + rel.rsplit("/", 1)[-1]) and "/" not in rel:
                roots.setdefault(path.rsplit("/", 1)[0] + "/", set()).add(("flat", rel))
    if not roots:
        return None

    def score(item):
        root, hits = item
        return (len(hits), -root.count("/"))       # most files, then shallowest

    root, hits = max(roots.items(), key=score)
    flattened = all(kind == "flat" for kind, _ in hits)
    return root, flattened, len(hits)


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

    host_files = [f for f in sorted(ctx_dir.rglob("*"))
                  if f.is_file() and f.suffix in EXTENSIONS
                  and not _noise(f)]
    if not host_files:
        return None

    layout = _resolve_layout(host_files, ctx_dir, table)
    if layout is None:
        print(f"?      {svc}: could not locate this build context inside the image")
        return None
    root, flattened, _ = layout

    drift, checked = [], 0
    for f in host_files:
        rel = f.relative_to(ctx_dir).as_posix()
        key = root + (rel.rsplit("/", 1)[-1] if flattened else rel)
        digest = table.get(key)
        if digest is None:
            continue          # not shipped in this image; not drift
        checked += 1
        if md5(f) != digest:
            drift.append(rel)

    shape = "flattened" if flattened else "structured"
    if drift:
        print(f"STALE  {svc} — {len(drift)} of {checked} file(s) differ from the image")
        for d in drift[:8]:
            print(f"         {d}")
        if len(drift) > 8:
            print(f"         ... and {len(drift) - 8} more")
        print(f"       fix: docker compose build {svc} && docker compose up -d {svc}")
    else:
        print(f"ok     {svc} ({checked} file(s) match, root {root} {shape})")
    return bool(drift)


def check_frontend(live):
    """Is the SERVED frontend bundle built from this working tree?

    Hashing cannot answer this: the frontend is a build artifact, so
    src/lib/constants.ts never appears verbatim in dist/assets/*.js. What does
    survive the build is BUILD_VERSION, which the project already requires to be
    bumped in lockstep across constants.ts, package.json and .env.

    That makes it a usable staleness marker — and it caught a real one: the repo
    was at 2026.08.17-1330 while the container was still serving 2026.08.17-1105,
    invisible to a source-hash check of any kind.
    """
    svc = "pentest-dashboard"
    if svc not in live:
        return None

    src = ROOT / "dashboard" / "frontend" / "src" / "lib" / "constants.ts"
    if not src.exists():
        return None
    m = re.search(r"BUILD_VERSION\s*=\s*['\"]([^'\"]+)", src.read_text())
    if not m:
        return None
    want = m.group(1)

    out = _sh(["docker", "exec", svc, "sh", "-c",
               "grep -rhoE '[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}-[0-9]{4}' "
               "/app/frontend/dist/assets/*.js 2>/dev/null | sort -u"])
    served = [v for v in out.split() if v]
    if not served:
        print(f"?      {svc} frontend: no BUILD_VERSION found in the served bundle")
        return None

    if want in served:
        print(f"ok     {svc} frontend bundle is {want}")
        return False

    print(f"STALE  {svc} frontend bundle is {', '.join(served)} but the tree says {want}")
    print(f"       the UI is serving an older build than this checkout")
    print(f"       fix: docker compose build {svc} && docker compose up -d {svc}")
    return True


def check_base_image():
    """Is rag-common:latest carrying the current common/ sources?

    The base image is the one thing `docker compose build <service>` will NOT
    refresh: it is a FROM dependency, not a layer of the service build. Editing
    common/tool_job.py and rebuilding a service therefore produces an image
    built on STALE shared code — which presents as an ImportError for a function
    that plainly exists in the tree, or worse, silently runs the old version.

    Returns a list of problem strings (empty when fine).
    """
    import subprocess as _sp
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    common = os.path.join(repo, "common")
    if not os.path.isdir(common):
        return []
    try:
        _sp.run(["docker", "image", "inspect", "rag-common:latest"],
                capture_output=True, check=True)
    except Exception:
        return ["rag-common:latest does not exist — run scripts/build-base-image.sh"]

    problems = []
    for fn in sorted(os.listdir(common)):
        if not fn.endswith(".py"):
            continue
        local = os.path.join(common, fn)
        with open(local, "rb") as fh:
            want = hashlib.sha256(fh.read()).hexdigest()
        try:
            out = _sp.run(
                ["docker", "run", "--rm", "--entrypoint", "sha256sum",
                 "rag-common:latest", f"/usr/local/lib/python3.12/site-packages/{fn}"],
                capture_output=True, text=True, timeout=60)
            got = (out.stdout or "").split()[0] if out.stdout.strip() else None
        except Exception as e:
            problems.append(f"could not read {fn} from rag-common: {e}")
            continue
        if got is None:
            problems.append(f"common/{fn} is missing from rag-common:latest")
        elif got != want:
            problems.append(f"common/{fn} differs from the copy in rag-common:latest")
    return problems


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

    if not want or want == "pentest-dashboard":
        fr = check_frontend(live)
        if fr is not None:
            results.append(("pentest-dashboard frontend", fr))

    # The base image is checked separately: it is a FROM dependency, so
    # rebuilding a service does NOT refresh it. A stale rag-common ships old
    # shared code into freshly-built services — which surfaced here as an
    # ImportError for a function that plainly existed in the tree.
    base_problems = check_base_image()
    for problem in base_problems:
        print(f"STALE  rag-common: {problem}")
    if base_problems:
        print("       fix: scripts/build-base-image.sh, then rebuild dependent services")

    stale = [s for s, bad in results if bad]
    print()
    if base_problems:
        print("rag-common:latest is out of date with common/ — services built on it")
        print("are running old shared code. Rebuild the base FIRST, then the services.")
        return 1
    if stale:
        print(f"{len(stale)} service(s) running stale code: {', '.join(stale)}")
        print("A restart will NOT fix this — these images must be rebuilt.")
        return 1
    print(f"All {len(results)} running built service(s) match this working tree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
