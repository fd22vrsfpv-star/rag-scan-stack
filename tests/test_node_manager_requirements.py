"""Every third-party module node_manager imports must be in its requirements.txt.

`node_manager.py` imported `requests` in three places — the remote-scan ingest
POST and both webhook emits — and `node_manager/requirements.txt` never listed
it. The container built fine, started fine and reported `/health` ok, because
all three imports are *inside functions*:

    {"ok": true, ..., "ingest": {"ok": false, "error": "No module named 'requests'"}}

So every remote scan ran on the node, downloaded its results, and then discarded
them; and every webhook emit raised ImportError into `except Exception: pass`,
which logged nothing at all. Nothing static caught it: `ast.parse` passes, the
module imports, the container is healthy.

A function-local import is the dangerous kind precisely because it defers the
failure to the one code path that needs it, so this guard reads them too.

Sabotage check: delete the `requests==` line from node_manager/requirements.txt
and `test_all_imports_are_declared` fails naming `requests`.

    pytest tests/test_node_manager_requirements.py -q
"""

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PKG = REPO / "node_manager"
REQS = PKG / "requirements.txt"

# Import name -> distribution name, where they differ.
DIST_ALIASES = {
    "psycopg2": "psycopg2-binary",
    "sliver": "sliver-py",
    "yaml": "pyyaml",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "dateutil": "python-dateutil",
}

# Ships as a dependency of a package that IS declared.
TRANSITIVE = {"botocore": "boto3"}


def _declared() -> set[str]:
    if not REQS.exists():
        pytest.skip(f"{REQS} not found")
    names = set()
    for line in REQS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        for sep in ("==", ">=", "<=", "~=", ">", "<", "["):
            if sep in line:
                line = line.split(sep, 1)[0]
                break
        names.add(line.strip().lower().replace("_", "-"))
    return names


def _imported() -> dict[str, set[str]]:
    """Top-level import names -> the files that import them (nested included)."""
    found: dict[str, set[str]] = {}
    for py in sorted(PKG.glob("*.py")):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError as e:
            pytest.fail(f"{py.name} does not parse: {e}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:          # relative import — local by definition
                    continue
                roots = [(node.module or "").split(".")[0]]
            else:
                continue
            for root in roots:
                if root:
                    found.setdefault(root, set()).add(py.name)
    return found


def _is_local(name: str) -> bool:
    """A module the repo itself provides — copied or bind-mounted, not pip'd.

    Scoped to pip declarations on purpose: whether a local module actually
    REACHES the container is a packaging question the Dockerfile and compose
    mounts answer, not requirements.txt. (It is the same class of bug —
    `audit_writer` was imported and present in neither — but a different fix.)
    """
    if (REPO / name).is_dir():
        return True
    if (PKG / f"{name}.py").exists():
        return True
    return any((d / f"{name}.py").exists()
               for d in REPO.iterdir() if d.is_dir() and not d.name.startswith("."))


def test_all_imports_are_declared():
    declared = _declared()
    missing = {}
    for name, files in sorted(_imported().items()):
        if name in sys.stdlib_module_names or _is_local(name):
            continue
        if TRANSITIVE.get(name, "").lower() in declared:
            continue
        dist = DIST_ALIASES.get(name, name).lower().replace("_", "-")
        if dist not in declared:
            missing[name] = sorted(files)
    assert not missing, (
        "node_manager imports these but requirements.txt does not declare them — "
        "they will raise ImportError at runtime, on the exact code path that "
        "needs them: "
        + "; ".join(f"{n} (in {', '.join(f)})" for n, f in missing.items()))


def test_requests_specifically_is_declared():
    """The one that cost every remote scan its results."""
    assert "requests" in _declared(), (
        "requests is gone from node_manager/requirements.txt — remote-scan "
        "ingest and every webhook emit will fail with 'No module named requests'")
