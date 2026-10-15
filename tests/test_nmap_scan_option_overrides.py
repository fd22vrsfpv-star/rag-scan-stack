"""An explicit per-scan option must be able to turn a default OFF, not only on.

`nmap-api.py` resolves several options as "per-scan overrides env". Two of them
already distinguish *unset* from *explicitly set* — the file's own convention:

    service_detection = svc_param if svc_param is not None else <env default>
    version_intensity = str(vi) if vi is not None else <env default>

`scripts` did not:

    scripts = opts.get("scripts") or os.environ.get("NMAP_SCRIPTS", "")

`"" or X` is `X`, so an explicit empty value fell through to the environment and
the per-scan override could only ADD scripts, never remove them.

Observed 2026-10-14: a 762-host proxied connect scan was dispatched with
`service_detection: false` to answer "is anything listening". The container's
`NMAP_SCRIPTS` default attached `banner,http-title,ssl-cert,ssl-enum-ciphers,
ssh2-enum-algos,vulscan/vulscan.nse` anyway. `ssl-enum-ciphers` opens a
connection per cipher suite, and through a single SOCKS5 tunnel under
`strict_chain` the scan produced **zero completed hosts in 15 minutes** — the
output file held nothing but the command echo. The caller had no way to say
"no scripts".

Static (`ast`): no nmap, no network.

Sabotage check: restore either `or os.environ.get(...)` form and the matching
case fails by name.

    pytest tests/test_nmap_scan_option_overrides.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NMAP_API = REPO / "nmap_scanner" / "nmap-api.py"

# Option -> the local name it is assigned to in the source.
OVERRIDABLE = {
    "scripts": ("scripts", "extra_scripts"),
    "service_detection": ("service_detection", "svc_detect"),
}


def _tree() -> ast.Module:
    if not NMAP_API.exists():
        pytest.skip(f"{NMAP_API} not found")
    return ast.parse(NMAP_API.read_text(encoding="utf-8"))


def _assignments_for(local_names) -> list:
    """Every `<local> = <value>` whose value mentions an env lookup."""
    out = []
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.Assign) or not node.value:
            continue
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if not targets & set(local_names):
            continue
        env_used = any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("get", "getenv")
            and "environ" in ast.dump(n.func.value)
            for n in ast.walk(node.value))
        if env_used:
            out.append(node)
    return out


@pytest.mark.parametrize("option", sorted(OVERRIDABLE))
def test_explicit_value_beats_the_env_default(option):
    """`x or env` discards an explicit falsy value; the ternary does not."""
    assigns = _assignments_for(OVERRIDABLE[option])
    assert assigns, (
        f"no env-backed assignment found for {option!r} — has the resolution "
        "moved? This guard is now blind.")
    for node in assigns:
        boolops = [n for n in ast.walk(node.value)
                   if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or)]
        assert not boolops, (
            f"{option} is resolved with `or` at line {node.lineno}: an explicit "
            "empty/false value falls through to the environment, so the "
            "per-scan override can only add the default, never turn it off. "
            "Use the `x if x is not None else <env>` form this file already "
            "uses for service_detection.")


def test_unset_still_takes_the_env_default():
    """The fix must not have hardcoded the option off."""
    for option, locals_ in OVERRIDABLE.items():
        for node in _assignments_for(locals_):
            src = ast.dump(node.value)
            assert "environ" in src, (
                f"{option} at line {node.lineno} no longer consults the "
                "environment — an unset option would ignore the operator's "
                "container defaults")
            assert "IsNot" in src or "Is" in src, (
                f"{option} at line {node.lineno} does not test for None, so it "
                "cannot tell 'unset' from 'explicitly empty'")
