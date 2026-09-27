"""render_command shell-quotes the URL/target it substitutes.

The rendered command is handed to /bin/sh by the listener. A finding URL that
carries a shell metacharacter — the classic being a stray trailing apostrophe
from a relative-path-confusion crawl artifact, e.g.
`http://192.168.1.150:80/doc/'` — MUST be quoted, or the probe dies before it
reaches the network with `/bin/sh: Syntax error: Unterminated quoted string`
and is then filed as a probe that ran and found nothing (OPEN_ITEMS: "Generated
curl commands carry a stray trailing quote and die in the shell").

Guards the CLASS: any value with a shell metacharacter must render to a command
that survives `shlex.split`, whether the map template wraps `{url}` in quotes or
leaves it bare.

Pure stdlib module — imported directly, runs on a bare checkout; skips cleanly
if wstg.py is not present.

    pytest tests/test_wstg_command_quoting.py
"""
import importlib.util
import os
import shlex

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "app", "rag-api", "wstg.py")


def _load():
    if not os.path.exists(MOD):
        pytest.skip("wstg.py not present")
    spec = importlib.util.spec_from_file_location("wstg", MOD)
    m = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(m)
    except Exception as e:  # noqa: BLE001 — missing optional dep -> skip, not error
        pytest.skip(f"wstg.py could not be imported: {type(e).__name__}: {e}")
    return m


wstg = _load()

# The exact string from OPEN_ITEMS.md — a directory URL with a trailing
# apostrophe and no opener.
DIRTY_URL = "http://192.168.1.150:80/doc/'"

# Both quoting styles the map uses (see knowledge/wstg_map.yaml): bare {url}
# (e.g. dir_listing: `curl -sk {url}`) and author-quoted "{url}".
BARE_TEMPLATE = "curl -sk {url}"
QUOTED_TEMPLATE = 'curl -sk "{url}"'


def _balanced(cmd):
    """A command is shell-balanced iff shlex can split it without raising."""
    try:
        shlex.split(cmd)
        return True
    except ValueError:
        return False


def test_bare_template_with_stray_quote_is_balanced():
    cmd = wstg.render_command({"command": BARE_TEMPLATE},
                              target="192.168.1.150", url=DIRTY_URL)
    assert _balanced(cmd), (
        f"stray quote produced an unparseable command that dies in /bin/sh: {cmd!r}")
    # The command still targets the intended path — the fix quotes, it does not
    # drop or mangle the URL.
    assert shlex.split(cmd)[-1] == DIRTY_URL, shlex.split(cmd)


def test_quoted_template_with_stray_quote_is_balanced():
    cmd = wstg.render_command({"command": QUOTED_TEMPLATE},
                              target="192.168.1.150", url=DIRTY_URL)
    assert _balanced(cmd), f"author-quoted template not double-quote-safe: {cmd!r}"
    assert shlex.split(cmd)[-1] == DIRTY_URL, shlex.split(cmd)


def test_clean_url_is_unchanged():
    """shlex.quote is a no-op for a well-formed URL, so existing map behaviour is
    preserved — a clean URL renders bare, exactly as before the fix."""
    clean = "http://192.168.1.150:80/doc/"
    cmd = wstg.render_command({"command": BARE_TEMPLATE},
                              target="192.168.1.150", url=clean)
    assert cmd == f"curl -sk {clean}", cmd


def test_space_in_path_is_balanced():
    """A crawl artifact with spaces (`/my documents/...`) must not split into
    multiple curl arguments."""
    spaced = "http://192.168.1.150:80/my documents/JohnSmith/"
    cmd = wstg.render_command({"command": BARE_TEMPLATE},
                              target="192.168.1.150", url=spaced)
    assert _balanced(cmd), cmd
    assert shlex.split(cmd)[-1] == spaced, shlex.split(cmd)


def test_target_placeholder_is_quoted_too():
    cmd = wstg.render_command({"command": "sslscan {target}"},
                              target="192.168.1.150'", url=None)
    assert _balanced(cmd), cmd
