"""A file read injects nothing, so a canary cannot prove it.

CVE-2026-21589 is a pre-auth path traversal. Every iteration of its build
logged `regex_missed` because the assertion was:

    {"canary": "POCz9cb7f414d9", "expect_regex": "POCz9cb7f414d9"}

That can never match. The exploit RETRIEVES `WEB-INF/web.xml`; it puts nothing
into the response for a canary to come back in. Two causes, both fixed:

  1. `_CRAFT_CLASS_GUIDANCE` is keyed on ONE spelling per family and
     `_class_guidance_block` did a plain `.get(vc)`. The run's class was
     `path-traversal`, which is not a key, so it received NO class guidance at
     all and defaulted to a canary.
  2. Even the `lfi` text it would have got said "Place the canary in the
     filename or output marker" — wrong for a read.

And the operator's point, which is the sharp one: for a file read a canary
coming back is evidence of ECHO, not of disclosure. The proof has to be
content only the real file has.

Sabotage check: delete `path-traversal` from the alias map and
`test_every_file_read_spelling_gets_guidance` fails; put the word "canary"
back into the lfi guidance and `test_the_file_read_guidance_forbids_a_canary`
fails.

    pytest tests/test_file_read_proof.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _const(name):
    if not API.exists():
        pytest.skip("api.py not found")
    for n in ast.walk(ast.parse(API.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.literal_eval(n.value)
    pytest.fail(f"{name} not found in api.py")


def _vc_mod():
    """The real class table — the gate reads it, so the test must too."""
    import sys as _sys
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
    from etl import vuln_classes as _m
    return _m


FILE_READ_SPELLINGS = [
    "lfi", "path-traversal", "path_traversal", "directory-traversal",
    "file-read", "arbitrary-file-read", "rfi",
]


# -- 1. every spelling reaches guidance -------------------------------------

@pytest.mark.parametrize("spelling", FILE_READ_SPELLINGS)
def test_every_file_read_spelling_gets_guidance(spelling):
    """A classifier's wording must not decide whether guidance exists."""
    guidance = _const("_CRAFT_CLASS_GUIDANCE")
    key = _vc_mod().canonical(spelling)
    assert key in guidance, (
        f"class {spelling!r} resolves to {key!r}, which has no guidance — a "
        "CVE classified that way gets none at all and the model falls back to "
        "a canary assertion a file read can never satisfy")


def test_every_file_read_class_has_its_own_guidance():
    """lfi, rfi and path-traversal prove the same way and are REACHED
    differently, so each needs guidance that says where the payload goes. One
    entry hedging between them is what let a traversal be told to find a
    parameter."""
    guidance = _const("_CRAFT_CLASS_GUIDANCE")
    m = _vc_mod()
    for cls in sorted(m.classes_where(file_read=True)):
        if cls == "xxe":
            continue            # body injection, guided as its own class
        assert cls in guidance, f"{cls} has no craft guidance"


def test_the_alias_map_is_actually_consulted():
    """A map nobody reads is a map that does nothing."""
    src = API.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef)
               and n.name == "_class_guidance_block"), None)
    assert fn, "_class_guidance_block not found"
    seg = ast.unparse(fn)
    assert "_vc_canonical" in seg, (
        "_class_guidance_block does not normalise the class name, so alternate "
        "spellings still fall through to no guidance")


# -- 2. the guidance says the right thing -----------------------------------

def test_the_file_read_guidance_forbids_a_canary():
    g = _const("_CRAFT_CLASS_GUIDANCE")["lfi"]
    low = g.lower()
    assert "do not assert on" in low or "wrong proof" in low, (
        "the file-read guidance does not tell the model a canary is the wrong "
        "proof — it will keep emitting unsatisfiable expect_regex assertions")
    assert "echo" in low, (
        "the guidance does not say that a canary COMING BACK means the app "
        "echoed the input rather than disclosing a file — that is the signal "
        "that distinguishes a real read from a reflection")
    # ABSENCE, not just presence. The first version of this test only checked
    # that the warnings were there, so restoring the old instruction beside
    # them passed 13/13 — a guard that cannot fail. Caught by sabotage.
    # Match the IMPERATIVE only. "canary in the filename" also appears inside
    # this guidance's own warning ("Do NOT put a canary in the filename"), so
    # a bare substring check fails against correct text — caught immediately
    # when the restore after a sabotage still failed.
    assert "place the canary" not in low, (
        "the file-read guidance still instructs the model to place a canary; "
        "the warnings beside it do not cancel an explicit instruction")


def test_the_file_read_guidance_offers_content_markers():
    """Content only the real file has — the only usable proof here."""
    g = _const("_CRAFT_CLASS_GUIDANCE")["lfi"]
    for marker in ("root:x:0:0:", "<web-app", "<configuration"):
        assert marker in g, (
            f"{marker!r} is not offered as a proof marker; without concrete "
            "per-file signatures the model has nothing to assert on")


def test_the_file_read_guidance_prefers_the_least_sensitive_file():
    """Read what proves the flaw, not what is most damaging."""
    g = _const("_CRAFT_CLASS_GUIDANCE")["lfi"].lower()
    assert "least sensitive" in g, (
        "the guidance does not tell the model to prove the primitive with the "
        "least sensitive file first")
    assert "never credentials" in g or "not credentials" in g, (
        "the guidance does not warn the model off credentials and keys")


# -- 3. the other classes still have theirs ---------------------------------

def test_the_injection_classes_still_use_a_canary():
    """The fix must not strip canaries from classes that DO inject."""
    g = _const("_CRAFT_CLASS_GUIDANCE")
    for vc in ("sqli", "xss", "ssti"):
        assert "canary" in g[vc].lower(), (
            f"{vc} no longer mentions a canary — it injects, so a reflected "
            "canary is exactly the right proof for it")


# -- 4. the evidence path, wired into the loop ------------------------------

def _api_src():
    return API.read_text(encoding="utf-8")


def _func(name):
    fn = next((n for n in ast.walk(ast.parse(_api_src()))
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in api.py"
    return fn


def test_the_refine_loop_captures_retrieved_content():
    """The proof of a file read is the file. Matching and discarding it
    leaves nothing for a human to confirm and nothing to put in a report."""
    seg = ast.get_source_segment(_api_src(), _func("_run_refine_poc")) or ""
    assert "_file_read_evidence" in seg, (
        "the refine loop never captures what a file-read exploit retrieved")
    assert "_vc_is_file_read" in seg, (
        "evidence capture is not gated on the class, so it would run for "
        "injection classes where the response is not a retrieved file")


def test_an_echoed_canary_refutes_a_file_read():
    """THE operator's point: for a read, a canary coming back is evidence
    AGAINST success — the app reflected the request."""
    # Structural: find the `if` whose test reads .get("echoed") and check it
    # assigns success = False. A window search for "echoed" matched an
    # unrelated comment elsewhere in this 1000-line function — the same
    # brittleness this file exists to document.
    fn = _func("_run_refine_poc")
    refuting = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        test_src = ast.unparse(node.test)
        if "echoed" not in test_src:
            continue
        body_src = ast.unparse(node.body)
        if "success = False" in body_src or "success=False" in body_src:
            refuting.append(test_src)
    assert refuting, (
        "no branch downgrades the verdict when the canary was echoed — a "
        "reflection would be recorded as a successful file read")


def test_the_evidence_helper_never_raises():
    """Evidence handling must not be able to fail a build."""
    fn = _func("_file_read_evidence")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert returns, "_file_read_evidence never returns"
    handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try) for h in n.handlers]
    assert handlers, "_file_read_evidence has no exception handling"


def test_the_saved_file_is_labelled_for_review():
    """An operator opening it must know it is content read off a target."""
    seg = ast.get_source_segment(_api_src(), _func("_file_read_evidence")) or ""
    assert "review before sharing" in seg, (
        "the saved evidence carries no warning that it is target content")
    for field in ("signature", "canary echoed"):
        assert field in seg, f"the evidence header omits {field!r}"


def test_signatures_cover_the_common_proof_files():
    """`_FILE_READ_SIGNATURES` is a projection of
    knowledge/payload_variants.yaml now, so the OS is recoverable instead of
    flattened away. Nothing it used to prove may be lost."""
    import sys as _sys
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
    from etl import payload_variants as _pv
    sigs = _pv.file_read_signatures()
    assert sigs, "the projection is empty"
    for f in ("/etc/passwd", "/etc/hosts", "web.xml", "web.config"):
        assert any(f.split("/")[-1] in k for k in sigs), (
            "no content signature for %s" % f)
    fallback = _const("_FILE_READ_SIGNATURES_FALLBACK")
    assert fallback, "the fallback literal is gone — an unreadable table would "\
                     "silently disable every file-read proof"


# -- 5. a path traversal has no input field ---------------------------------

PATH_CLASSES = ["path-traversal", "path_traversal", "directory-traversal",
                "Path Traversal"]
# lfi and rfi were in this list until 2026-10-16. They are file reads reached
# through a PARAMETER (`?page=../../etc/passwd`), and listing them as
# path-injecting made the gather gate record input_field as satisfied by the
# endpoint — so it never demanded the parameter for ANY file read.
PARAMETER_FILE_READS = ["lfi", "rfi", "local-file-inclusion", "file-read",
                        "arbitrary-file-read", "remote-file-inclusion"]


@pytest.mark.parametrize("vc", PATH_CLASSES)
def test_path_based_classes_do_not_need_a_parameter(vc):
    """The payload IS the path. Demanding a parameter asks for the impossible.

    CVE-2026-21589 stopped `gather_incomplete:input_field` with 0 iterations
    AFTER everything else was gathered — including the correct webresource
    traversal endpoint — because deep recon honestly reported "only a JWT
    parameter on root path, no forms". It was right: there are no parameters
    in a path traversal.
    """
    m = _vc_mod()
    assert m.path_is_the_field(vc), (
        f"{vc} is not recognised as path-based, so the gather gate will "
        "demand an input_field that cannot exist and block the run")
    # It stays REQUIRED — the endpoint is what satisfies it. Dropping the
    # requirement would let a traversal with no endpoint through the gate
    # with nothing to attack.
    assert m.needs_input_field(vc)


@pytest.mark.parametrize("vc", PARAMETER_FILE_READS)
def test_a_file_read_through_a_parameter_still_needs_one(vc):
    """The other half of the same bug, and the more expensive half: with lfi
    treated as path-injecting, the gate stopped asking for the parameter on
    every classic `?page=` file read and synth guessed it."""
    m = _vc_mod()
    assert m.is_file_read(vc), f"{vc} should still be a file read"
    assert not m.path_is_the_field(vc), (
        f"{vc} injects through a parameter; treating the path as its injection "
        "point is what stopped the gate demanding one")
    assert m.needs_input_field(vc)


def test_the_endpoint_satisfies_the_field_for_path_classes():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_gather_manifest")) or ""
    assert "_vc_path_is_the_field" in src, (
        "the gather manifest does not consult the path-injection predicate")
    i = src.find("_vc_path_is_the_field")
    window = src[i:i + 500]
    assert "path_is_the_field" in window, (
        "the item is satisfied without recording WHY — an operator reading "
        "the manifest cannot tell a real parameter from a path standing in "
        "for one")


def test_injection_classes_still_require_a_parameter():
    """The fix must not let a real injection class through without one."""
    m = _vc_mod()
    for vc in ("sqli", "ssti", "cmdi", "xss", "idor", "ssrf", "xxe"):
        assert not m.path_is_the_field(vc), (
            f"{vc} is treated as path-based — it injects into a parameter or a "
            "body, and skipping input_field for it would synthesise blind")


def test_a_path_class_with_no_endpoint_still_blocks():
    """The endpoint is what satisfies it; with none there is nothing to use."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_gather_manifest")) or ""
    i = src.find("_vc_path_is_the_field")
    cond = src[max(0, i - 120):i + 120]
    assert "endpoint" in cond, (
        "the path-is-the-field rule does not require an endpoint, so a run "
        "with neither a parameter nor a path would report the field gathered")


# -- 6. the class can arrive AFTER the items were decided -------------------

def test_the_path_rule_is_reapplied_when_the_class_arrives_late():
    """Class-dependent items are decided before the class is always known.

    CVE-2026-21589 (2026-10-16, run ..._1792183000): the manifest was built
    while vuln_class was unknown, so `input_field` was recorded "n/a". The LLM
    fallback then set vuln_class=path-traversal, which makes input_field
    REQUIRED, and the stale n/a read as missing. The manifest text prints only
    gathered/missing items, so the gate reported "missing: input_field" for an
    item that did not appear in its own manifest.
    """
    # Structural: find the `if name == "vuln_class"` branch and check the
    # rule is re-applied INSIDE it. A fixed-size window missed the marker by
    # 146 characters once the explanatory comment grew — the same brittleness
    # this suite keeps catching.
    fn = _func("_gather_manifest")
    branch = None
    for node in ast.walk(fn):
        # ast.unparse normalises string quotes to SINGLE, so matching on
        # '"vuln_class"' finds nothing even when the branch is right there.
        if isinstance(node, ast.If) and "vuln_class" in ast.unparse(node.test):
            body = ast.unparse(node.body)
            if "vc = keep" in body:
                branch = body
                break
    assert branch, "no `if name == \"vuln_class\"` branch that updates vc"
    assert "_vc_path_is_the_field" in branch, (
        "the path-is-the-field rule is not re-applied after the class is "
        "learned, so a late vuln_class leaves input_field stuck at n/a and "
        "the gate blocks on an item absent from its own manifest")
    assert "path_is_the_field:after_class" in branch, (
        "the late upgrade does not record a distinct source, so it is "
        "indistinguishable from the one applied at build time")


def _late_upgrade_loop():
    """The `for it in items:` loop that performs the late upgrade.

    Located structurally: a fixed-size window over the source missed this
    marker by 146 characters once the explanatory comment above it grew.
    """
    for node in ast.walk(_func("_gather_manifest")):
        if not isinstance(node, ast.For):
            continue
        if any(isinstance(c, ast.Constant)
               and c.value == "path_is_the_field:after_class"
               for c in ast.walk(node)):
            return node
    return None


def test_the_late_upgrade_needs_an_endpoint():
    """With no endpoint there is nothing to stand in for the parameter."""
    loop = _late_upgrade_loop()
    assert loop is not None, "no late-upgrade loop found"
    # Some branch inside the loop must bail out when the endpoint is absent.
    bail = [n for n in ast.walk(loop)
            if isinstance(n, ast.If)
            and any(isinstance(x, ast.Name) and x.id == "_ep"
                    for x in ast.walk(n.test))
            and any(isinstance(b, (ast.Break, ast.Continue)) for b in n.body)]
    assert bail, (
        "the late upgrade does not require an endpoint, so a run with "
        "neither a parameter nor a path would report the field gathered")


def test_the_late_upgrade_does_not_overwrite_a_real_parameter():
    loop = _late_upgrade_loop()
    assert loop is not None, "no late-upgrade loop found"
    skip = [n for n in ast.walk(loop)
            if isinstance(n, ast.If)
            and any(isinstance(c, ast.Constant) and c.value == "gathered"
                    for c in ast.walk(n.test))
            and any(isinstance(b, (ast.Continue, ast.Break)) for b in n.body)]
    assert skip, (
        "the late upgrade does not skip an already-gathered input_field — it "
        "would overwrite a real parameter the miner found")
