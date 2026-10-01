"""Static-check that every RAG loader honors the no-plaintext-secrets rule.

Rule: `_load_observed_fact_into_rag(source, ip, kind, value, ...)` embeds the
`value` arg into rag_documents.text_chunk. The embedded body is retrievable
by anyone with RAG read access; a plaintext password/token/API-key there is
a credential leak the moment the corpus is backed up or dumped.

This test AST-walks every `_load_<x>_into_rag` function and checks that:
  - no local variable named like a sensitive secret
    (secret, password, pwd, token, api_key, apikey, auth_token, bearer,
     secret_value, plaintext) is passed to _load_observed_fact_into_rag
    AS THE `value` POSITIONAL ARG without being redacted first (replaced
    with a '<known>' / '<invalid>' / '<redacted>' marker).

Sabotage-proven per CLAUDE.md: edit any loader to pass `secret_value`
directly and this test fails by name.
"""
import ast
import re
import pytest

API_PATH = "/opt/rag-scan-stack/app/rag-api/api.py"
SENSITIVE_NAMES = (
    "secret", "secret_value", "plaintext", "password", "pwd", "passphrase",
    "token", "api_key", "apikey", "auth_token", "bearer", "cookie_value",
    "private_key", "privkey",
)
REDACTION_MARKERS = ("<known>", "<invalid>", "<redacted>", "<masked>")


def _parse_api():
    with open(API_PATH) as fh:
        src = fh.read()
    try:
        return ast.parse(src), src
    except SyntaxError as e:
        pytest.fail(f"api.py doesn't parse: {e}")


def test_api_module_parses():
    """Sanity: api.py is well-formed Python."""
    tree, _ = _parse_api()
    assert tree is not None


def _loader_functions(tree):
    """Yield every function matching _load_<x>_into_rag."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and re.match(r"^_load_.+_into_rag$", node.name):
            yield node


def test_every_loader_name_is_known():
    """Confirms we find at least the known loader set. If a new loader is
    added without matching this pattern, add it (or match the pattern)."""
    tree, _ = _parse_api()
    names = sorted(f.name for f in _loader_functions(tree))
    expected_at_least = {
        "_load_observed_fact_into_rag",
        "_load_credential_into_rag",
        "_load_identity_into_rag",
        "_load_verified_technique_into_rag",
        "_load_vuln_finding_into_rag",
        "_load_service_fingerprint_into_rag",
        "_load_discovered_endpoint_into_rag",
        "_load_web_finding_into_rag",
        "_load_api_schema_into_rag",
        "_load_info_disclosure_into_rag",
        "_load_failed_technique_into_rag",
        "_load_subdomain_pattern_into_rag",
        "_load_session_scheme_into_rag",
        "_load_shell_access_into_rag",
    }
    missing = expected_at_least - set(names)
    assert not missing, f"loader names missing (renamed? deleted?): {missing}"


def _call_passes_sensitive_as_value(call, sensitive_param_names):
    """Return the sensitive variable name if the call is
    _load_observed_fact_into_rag(source, ip, kind, VALUE, ...) AND VALUE
    is a bare reference to one of the sensitive_param_names. Else None.
    Positional 4th arg (index 3) OR keyword `value=`."""
    if not isinstance(call.func, ast.Name) or call.func.id != "_load_observed_fact_into_rag":
        return None
    value_node = None
    if len(call.args) >= 4:
        value_node = call.args[3]
    for kw in call.keywords:
        if kw.arg == "value":
            value_node = kw.value
            break
    if value_node is None:
        return None
    if isinstance(value_node, ast.Name) and value_node.id in sensitive_param_names:
        return value_node.id
    # Also catch Subscript: row['password'], row['secret_value'], etc.
    if isinstance(value_node, ast.Subscript):
        key = value_node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if key.value.lower() in SENSITIVE_NAMES:
                return f"<subscript[{key.value!r}]>"
    return None


def test_no_loader_embeds_plaintext_secret():
    """For each loader function, walk its body: find any local variable
    assigned from a param matching SENSITIVE_NAMES, then confirm it's
    NOT passed as the `value` positional arg to _load_observed_fact_into_rag.
    """
    tree, src = _parse_api()
    violations = []
    for fn in _loader_functions(tree):
        if fn.name == "_load_observed_fact_into_rag":
            continue  # the primitive itself — no sensitive-arg contract
        # Collect param names that LOOK sensitive
        param_names = {a.arg for a in fn.args.args}
        sensitive_params = {p for p in param_names
                             if any(s in p.lower() for s in SENSITIVE_NAMES)}
        # Walk the function body
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            hit = _call_passes_sensitive_as_value(node, sensitive_params | set(SENSITIVE_NAMES))
            if hit:
                violations.append(f"{fn.name}:{node.lineno}: embeds `{hit}` as value "
                                   f"(use a <known>/<redacted> marker instead)")
    assert not violations, (
        "RAG loader(s) embedding plaintext secrets:\n  " + "\n  ".join(violations)
    )


def test_credential_loader_uses_known_marker():
    """Belt-and-suspenders: _load_credential_into_rag source must contain a
    `<known>` or `<invalid>` marker literal (proves the author redacted the
    plaintext). If this test fails after an edit, the author bypassed the
    redaction convention and the AST walker above probably also fired."""
    with open(API_PATH) as fh:
        src = fh.read()
    tree = ast.parse(src)
    for fn in _loader_functions(tree):
        if fn.name != "_load_credential_into_rag":
            continue
        body_src = ast.get_source_segment(src, fn) or ""
        has_marker = any(m in body_src for m in REDACTION_MARKERS)
        assert has_marker, (
            "_load_credential_into_rag must redact the plaintext secret with one of "
            f"{REDACTION_MARKERS} — the plaintext stays in credential_findings."
            "recovered_secret, NEVER in rag_documents"
        )
        return
    pytest.fail("_load_credential_into_rag not found in api.py (renamed?)")
