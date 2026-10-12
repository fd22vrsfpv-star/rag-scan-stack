"""Shell paren counter + template var resolution in build-PoC.

Guards:
  _poc_shell_syntax_check — must NOT reject SQL payloads in curl data args
  _assemble_from_cve_spec — must resolve {hostid}/{scriptid}/{sessionid}
                            from confirmed_facts before building the curl cmd
  _post_run_review        — must detect repeated same-strategy failures
"""
import subprocess
import pytest

from _container import container_python, service_healthy


def _rag_api_up():
    # Shared probe — see tests/_container.py. Was a private
    # subprocess.run(['docker','exec',...]) copy in nine modules.
    return service_healthy("rag-api")


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    # Shared runner — see tests/_container.py::container_python.
    return container_python(py_snippet)


class TestShellParenCounter:
    """The shell-syntax paren counter must skip curl data arguments so that
    SQL injection payloads with intentionally unbalanced parens pass."""

    def test_sqli_in_data_urlencode_passes(self):
        """A curl --data-urlencode with 1') UNION SELECT must not be rejected."""
        py = r"""
import sys; sys.path.insert(0, '/app')
from api import _poc_shell_syntax_check
cmd = "curl -sk 'http://172.19.0.17:8000/wp-admin/admin-ajax.php' --data-urlencode \"locations_ids[]=1') ; SELECT 'POCz6ef3' /*\" --data-urlencode 'action=w2dc_get_widget_listings_by_location'"
ok, msg = _poc_shell_syntax_check(cmd)
assert ok, f"should pass but got: {msg}"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_sqli_in_d_flag_passes(self):
        """A curl -d with unbalanced SQL parens must pass."""
        py = r"""
import sys; sys.path.insert(0, '/app')
from api import _poc_shell_syntax_check
cmd = "curl -sk 'http://target:8000/api' -d 'id=1) UNION SELECT SLEEP(5)-- -'"
ok, msg = _poc_shell_syntax_check(cmd)
assert ok, f"should pass but got: {msg}"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_sqli_data_equals_form_passes(self):
        """A curl --data=VALUE form must also be skipped."""
        py = r"""
import sys; sys.path.insert(0, '/app')
from api import _poc_shell_syntax_check
cmd = "curl -sk 'http://target:8000/api' --data='id=1) OR 1=1--'"
ok, msg = _poc_shell_syntax_check(cmd)
assert ok, f"should pass but got: {msg}"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_unbalanced_shell_parens_still_rejected(self):
        """Actual unbalanced shell syntax must still be caught."""
        py = r"""
import sys; sys.path.insert(0, '/app')
from api import _poc_shell_syntax_check
cmd = "echo $(curl -sk 'http://target:8000/api'"
ok, msg = _poc_shell_syntax_check(cmd)
assert not ok, f"should reject but passed"
assert "unbalanced" in msg.lower() or "quotation" in msg.lower()
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_balanced_subshell_passes(self):
        """A balanced $(curl ...) subshell must pass."""
        py = r"""
import sys; sys.path.insert(0, '/app')
from api import _poc_shell_syntax_check
cmd = "NONCE=$(curl -sk 'http://target:8000/' | grep -oP 'nonce\":\"\\K[a-f0-9]+'); curl -sk 'http://target:8000/api' -d \"nonce=$NONCE\""
ok, msg = _poc_shell_syntax_check(cmd)
assert ok, f"should pass but got: {msg}"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err


class TestTemplateVarResolution:
    """_assemble_from_cve_spec must resolve template vars from confirmed_facts."""

    def test_resolve_vars_function_exists(self):
        """The _resolve_vars local function should exist inside _assemble_from_cve_spec."""
        py = r"""
import sys, ast; sys.path.insert(0, '/app')
with open('/app/api.py') as f:
    src = f.read()
tree = ast.parse(src)
found = False
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == '_assemble_from_cve_spec':
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef) and child.name == '_resolve_vars':
                found = True
                break
assert found, "_resolve_vars not found inside _assemble_from_cve_spec"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_confirmed_facts_query_present(self):
        """The function must query confirmed_facts for template values."""
        py = r"""
import sys, inspect; sys.path.insert(0, '/app')
from api import _assemble_from_cve_spec
src = inspect.getsource(_assemble_from_cve_spec)
assert 'confirmed_facts' in src, "must query confirmed_facts"
assert 'object_id' in src, "must handle object_id claim_type"
assert 'token_valid' in src, "must handle token_valid claim_type"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err


class TestRepeatedStrategyDetection:
    """_post_run_review must detect repeated same-strategy failures."""

    def test_review_checks_prior_attempts(self):
        """The review agent must query build_poc_attempts for prior runs."""
        py = r"""
import sys, inspect; sys.path.insert(0, '/app')
from api import _post_run_review
src = inspect.getsource(_post_run_review)
assert 'build_poc_attempts' in src, "must check build_poc_attempts"
assert 'repeated_strategy' in src, "must flag repeated_strategy"
assert 'stage_reached' in src, "must compare stage_reached"
assert 'stop_reason' in src, "must compare stop_reason"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err


class TestRefutedFactsFeedback:
    """The refine loop must feed refuted confirmed_facts back to the LLM
    so it doesn't retry endpoints/sids proven wrong."""

    def test_refine_loop_queries_refuted_facts(self):
        """_run_refine_poc must query confirmed_facts for refuted entries."""
        py = r"""
import sys, inspect; sys.path.insert(0, '/app')
from api import _run_refine_poc
src = inspect.getsource(_run_refine_poc)
assert "refuted" in src, "must query refuted confirmed_facts"
assert "KNOWN-BAD" in src or "KNOWN_BAD" in src, "must label them as known-bad"
assert "_refuted_note" in src, "must build a refuted note for the prompt"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err

    def test_refuted_note_in_refine_prompt(self):
        """The refuted note must appear in the refine prompt string."""
        py = r"""
import sys, inspect; sys.path.insert(0, '/app')
from api import _run_refine_poc
src = inspect.getsource(_run_refine_poc)
# The refuted note must be interpolated into rprompt
assert '_refuted_note' in src, "refuted note must exist"
# It must appear in the prompt construction (the f-string that builds rprompt)
idx_rprompt = src.index('rprompt')
idx_refuted = src.index('_refuted_note', idx_rprompt)
assert idx_refuted > idx_rprompt, "refuted note must be in rprompt"
print('OK')
"""
        out, err, rc = _in_container(py)
        assert rc == 0 and 'OK' in out, err
