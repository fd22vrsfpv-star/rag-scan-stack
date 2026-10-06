"""Guard the AWS error-surfacing behaviour.

Before 2026-10-06, a `boto3.ClientError` from the EC2-create path escaped
FastAPI as a bare `500 Internal Server Error`. The operator saw no reason;
the real cause ("AuthFailure", "InvalidClientTokenId", missing permission)
was only in `docker logs node-manager`. This file fails if that behaviour
is reintroduced.

Run on demand:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest fastapi botocore && \
      PYTHONPATH=/work/node_manager python -m pytest tests/test_aws_error_surfacing.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import HTTPException


REPO = Path(__file__).resolve().parent.parent
NM = REPO / "node_manager" / "node_manager.py"


# ── unit: the converter preserves AWS code + message ──────────────────────


def test_client_error_to_http_extracts_aws_message():
    """The helper lives in node_manager.node_manager; stand it up in a thin
    namespace so this test can run without pulling the full service."""
    from botocore.exceptions import ClientError

    # Reproduce the helper's logic by importing it from source. Avoid importing
    # the full module (it opens DB connections at import time).
    src = NM.read_text()
    m = re.search(
        r"def _aws_client_error_to_http\(e, operation: str = \"AWS call\"\) -> HTTPException:.*?return HTTPException\(400, [^\n]+\)",
        src, re.S,
    )
    assert m, "helper _aws_client_error_to_http missing from node_manager"
    ns: dict = {"HTTPException": HTTPException}
    exec("import functools\n" + m.group(0), ns)
    helper = ns["_aws_client_error_to_http"]

    e = ClientError(
        error_response={"Error": {"Code": "AuthFailure", "Message": "AWS was not able to validate the provided access credentials"}},
        operation_name="DescribeKeyPairs",
    )
    exc = helper(e, "DescribeKeyPairs")
    assert isinstance(exc, HTTPException)
    assert exc.status_code == 400
    assert "AuthFailure" in exc.detail
    assert "AWS was not able to validate" in exc.detail
    assert "DescribeKeyPairs" in exc.detail


# ── structural: the decorator still fences /cloud/aws/create ──────────────


def test_create_handler_is_decorated_with_error_boundary():
    """Removing @_aws_error_boundary from /cloud/aws/create reintroduces the
    silent-500 bug — this test fails before the handler definition."""
    src = NM.read_text()
    # The decorator stack must appear between the route decorator and the def.
    m = re.search(
        r'@app\.post\("/cloud/aws/create"\)[^\n]*\n@_aws_error_boundary\s*\nasync def create_ec2_instance',
        src,
    )
    assert m, (
        "/cloud/aws/create must carry @_aws_error_boundary immediately after "
        "@app.post so ClientError surfaces as 400 instead of leaking as 500"
    )


def test_aws_test_endpoint_is_decorated_too():
    """The /cloud/aws/test endpoint has the same requirement — Save-time
    validation that doesn't surface the real error defeats its purpose."""
    src = NM.read_text()
    m = re.search(
        r'@app\.post\("/cloud/aws/test"\)[^\n]*\n@_aws_error_boundary\s*\nasync def test_aws_credentials',
        src,
    )
    assert m, (
        "/cloud/aws/test must carry @_aws_error_boundary so a bad key surfaces "
        "to Settings → API Keys instead of appearing as a bare 500"
    )


# ── structural: DO list_public_keys does not reuse IGNORE_SUFFIXES ────────


def test_do_list_public_keys_does_not_strip_pub_suffix():
    """`.pub` IS the public-key suffix; the old impl filtered them out, so the
    Public Key dropdown on New Droplet rendered empty."""
    import ast as _ast

    body = (REPO / "node_manager" / "ssh_manager.py").read_text()
    tree = _ast.parse(body)
    # Find the function (static method on SSHManager) and inspect its source.
    func_src: str | None = None
    for node in _ast.walk(tree):
        if isinstance(node, _ast.FunctionDef) and node.name == "list_public_keys":
            func_src = _ast.get_source_segment(body, node)
            break
    assert func_src, "list_public_keys missing from ssh_manager.py"
    # Match the attribute lookup pattern, not just the identifier (so a docstring
    # that mentions IGNORE_SUFFIXES to explain WHY it was removed is OK).
    assert "SSHManager.IGNORE_SUFFIXES" not in func_src and "self.IGNORE_SUFFIXES" not in func_src, (
        "list_public_keys must not filter by IGNORE_SUFFIXES — that set contains "
        "`.pub`, which is the very suffix the dropdown needs to include"
    )
