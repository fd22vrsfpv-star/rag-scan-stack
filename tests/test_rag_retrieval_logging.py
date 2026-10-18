"""What the agents RECALL must be on the record.

Two gaps, measured 2026-10-17:

  * `rag_query_log` had exactly ONE writer — the operator's manual `/ask`. All
    498 rows were hand-typed questions, so every agent-side retrieval through
    `/rag/knowledge/search` (what `search_knowledge_base` calls) was invisible
    and a planning decision could not be traced back to what justified it.
  * The PoC path's `recall_context` trace recorded
    `composed recall block (3779 chars)` and nothing else. Of 682 PoC trace
    files, 13 carried that line at all. A character count cannot tell you
    whether the block held the right credential or a stale lesson.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_rag_retrieval_logging.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
MIGRATION = REPO / "scan_recommender" / "migrations" / "add_rag_feedback_loop.sql"
RUNTIME_DDL = REPO / "scan_recommender" / "exploits_rag.py"


@pytest.fixture(scope="module")
def tree():
    return ast.parse(API.read_text(encoding="utf-8"))


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not found in api.py")


def _calls(node):
    return {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            for n in ast.walk(node) if isinstance(n, ast.Call)}


class TestTheKnowledgeSearchIsLogged:
    def test_the_endpoint_logs_its_retrieval(self, tree):
        fn = _func(tree, "rag_knowledge_search")
        assert "_rag_log_retrieval" in _calls(fn), (
            "the planner's retrieval is not recorded, so a decision cannot be "
            "traced back to what it recalled")

    def test_logging_cannot_break_retrieval(self, tree):
        """Observability must never take down the thing it observes."""
        fn = _func(tree, "rag_knowledge_search")
        guarded = [h for n in ast.walk(fn) if isinstance(n, ast.Try)
                   for h in [n] if "_rag_log_retrieval" in _calls(n)]
        assert guarded, "the log call must sit inside a try/except"

    def test_the_query_selects_the_document_id(self, tree):
        """Without the id the log says how well it matched but not what
        came back, which is the half that matters."""
        fn = _func(tree, "rag_knowledge_search")
        sql = [n.value for n in ast.walk(fn)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and "rag_documents" in n.value]
        assert sql, "the rag_documents SELECT was not found"
        assert any("id" in s.split("FROM")[0].split() or "SELECT id" in s
                   for s in sql), "the SELECT must return id"

    def test_the_caller_is_recorded(self, tree):
        """A planner recall, an agent tool call and an operator poking the
        endpoint must be distinguishable, or the log says only that
        'something' retrieved this."""
        body = _func(tree, "rag_knowledge_search")
        src = ast.dump(body)
        assert "caller" in src, "the source label must carry the caller"
        fields = {t.target.id for t in ast.walk(tree)
                  if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)}
        assert "caller" in fields, "KnowledgeSearchBody must declare `caller`"


class TestTheDocumentIdColumnExists:
    """rag_documents.id is a uuid; top_k_chunk_ids is bigint[] and belongs to
    the exploit_chunks corpus. Casting between them would misreport which
    corpus answered."""

    def test_both_ddl_sites_declare_it(self):
        for path in (MIGRATION, RUNTIME_DDL):
            text = path.read_text(encoding="utf-8")
            assert "top_k_doc_ids" in text, (
                f"{path.name} does not declare top_k_doc_ids — the table is "
                "defined in more than one place and they must agree")

    def test_existing_databases_get_an_alter(self):
        text = MIGRATION.read_text(encoding="utf-8")
        assert "ADD COLUMN IF NOT EXISTS top_k_doc_ids" in text, (
            "a CREATE TABLE IF NOT EXISTS will not add a column to a table "
            "that already exists; existing databases need the ALTER")

    def test_it_is_a_uuid_array_not_a_bigint_array(self):
        text = MIGRATION.read_text(encoding="utf-8")
        line = [l for l in text.splitlines() if "top_k_doc_ids" in l and "uuid" in l]
        assert line, "top_k_doc_ids must be uuid[] to hold rag_documents.id"


class TestTheRecallBlockReportsItsSources:
    def test_the_manifest_helper_exists(self, tree):
        _func(tree, "_recall_manifest")

    def test_compose_returns_text_and_manifest_on_every_path(self, tree):
        """A bare `return ""` on one path would break the caller's unpack."""
        fn = _func(tree, "_compose_recall_context")
        returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value]
        assert returns, "no return found"
        for r in returns:
            assert isinstance(r.value, ast.Tuple), (
                "every return must be (text, manifest); a bare string on one "
                "path raises at the call site, not here")
            assert len(r.value.elts) == 2

    def test_the_trace_records_the_sources_not_just_a_size(self, tree):
        """`composed recall block (3779 chars)` was the entire record."""
        fn = _func(tree, "_synthesize_cve_poc")
        traces = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                  and (getattr(n.func, "id", None) == "_poc_trace")
                  and any(isinstance(a, ast.Constant) and a.value == "recall_context"
                          for a in n.args)]
        assert traces, "the recall_context trace is gone"
        assert any(any(k.arg == "extra" for k in t.keywords) for t in traces), (
            "the trace must carry structured `extra` naming each source; a "
            "character count cannot say what was recalled")

    def test_all_three_outcomes_are_labelled(self, tree):
        """hit / empty / not_queried must each carry `outcome`.

        The populated branch originally set no label, so a successful recall
        read as None and any aggregate over the field counted the hits as
        unknowns — the measurement problem one level up from the one this
        whole change was built to fix.
        """
        fn = _func(tree, "_synthesize_cve_poc")
        labels = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if (isinstance(k, ast.Constant) and k.value == "outcome"
                            and isinstance(v, ast.Constant)):
                        labels.add(v.value)
        assert {"hit", "empty", "not_queried"} <= labels, (
            f"every recall outcome must be labelled; found {sorted(labels)}")

    def test_disabled_is_not_reported_as_empty(self, tree):
        """THREE outcomes at this level too.

        The first version of this fix returned ("", []) both when the feature
        flag was off and when every source genuinely returned nothing, and
        traced both as "every source returned nothing" — recording a disabled
        memory as an exhausted one. Caught in review, not by a test, which is
        why there is now a test.
        """
        fn = _func(tree, "_compose_recall_context")
        rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value]
        dumps = [ast.dump(r) for r in rets]
        assert any("not_queried" in d for d in dumps), (
            "the disabled path must carry a reason, or it is indistinguishable "
            "from an empty result")
        caller = _func(tree, "_synthesize_cve_poc")
        cdump = ast.dump(caller)
        assert "not_queried" in cdump, (
            "the caller must branch on the reason; a composer that reports it "
            "to a caller that ignores it changes nothing")

    def test_an_empty_recall_is_still_traced(self, tree):
        """Three outcomes: recalled something, recalled nothing, never looked.
        Only tracing the non-empty case made the last two identical."""
        fn = _func(tree, "_synthesize_cve_poc")
        traces = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                  and (getattr(n.func, "id", None) == "_poc_trace")
                  and any(isinstance(a, ast.Constant) and a.value == "recall_context"
                          for a in n.args)]
        assert len(traces) >= 2, (
            "both the populated and the empty case must emit a trace row, or "
            "'recalled nothing' is indistinguishable from 'never ran'")
