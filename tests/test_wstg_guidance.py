"""WSTG guidance retrieval must return whole documents, not spliced fragments.

Run on demand:

    pytest tests/test_wstg_guidance.py -v
    RAG_API=https://localhost:3002/api pytest tests/test_wstg_guidance.py

WHY THIS EXISTS
---------------
`_wstg_guidance_text()` looks a test's methodology up by WSTG id. That exact
lookup is DELIBERATE and is not a weak substitute for vector search: the caller
already knows which test it wants, and a nearest-neighbour query would happily
return WSTG-CRYP-02's prose when asked for CRYP-01. Semantic ranking belongs
inside a document, not across them.

What was wrong was the paging. `ORDER BY chunk_id LIMIT 6` applied across the
whole match set rather than per document, and:

  * `WSTG-INPV-13` matches TWO ingested documents — "Testing for Buffer Overflow"
    and "Testing for Format String Injection". The operator got chunk 0 of the
    first joined to chunks 0-4 of the second by a bare newline, with nothing
    marking the boundary: one test's methodology read as if it were the other's.
  * 20 of 116 ingested documents have more than 6 chunks, so their guidance was
    silently truncated mid-document.

Both are invisible to a caller — the response looks like prose either way, which
is exactly why an LLM consuming it would never flag the problem.

Skips cleanly when the stack is not up.
"""
import os
import re

import pytest

requests = pytest.importorskip("requests")
requests.packages.urllib3.disable_warnings()

BASE = os.environ.get("RAG_API", "https://localhost:3002/api")

#: Matches two distinct ingested documents. The whole point of the fix.
AMBIGUOUS_ID = "WSTG-INPV-13"


def _guidance(wstg_id):
    try:
        r = requests.get(f"{BASE}/rag/wstg/{wstg_id}", verify=False, timeout=60)
    except requests.RequestException as exc:
        pytest.skip(f"rag-api not reachable at {BASE}: {exc}")
    if r.status_code in (502, 503, 504):
        pytest.skip(f"upstream not ready ({r.status_code})")
    assert r.status_code == 200, r.text[:300]
    return r.json().get("guidance") or ""


#: WSTG ids whose ingested document is a HEADER ONLY — category + source line and
#: no methodology. The operator is handed these as "guidance", and the Tier-4
#: checklist renders them as if they were instructions.
#:
#: They are upstream/ingest gaps, not retrieval bugs, and are listed so they are
#: VISIBLE: this list may shrink, never grow. WSTG-INPV-13 Buffer Overflow being
#: one of them is why splicing it ahead of Format String Injection was so
#: misleading — a near-empty header followed by another test's real prose.
KNOWN_STUB_DOCS = {
    "WSTG-INFO-09", "WSTG-CLNT-08", "WSTG-ERRH-02", "WSTG-INPV-13",
    "WSTG-INPV-03", "WSTG-IDNT-05", "WSTG-CONF-08", "WSTG-ATHN-01",
}


def test_guidance_is_returned_at_all():
    """A test with real ingested prose comes back with real prose."""
    g = _guidance("WSTG-SESS-01")
    assert len(g) > 200, f"suspiciously short guidance ({len(g)} chars) — is the corpus ingested?"


def test_the_stub_list_does_not_grow():
    """A ratchet on ingest quality. 8 of 116 documents carry no methodology; a
    ninth means the WSTG ingest regressed, and nothing else would notice because
    the response still looks like prose."""
    thin = []
    for wstg_id in sorted(KNOWN_STUB_DOCS | {"WSTG-SESS-01", "WSTG-CRYP-01",
                                             "WSTG-BUSL-01", "WSTG-ATHZ-01"}):
        g = _guidance(wstg_id)
        if len(g) < 400 and wstg_id not in KNOWN_STUB_DOCS:
            thin.append((wstg_id, len(g)))
    assert not thin, (
        f"these documents are now header-only stubs and were not before: {thin}"
    )


def test_two_documents_sharing_an_id_are_not_spliced():
    """The regression. Both documents must be present AND separated."""
    g = _guidance(AMBIGUOUS_ID)
    low = g.lower()
    assert "buffer overflow" in low, "the Buffer Overflow document is missing"
    assert "format string" in low, "the Format String document is missing"
    assert "\n\n---\n\n" in g, (
        "two distinct documents were concatenated with no separator — a reader "
        "cannot tell where one test's methodology ends and the other begins"
    )


def test_each_document_keeps_its_own_heading():
    """Provenance: a reader must be able to attribute the prose to a test."""
    g = _guidance(AMBIGUOUS_ID)
    heads = [h for h in re.findall(r"^#+ .*$", g, re.M) if AMBIGUOUS_ID in h]
    assert len(heads) >= 2, (
        f"expected a heading per document, found {len(heads)}: {heads}"
    )


def test_a_long_document_is_not_cut_at_six_chunks():
    """WSTG-INPV-23 (Insecure Deserialization) has 10 ingested chunks; the old
    LIMIT 6 truncated it."""
    g = _guidance("WSTG-INPV-23")
    assert len(g) > 3000, (
        f"WSTG-INPV-23 guidance is only {len(g)} chars — the per-document chunk "
        "limit is truncating a long document again"
    )


@pytest.mark.parametrize("wstg_id", ["WSTG-CRYP-01", "WSTG-SESS-01", "WSTG-BUSL-01"])
def test_an_unambiguous_id_returns_exactly_one_document(wstg_id):
    """Exact matching must not drag in neighbours: asking for CRYP-01 must not
    return CRYP-02's methodology."""
    g = _guidance(wstg_id)
    assert g, f"no guidance for {wstg_id}"
    others = {m for m in re.findall(r"WSTG-[A-Z]+-\d+", g)} - {wstg_id}
    # A document may legitimately cross-reference another test; it must not be
    # the SUBJECT of a heading.
    bad = [h for h in re.findall(r"^#+ .*$", g, re.M)
           if any(o in h for o in others) and wstg_id not in h]
    assert not bad, f"{wstg_id} guidance carries another test's heading: {bad}"
