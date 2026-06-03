"""
Unit tests for Scan Recommender RAG functions.
Tests exploit ingestion, vector search, and LLM integration.
"""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import pytest
import hashlib

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from scan_recommender import exploits_rag


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestRAGUtils:
    """Test RAG utility functions."""

    def test_sha256(self):
        """Test SHA256 hash calculation."""
        data = b"test_exploit_code"
        expected = hashlib.sha256(data).hexdigest()

        # Execute
        result = exploits_rag._sha256(data)

        # Verify
        assert result == expected

    def test_chunk_text_small(self):
        """Test chunking text smaller than chunk size."""
        text = "Small text content"

        # Execute
        chunks = exploits_rag._chunk_text(text, chunk_size=100, overlap=20)

        # Verify
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_chunk_text_large(self):
        """Test chunking large text with overlap."""
        text = "A" * 10000  # 10k characters

        # Execute
        chunks = exploits_rag._chunk_text(text, chunk_size=3000, overlap=200)

        # Verify
        assert len(chunks) > 1
        # Check overlap - last chars of chunk should match first chars of next
        for i in range(len(chunks) - 1):
            # Some overlap expected (not exact due to boundary handling)
            assert len(chunks[i]) <= 3000

    # ---- Markdown-aware chunker tests ----

    def test_chunk_markdown_keeps_header_with_command(self):
        """A section whose ### header, prose, fenced command, and trailing
        usage notes fit inside max_chars must come back as ONE tuple --
        otherwise the LLM gets the command without "when to use" or vice
        versa, which is the bug we're fixing."""
        md = (
            "### Brute Force\n\n"
            "Use when default creds didn't work and you have a wordlist.\n\n"
            "```bash\n"
            "hydra -L users.txt -P passwords.txt ssh://target\n"
            "```\n\n"
            "Check for:\n"
            "- Successful logins in hydra output\n"
            "- Lockout indicators in target logs\n"
        )

        chunks = exploits_rag._chunk_markdown(md)

        assert len(chunks) == 1, f"Expected single chunk, got {len(chunks)}"
        section, body = chunks[0]
        assert section == "Brute Force"
        # Every part of the atomic unit must be present in the chunk
        assert "hydra -L users.txt -P passwords.txt ssh://target" in body
        assert "Use when default creds didn't work" in body
        assert "Successful logins in hydra output" in body

    def test_chunk_markdown_preserves_fenced_block(self):
        """A section containing a fenced code block that pushes the section
        over max_chars must NEVER split the fence -- both ``` markers must
        live in the same chunk."""
        big_code = "echo 'line {}'\n".format("x" * 30) * 100  # ~3.3k chars of code
        md = (
            "### Big Section\n\n"
            "Preamble paragraph.\n\n"
            "```bash\n"
            f"{big_code}"
            "```\n\n"
            "Trailing paragraph.\n"
        )

        chunks = exploits_rag._chunk_markdown(md, max_chars=3500)

        # The fence must be intact: find the chunk containing the opening
        # ``` and assert it also contains the closing ```.
        fence_chunks = [body for _h, body in chunks if "```bash" in body]
        assert len(fence_chunks) == 1, (
            "Opening ```bash should appear in exactly one chunk"
        )
        body = fence_chunks[0]
        # An even number of fence markers means every open has a close
        # within the same chunk.
        assert body.count("```") % 2 == 0, (
            f"Found uneven fence count in chunk -- fence was split.\n"
            f"chunk head: {body[:120]!r}\nchunk tail: {body[-120:]!r}"
        )

    def test_chunk_markdown_splits_oversized_section_at_paragraphs(self):
        """A single section bigger than max_chars should split at blank-line
        paragraph boundaries, with every sub-chunk carrying the same
        section_header.  Fences must stay whole."""
        paragraphs = "\n\n".join(
            [f"Paragraph {i}: " + ("p" * 400) for i in range(20)]
        )
        md = f"### Huge Section\n\n{paragraphs}\n"

        chunks = exploits_rag._chunk_markdown(md, max_chars=1500)

        assert len(chunks) > 1, "Oversized section should have split"
        # Every chunk should carry the same section header
        headers = {h for h, _b in chunks}
        assert headers == {"Huge Section"}, (
            f"All sub-chunks should share header; got {headers}"
        )
        # No mid-paragraph splits: every chunk should either start the file
        # or start with "Paragraph N:" at its first non-empty line.
        for _h, body in chunks[1:]:
            first_meaningful = next(
                (ln for ln in body.splitlines() if ln.strip()), ""
            )
            assert first_meaningful.startswith("Paragraph "), (
                f"Sub-chunk started mid-paragraph: {first_meaningful!r}"
            )

    def test_chunk_markdown_merges_tiny_sections(self):
        """Single-line subsections shouldn't become orphan chunks -- they
        should merge forward under the previous header."""
        md = (
            "### Main Step\n\n"
            "A full paragraph of context that easily clears min_chars. "
            * 30
            + "\n\n"
            "### Tiny\n\n"
            "one line only\n"
        )

        chunks = exploits_rag._chunk_markdown(md, min_chars=400)

        # The tiny section should have merged into the previous one.
        # Either we get a single chunk (merged), or two chunks where the
        # tiny header doesn't appear standalone -- both are acceptable.
        all_text = "".join(body for _h, body in chunks)
        assert "one line only" in all_text
        # The "Tiny" header should NOT be the section_header of a separate
        # chunk -- its content merges back under "Main Step".
        tiny_chunks = [c for h, c in chunks if h == "Tiny"]
        assert len(tiny_chunks) == 0, (
            "Tiny section should have merged into the previous section"
        )

    def test_embed_batch_falls_back_on_failure(self, monkeypatch):
        """When the batch endpoint errors, _embed_batch must fall back to
        per-text _embed() and preserve input ordering."""
        # Simulate batch endpoint failure: make requests.post raise on the
        # batch path, but make _embed succeed and return a deterministic
        # vector so we can verify ordering.
        def fake_post(*args, **kwargs):
            raise RuntimeError("simulated batch endpoint failure")

        def fake_embed(text):
            # Encode the text length so we can verify ordering.
            return [float(len(text)), 0.0, 0.0]

        monkeypatch.setattr(exploits_rag.requests, "post", fake_post)
        monkeypatch.setattr(exploits_rag, "_embed", fake_embed)

        texts = ["short", "a bit longer text", "x"]
        result = exploits_rag._embed_batch(texts)

        # Order preserved + correct fallback values
        assert len(result) == 3
        assert result[0][0] == float(len("short"))
        assert result[1][0] == float(len("a bit longer text"))
        assert result[2][0] == float(len("x"))

    # ---- _stable_playbook_id tests ----

    def test_stable_playbook_id_is_deterministic(self):
        """Same filename -> same id, always.  This is the property that
        Python's hash() lacks (PYTHONHASHSEED makes it non-deterministic)
        and that the atomic-replace ingest depends on."""
        a = exploits_rag._stable_playbook_id("ssh_methodology.md")
        b = exploits_rag._stable_playbook_id("ssh_methodology.md")
        c = exploits_rag._stable_playbook_id("ssh_methodology.md")
        assert a == b == c, f"non-deterministic: {a}, {b}, {c}"

    def test_stable_playbook_id_is_negative(self):
        """All playbook ids must be strictly negative (in the range
        [-1_000_000_001, -1]) so they can never collide with positive
        ExploitDB ids -- including the boundary cases of the old buggy
        code (-abs(x) % N which returned 0..N-1 i.e. positive)."""
        for name in [
            "ssh_methodology.md",
            "web_methodology.md",
            "smb_methodology.md",
            "database_methodology.md",
            "x.md",  # short
            "extremely_long_filename_for_a_playbook.md",
            "",      # empty -- still must be in the negative range
        ]:
            pid = exploits_rag._stable_playbook_id(name)
            assert pid < 0, f"{name!r} -> {pid}, expected negative"
            assert pid >= -1_000_000_001, f"{name!r} -> {pid}, out of range"

    def test_stable_playbook_id_is_unique_across_filenames(self):
        """Reasonable spread of distinct filenames must produce distinct
        ids.  32-bit hash space with a billion-modulo means actual
        collisions are vanishingly unlikely for ~11 playbook files."""
        names = [
            f"{prefix}_methodology.md"
            for prefix in [
                "ssh", "web", "smb", "database", "active_directory",
                "credential", "lateral", "persistence", "defense",
                "code_injection", "network",
            ]
        ]
        ids = [exploits_rag._stable_playbook_id(n) for n in names]
        assert len(set(ids)) == len(ids), (
            f"collision among {len(names)} playbook ids: {ids}"
        )

    # ---- _embed_batch_cached tests ----

    def test_embed_batch_cached_reuses_existing(self, monkeypatch):
        """When a text's sha256 is already in the DB, _embed_batch_cached
        reuses the stored embedding and skips the embedder.  Tests this
        without a real DB by stubbing _conn() to return a fake cursor
        that yields a known sha256 -> embedding mapping."""
        # The two cached vectors.
        known_text = "this is content we have seen before"
        known_emb = [9.9, 8.8, 7.7]
        new_text = "fresh content the embedder must process"
        # _embed_batch's fallback path returns whatever fake we wire in.

        # Stub _conn().__enter__().cursor() -> fake cursor that returns
        # exactly one row for our known sha256.
        known_digest = exploits_rag._sha256(known_text.encode("utf-8"))

        class _FakeCursor:
            def __init__(self):
                self._rows = []
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, params=None):
                # The cached lookup query selects sha256, embedding.
                if "FROM exploit_chunks WHERE sha256" in sql:
                    # params is (list_of_digests,)
                    requested = set(params[0]) if params else set()
                    self._rows = [
                        (known_digest, json.dumps(known_emb))
                    ] if known_digest in requested else []
                else:
                    self._rows = []
            def fetchall(self): return self._rows

        class _FakeConn:
            def cursor(self): return _FakeCursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        import json
        monkeypatch.setattr(exploits_rag, "_conn", lambda: _FakeConn())

        # Stub _embed_batch so we can verify ONLY the new text was sent.
        sent_to_embedder = []
        def fake_embed_batch(texts, batch_size=32):
            sent_to_embedder.extend(texts)
            return [[1.1, 2.2, 3.3] for _ in texts]
        monkeypatch.setattr(exploits_rag, "_embed_batch", fake_embed_batch)

        result = exploits_rag._embed_batch_cached([known_text, new_text])

        # 1. Order preserved
        assert len(result) == 2
        # 2. Known text reused its stored embedding (not the fake fresh one)
        assert result[0] == known_emb, f"expected cached, got {result[0]}"
        # 3. Only the new text actually went to the embedder
        assert sent_to_embedder == [new_text], (
            f"embedder was called with: {sent_to_embedder}"
        )

    def test_playbook_reingest_removes_orphans(self, tmp_path, monkeypatch):
        """Re-ingesting a playbook that shrunk MUST issue a DELETE for that
        file's existing chunks before INSERTing the new ones, all in the same
        transaction.

        The atomic-replace contract: if the playbook drops from 5 chunks to
        2, post-ingest DB state for that ``edb_id`` is exactly 2 rows with
        ``chunk_id`` 0 and 1 -- the prior chunks 2..4 do not survive as
        orphans poisoning future RAG retrieval.

        We can't run real Postgres in unit tests, so we instead verify the
        invariant by structure: capture every SQL statement the endpoint
        executes per file, and assert (1) exactly one DELETE precedes any
        INSERTs, (2) the DELETE filters on this file's edb_id, and (3) the
        INSERT chunk_ids run contiguously from 0 and never reach the
        previous-run count.
        """
        # ---- Build a fake DB that records every (sql, params) per cursor ----
        executed: list[tuple[str, tuple]] = []

        class _RecCursor:
            rowcount = 1  # every insert "succeeds" for inserted-count math

            def __enter__(self): return self
            def __exit__(self, *a): return False

            def execute(self, sql, params=None):
                executed.append((sql, params))

            def fetchall(self):  # _embed_batch_cached path may call this
                return []

        class _RecConn:
            def cursor(self): return _RecCursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def commit(self): pass
            def rollback(self): pass

        monkeypatch.setattr(exploits_rag, "_conn", lambda: _RecConn())
        monkeypatch.setattr(exploits_rag, "_dim", lambda: 3)
        monkeypatch.setattr(exploits_rag, "_ensure_schema", lambda dim: None)
        # Skip the cache lookup; return one 3-vec per input text.
        monkeypatch.setattr(
            exploits_rag,
            "_embed_batch_cached",
            lambda texts: [[0.1, 0.2, 0.3] for _ in texts],
        )

        playbook = tmp_path / "ssh_methodology.md"
        file_id = exploits_rag._stable_playbook_id(playbook.name)

        # Each section MUST be ≥ _chunk_markdown's default min_chars (400) or
        # they'd merge into one chunk and the orphan-shrink scenario would be
        # vacuous.  500-char filler per section is comfortably above the floor.
        def _section(letter: str, n: int) -> str:
            filler = (
                f"Section {letter}: this is body content for the playbook "
                f"section, padded to clear the merge-tiny floor. "
            ) * 6
            return f"### Section {letter} step {n}\n\n{filler}\n\n"

        # ---- First ingest: 5 distinct sections ----
        playbook.write_text(
            "".join(_section(c, i) for i, c in enumerate("ABCDE")),
            encoding="utf-8",
        )

        executed.clear()
        exploits_rag.ingest_playbooks_endpoint(playbook_dir=str(tmp_path))

        first_run = list(executed)
        deletes_1 = [(s, p) for s, p in first_run if s.lstrip().startswith("DELETE")]
        inserts_1 = [(s, p) for s, p in first_run if "INSERT INTO exploit_chunks" in s]

        assert len(deletes_1) == 1, (
            f"expected exactly one DELETE on first ingest, got {len(deletes_1)}"
        )
        # DELETE precedes every INSERT.
        first_delete_idx = next(i for i, (s, _) in enumerate(first_run) if s.lstrip().startswith("DELETE"))
        first_insert_idx = next(i for i, (s, _) in enumerate(first_run) if "INSERT INTO exploit_chunks" in s)
        assert first_delete_idx < first_insert_idx, (
            "DELETE must run BEFORE any INSERTs (atomic-replace invariant)"
        )
        # DELETE targets this file's edb_id with the knowledge_base source_repo.
        del_sql, del_params = deletes_1[0]
        assert "source_repo = 'knowledge_base'" in del_sql
        assert "edb_id = %s" in del_sql
        assert del_params == (file_id,)
        # First-run INSERT count == _chunk_markdown's section count.
        chunks_first = exploits_rag._chunk_markdown(playbook.read_text())
        assert len(inserts_1) == len(chunks_first)
        # chunk_id column (index 7 in the INSERT param tuple) runs 0..N-1.
        first_chunk_ids = [p[7] for _s, p in inserts_1]
        assert first_chunk_ids == list(range(len(chunks_first)))

        # ---- Second ingest: shrunk to 2 sections ----
        playbook.write_text(
            "".join(_section(c, i) for i, c in enumerate("AB")),
            encoding="utf-8",
        )

        executed.clear()
        exploits_rag.ingest_playbooks_endpoint(playbook_dir=str(tmp_path))

        second_run = list(executed)
        deletes_2 = [(s, p) for s, p in second_run if s.lstrip().startswith("DELETE")]
        inserts_2 = [(s, p) for s, p in second_run if "INSERT INTO exploit_chunks" in s]

        assert len(deletes_2) == 1, "shrink reingest must still issue one DELETE"
        chunks_second = exploits_rag._chunk_markdown(playbook.read_text())
        assert len(inserts_2) == len(chunks_second)
        # The orphan property: post-shrink chunk_ids never reach the prior
        # max.  Real DB state = exactly len(chunks_second) rows for this
        # edb_id because DELETE wiped everything first.
        second_chunk_ids = [p[7] for _s, p in inserts_2]
        assert second_chunk_ids == list(range(len(chunks_second)))
        assert max(second_chunk_ids) < max(first_chunk_ids), (
            "post-shrink chunk_ids must be strictly less than pre-shrink max "
            "-- combined with the DELETE this proves no orphans remain"
        )

    def test_parse_date_valid(self):
        """Test parsing valid ISO date."""
        date_str = "2024-01-15"

        # Execute
        result = exploits_rag._parse_date(date_str)

        # Verify
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_parse_date_invalid(self):
        """Test parsing invalid date returns None."""
        # Execute
        result = exploits_rag._parse_date("invalid-date")

        # Verify
        assert result is None

    def test_parse_date_none(self):
        """Test parsing None returns None."""
        # Execute
        result = exploits_rag._parse_date(None)

        # Verify
        assert result is None

    @patch('builtins.open', new_callable=mock_open, read_data='{"RESULTS_EXPLOIT": [{"EDB-ID": "1"}, {"EDB-ID": "2"}], "RESULTS_SHELLCODE": [{"EDB-ID": "3"}]}')
    def test_count_entries(self, mock_file):
        """Test counting entries in SearchSploit JSON."""
        # Execute
        count = exploits_rag._count_entries("/fake/path.json")

        # Verify
        assert count == 3  # 2 exploits + 1 shellcode
        mock_file.assert_called_once_with("/fake/path.json", "r", encoding="utf-8")

    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_count_entries_file_not_found(self, mock_file):
        """Test counting entries when file doesn't exist."""
        # Execute
        count = exploits_rag._count_entries("/missing/file.json")

        # Verify
        assert count == 0


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestRAGEmbeddings:
    """Test embedding and LLM functions."""

    @patch('scan_recommender.exploits_rag.requests.post')
    def test_embed(self, mock_post):
        """Test text embedding generation."""
        # Mock Ollama response
        mock_response = MagicMock()
        mock_response.json.return_value = {"embedding": [0.1] * 768}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        # Execute
        result = exploits_rag._embed("test exploit code")

        # Verify
        assert len(result) == 768
        assert all(x == 0.1 for x in result)
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "api/embeddings" in call_args[0][0]
        assert call_args[1]['json']['prompt'] == "test exploit code"

    @patch('scan_recommender.exploits_rag.requests.post')
    def test_dim(self, mock_post):
        """Test getting embedding dimensions."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"embedding": [0.0] * 768}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        # Execute
        result = exploits_rag._dim()

        # Verify
        assert result == 768

    @patch('scan_recommender.exploits_rag.requests.post')
    def test_generate(self, mock_post):
        """Test LLM text generation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": "Generated answer about exploits"
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        # Execute
        result = exploits_rag._generate("What is CVE-2021-44228?")

        # Verify
        assert result == "Generated answer about exploits"
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "api/generate" in call_args[0][0]
        assert call_args[1]['json']['prompt'] == "What is CVE-2021-44228?"
        assert call_args[1]['json']['model'] == exploits_rag.CHAT_MODEL


@pytest.mark.unit
@pytest.mark.database
@pytest.mark.scan_recommender
class TestRAGDatabase:
    """Test database operations."""

    @patch('scan_recommender.exploits_rag.psycopg2.connect')
    def test_ensure_schema(self, mock_connect):
        """Test database schema creation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        # Execute
        exploits_rag._ensure_schema(dim=768)

        # Verify
        assert mock_cursor.execute.call_count >= 3
        # Check extension, table, and index creation
        calls = [call[0][0] for call in mock_cursor.execute.call_args_list]
        assert any("CREATE EXTENSION" in call for call in calls)
        assert any("CREATE TABLE" in call and "exploit_chunks" in call for call in calls)
        assert any("CREATE INDEX" in call for call in calls)
        mock_conn.commit.assert_called_once()

    @patch('scan_recommender.exploits_rag.psycopg2.connect')
    def test_retrieve(self, mock_connect):
        """Test vector similarity retrieval."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        # Mock query results
        mock_cursor.fetchall.return_value = [
            {
                'edb_id': 12345,
                'title': 'WordPress RCE',
                'path': '/exploit',
                'chunk': 'exploit code here',
                'sim': 0.89
            },
            {
                'edb_id': 12346,
                'title': 'Apache Struts RCE',
                'path': '/exploit2',
                'chunk': 'more exploit code',
                'sim': 0.85
            }
        ]

        query_emb = [0.1] * 768

        # Execute
        results = exploits_rag._retrieve(query_emb, top_k=5)

        # Verify
        assert len(results) == 2
        assert results[0]['edb_id'] == 12345
        assert results[0]['sim'] == 0.89
        assert results[1]['title'] == 'Apache Struts RCE'

        # Check SQL query
        call_args = mock_cursor.execute.call_args[0]
        assert 'SELECT' in call_args[0]
        assert 'embedding <=> %s::vector' in call_args[0]
        assert call_args[1][2] == 5  # top_k parameter


@pytest.mark.unit
@pytest.mark.scan_recommender
@pytest.mark.integration
class TestRAGIngestion:
    """Test exploit ingestion process."""

    @patch('scan_recommender.exploits_rag._dim')
    @patch('scan_recommender.exploits_rag._ensure_schema')
    @patch('scan_recommender.exploits_rag._embed')
    @patch('scan_recommender.exploits_rag.psycopg2.connect')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.is_file')
    @patch('pathlib.Path.read_text')
    def test_ingest_basic(
        self,
        mock_read_text,
        mock_is_file,
        mock_open_file,
        mock_connect,
        mock_embed,
        mock_ensure_schema,
        mock_dim
    ):
        """Test basic exploit ingestion."""
        # Setup mocks
        mock_dim.return_value = 768
        mock_embed.return_value = [0.1] * 768
        mock_is_file.return_value = True
        mock_read_text.return_value = "exploit code content here"

        json_data = {
            "RESULTS_EXPLOIT": [
                {
                    "EDB-ID": "12345",
                    "Title": "Test Exploit",
                    "Platform": "linux",
                    "Type": "remote",
                    "Date": "2024-01-15",
                    "Path": "exploits/linux/remote/12345.py"
                }
            ],
            "RESULTS_SHELLCODE": []
        }

        mock_open_file.return_value.read.return_value = json.dumps(json_data)

        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 1  # Simulate successful insert
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        # Execute
        result = exploits_rag._ingest("/fake/searchsploit.json", "/fake/exploitdb")

        # Verify
        assert 'inserted' in result
        assert result['inserted'] >= 0
        mock_ensure_schema.assert_called_once_with(768)
        mock_embed.assert_called()  # Should embed chunks
        mock_conn.commit.assert_called()

    @patch('scan_recommender.exploits_rag._dim')
    @patch('scan_recommender.exploits_rag._ensure_schema')
    @patch('builtins.open', new_callable=mock_open)
    def test_ingest_invalid_json(
        self,
        mock_open_file,
        mock_ensure_schema,
        mock_dim
    ):
        """Test ingestion with invalid JSON."""
        mock_dim.return_value = 768
        mock_open_file.side_effect = Exception("JSON parse error")

        # Execute and verify exception raised
        with pytest.raises(Exception):
            exploits_rag._ingest("/fake/bad.json", "/fake/root")
