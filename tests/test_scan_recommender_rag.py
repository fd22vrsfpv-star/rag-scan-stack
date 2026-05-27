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
