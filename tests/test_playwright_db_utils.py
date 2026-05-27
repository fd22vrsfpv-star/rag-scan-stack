"""
Unit tests for Playwright Scanner database utilities.
Tests database operations for scans, findings, screenshots, and DOM analysis.
"""
import uuid
from unittest.mock import patch, MagicMock, call
import pytest
from psycopg2.extras import Json

# Import the module under test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright_scanner import db_utils


@pytest.mark.unit
@pytest.mark.database
class TestDatabaseUtils:
    """Test database utility functions."""

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_get_or_create_asset_existing(self, mock_connect):
        """Test getting an existing asset."""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        # Existing asset
        asset_id = uuid.uuid4()
        mock_cursor.fetchone.return_value = {'id': asset_id}

        # Execute
        result = db_utils.get_or_create_asset('192.168.1.100', 'testhost')

        # Verify
        assert result == asset_id
        mock_cursor.execute.assert_any_call(
            "SELECT id FROM assets WHERE ip = %s::inet",
            ('192.168.1.100',)
        )
        # Should update last_seen
        assert mock_cursor.execute.call_count == 2
        mock_conn.commit.assert_called_once()

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_get_or_create_asset_new(self, mock_connect):
        """Test creating a new asset."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        # No existing asset
        asset_id = uuid.uuid4()
        mock_cursor.fetchone.side_effect = [None, {'id': asset_id}]

        # Execute
        result = db_utils.get_or_create_asset('192.168.1.200')

        # Verify
        assert result == asset_id
        assert 'INSERT INTO assets' in mock_cursor.execute.call_args_list[1][0][0]
        mock_conn.commit.assert_called_once()

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_create_playwright_scan(self, mock_connect):
        """Test creating a Playwright scan record."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        mock_cursor.fetchone.return_value = {'id': scan_id}

        # Execute
        result = db_utils.create_playwright_scan(
            url='http://example.com',
            asset_id=asset_id,
            browser='chromium',
            viewport={'width': 1920, 'height': 1080},
            user_agent='TestAgent/1.0'
        )

        # Verify
        assert result == scan_id
        assert 'INSERT INTO playwright_scans' in mock_cursor.execute.call_args[0][0]
        # Check that Json() is used for viewport
        call_args = mock_cursor.execute.call_args[0][1]
        assert call_args[0] == asset_id
        assert call_args[1] == 'http://example.com'
        assert call_args[2] == 'chromium'

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_update_playwright_scan(self, mock_connect):
        """Test updating a Playwright scan with results."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()

        # Execute
        db_utils.update_playwright_scan(
            scan_id=scan_id,
            status='completed',
            screenshots=5,
            dom_snapshot=True,
            console_logs=['log1', 'log2'],
            errors=['error1']
        )

        # Verify
        assert 'UPDATE playwright_scans SET' in mock_cursor.execute.call_args[0][0]
        # Check parameters include status and scan_id
        params = mock_cursor.execute.call_args[0][1]
        assert params[0] == 'completed'
        assert params[-1] == scan_id
        mock_conn.commit.assert_called_once()

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_create_playwright_finding(self, mock_connect):
        """Test creating a Playwright finding."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        mock_cursor.fetchone.return_value = {'id': finding_id}

        # Execute
        result = db_utils.create_playwright_finding(
            scan_id=scan_id,
            asset_id=asset_id,
            url='http://example.com',
            finding_type='xss',
            title='XSS Vulnerability',
            severity='high',
            description='Reflected XSS found',
            cwe=['CWE-79'],
            confidence=0.95
        )

        # Verify
        assert result == finding_id
        assert 'INSERT INTO playwright_findings' in mock_cursor.execute.call_args[0][0]
        call_args = mock_cursor.execute.call_args[0][1]
        assert call_args[0] == scan_id
        assert call_args[4] == 'XSS Vulnerability'
        assert call_args[5] == 'high'

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_save_screenshot(self, mock_connect):
        """Test saving screenshot to database."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()
        screenshot_id = uuid.uuid4()

        # Test new screenshot
        mock_cursor.fetchone.side_effect = [None, {'id': screenshot_id}]
        image_data = b'fake_png_data'
        image_hash = 'abc123hash'

        # Execute
        result = db_utils.save_screenshot(
            scan_id=scan_id,
            url='http://example.com',
            image_data=image_data,
            image_hash=image_hash,
            format='png',
            full_page=True
        )

        # Verify
        assert result == screenshot_id
        # Should check for duplicate first
        assert mock_cursor.execute.call_count == 2
        assert 'INSERT INTO playwright_screenshots' in mock_cursor.execute.call_args[0][0]

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_save_screenshot_duplicate(self, mock_connect):
        """Test that duplicate screenshots are not saved."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()
        existing_id = uuid.uuid4()

        # Existing screenshot with same hash
        mock_cursor.fetchone.return_value = {'id': existing_id}

        # Execute
        result = db_utils.save_screenshot(
            scan_id=scan_id,
            url='http://example.com',
            image_data=b'data',
            image_hash='same_hash',
        )

        # Verify - should return existing ID without insert
        assert result == existing_id
        assert mock_cursor.execute.call_count == 1  # Only SELECT, no INSERT

    @patch('playwright_scanner.db_utils.psycopg2.connect')
    def test_save_dom_analysis(self, mock_connect):
        """Test saving DOM analysis results."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=None)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)

        scan_id = uuid.uuid4()
        analysis_id = uuid.uuid4()
        mock_cursor.fetchone.return_value = {'id': analysis_id}

        forms = [{'action': '/login', 'method': 'POST', 'inputs': []}]
        cookies = [{'name': 'session', 'secure': True}]

        # Execute
        result = db_utils.save_dom_analysis(
            scan_id=scan_id,
            asset_id=None,
            url='http://example.com',
            forms=forms,
            cookies=cookies,
            local_storage={'key': 'value'},
            session_storage={},
            javascript_libs=[],
            csp_header="default-src 'self'",
            cors_enabled=True,
            cors_config={'origin': '*'},
            security_headers={},
            external_scripts=[],
            mixed_content=False,
            websockets=[],
            postmessage_usage=False
        )

        # Verify
        assert result == analysis_id
        assert 'INSERT INTO dom_analysis' in mock_cursor.execute.call_args[0][0]
        call_args = mock_cursor.execute.call_args[0][1]
        assert call_args[0] == scan_id
        assert call_args[3] == 1  # forms_count
