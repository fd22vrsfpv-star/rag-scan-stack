"""
Unit tests for Playwright Screenshot Handler.
Tests screenshot capture, processing, and storage functionality.
"""
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright_scanner.screenshot_handler import ScreenshotHandler


@pytest.mark.unit
@pytest.mark.playwright
class TestScreenshotHandler:
    """Test ScreenshotHandler class."""

    @pytest.fixture
    def handler(self, tmp_path):
        """Create ScreenshotHandler instance with temp directory."""
        return ScreenshotHandler(screenshot_dir=str(tmp_path / "screenshots"))

    @pytest.mark.asyncio
    async def test_capture_full_page(self, handler):
        """Test capturing full page screenshot."""
        # Mock page
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.viewport_size = {"width": 1920, "height": 1080}
        screenshot_data = b"fake_png_data"
        mock_page.screenshot = AsyncMock(return_value=screenshot_data)

        # Execute
        image_data, image_hash, metadata = await handler.capture_full_page(
            mock_page, format="png"
        )

        # Verify
        assert image_data == screenshot_data
        assert image_hash == hashlib.sha256(screenshot_data).hexdigest()
        assert metadata['full_page'] is True
        assert metadata['format'] == 'png'
        assert metadata['url'] == 'http://example.com'
        assert metadata['viewport'] == {"width": 1920, "height": 1080}
        mock_page.screenshot.assert_called_once_with(full_page=True, type='png')

    @pytest.mark.asyncio
    async def test_capture_viewport(self, handler):
        """Test capturing viewport-only screenshot."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com/page"
        mock_page.viewport_size = {"width": 1280, "height": 720}
        screenshot_data = b"viewport_screenshot"
        mock_page.screenshot = AsyncMock(return_value=screenshot_data)

        # Execute
        image_data, image_hash, metadata = await handler.capture_viewport(mock_page)

        # Verify
        assert image_data == screenshot_data
        assert metadata['full_page'] is False
        assert metadata['url'] == 'http://example.com/page'
        mock_page.screenshot.assert_called_once_with(full_page=False, type='png')

    @pytest.mark.asyncio
    async def test_capture_element_found(self, handler):
        """Test capturing screenshot of specific element."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        mock_element = AsyncMock()
        element_screenshot = b"element_screenshot"
        mock_element.screenshot = AsyncMock(return_value=element_screenshot)
        mock_page.query_selector = AsyncMock(return_value=mock_element)

        # Execute
        result = await handler.capture_element(mock_page, selector="div.target")

        # Verify
        assert result is not None
        image_data, image_hash, metadata = result
        assert image_data == element_screenshot
        assert metadata['selector'] == 'div.target'
        assert metadata['full_page'] is False
        mock_page.query_selector.assert_called_once_with("div.target")

    @pytest.mark.asyncio
    async def test_capture_element_not_found(self, handler):
        """Test capturing element that doesn't exist."""
        mock_page = AsyncMock()
        mock_page.query_selector = AsyncMock(return_value=None)

        # Execute
        result = await handler.capture_element(mock_page, selector="div.missing")

        # Verify
        assert result is None
        mock_page.query_selector.assert_called_once_with("div.missing")

    @pytest.mark.asyncio
    async def test_capture_all_forms(self, handler):
        """Test capturing screenshots of all forms on page."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"

        # Mock forms
        mock_form1 = AsyncMock()
        mock_form1.screenshot = AsyncMock(return_value=b"form1_screenshot")
        mock_form2 = AsyncMock()
        mock_form2.screenshot = AsyncMock(return_value=b"form2_screenshot")

        mock_page.query_selector_all = AsyncMock(return_value=[mock_form1, mock_form2])

        # Execute
        screenshots = await handler.capture_all_forms(mock_page)

        # Verify
        assert len(screenshots) == 2
        assert all(len(s) == 3 for s in screenshots)  # Each is (data, hash, metadata)

        # Check first form
        data1, hash1, meta1 = screenshots[0]
        assert data1 == b"form1_screenshot"
        assert meta1['element_type'] == 'form'
        assert meta1['index'] == 0
        assert meta1['selector'] == 'form:nth-of-type(1)'

        # Check second form
        data2, hash2, meta2 = screenshots[1]
        assert data2 == b"form2_screenshot"
        assert meta2['index'] == 1

    @pytest.mark.asyncio
    async def test_capture_all_forms_with_error(self, handler):
        """Test that errors in individual form capture don't stop processing."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"

        # First form succeeds, second fails
        mock_form1 = AsyncMock()
        mock_form1.screenshot = AsyncMock(return_value=b"form1_ok")
        mock_form2 = AsyncMock()
        mock_form2.screenshot = AsyncMock(side_effect=Exception("Screenshot failed"))

        mock_page.query_selector_all = AsyncMock(return_value=[mock_form1, mock_form2])

        # Execute
        screenshots = await handler.capture_all_forms(mock_page)

        # Verify - should have 1 screenshot (error skipped)
        assert len(screenshots) == 1
        assert screenshots[0][0] == b"form1_ok"

    @pytest.mark.asyncio
    async def test_save_to_disk(self, handler, tmp_path):
        """Test saving screenshot to disk."""
        image_data = b"test_screenshot_data"

        # Execute with auto-generated filename
        filepath = await handler.save_to_disk(image_data, format="png")

        # Verify
        assert Path(filepath).exists()
        assert Path(filepath).read_bytes() == image_data
        assert filepath.endswith('.png')

    @pytest.mark.asyncio
    async def test_save_to_disk_custom_filename(self, handler):
        """Test saving screenshot with custom filename."""
        image_data = b"custom_screenshot"
        filename = "custom_screenshot.png"

        # Execute
        filepath = await handler.save_to_disk(image_data, filename=filename)

        # Verify
        assert Path(filepath).name == filename
        assert Path(filepath).read_bytes() == image_data

    def test_compute_hash(self):
        """Test SHA256 hash computation."""
        data = b"test_data_for_hashing"
        expected_hash = hashlib.sha256(data).hexdigest()

        # Execute
        result = ScreenshotHandler.compute_hash(data)

        # Verify
        assert result == expected_hash

    @pytest.mark.asyncio
    async def test_capture_multiple_viewports(self, handler):
        """Test capturing screenshots at different viewport sizes."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.viewport_size = {"width": 1920, "height": 1080}

        # Mock screenshot method
        async def mock_screenshot(full_page, type):
            # Return different data based on viewport
            return f"screenshot_{mock_page.viewport_size['width']}".encode()

        mock_page.screenshot = mock_screenshot

        viewports = [
            {"width": 1920, "height": 1080},  # Desktop
            {"width": 768, "height": 1024},   # Tablet
            {"width": 375, "height": 667},    # Mobile
        ]

        # Execute
        screenshots = await handler.capture_multiple_viewports(
            mock_page, viewports, format="png"
        )

        # Verify
        assert len(screenshots) == 3
        # Check metadata includes viewport info
        for i, (data, hash, meta) in enumerate(screenshots):
            assert meta['viewport'] == viewports[i]
            assert meta['responsive_test'] is True

        # Verify original viewport restored
        mock_page.set_viewport_size.assert_called()

    @pytest.mark.asyncio
    async def test_capture_with_annotations(self, handler):
        """Test capturing screenshot with visual annotations."""
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        screenshot_data = b"annotated_screenshot"
        mock_page.screenshot = AsyncMock(return_value=screenshot_data)
        mock_page.evaluate = AsyncMock()

        annotations = [
            {"selector": "input[type=password]", "color": "red", "label": "XSS"},
            {"selector": "form", "color": "yellow", "label": "CSRF"}
        ]

        # Execute
        image_data, image_hash, metadata = await handler.capture_with_annotations(
            mock_page, annotations
        )

        # Verify
        assert image_data == screenshot_data
        assert metadata['annotated'] is True
        assert metadata['annotation_count'] == 2

        # Should have called evaluate twice (inject annotations, then remove)
        assert mock_page.evaluate.call_count == 2
        mock_page.screenshot.assert_called_once_with(full_page=True, type='png')
