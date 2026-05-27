"""
Screenshot Handler Module
Captures and processes screenshots with different strategies
"""

import hashlib
from typing import Optional, Dict, Tuple, List
from pathlib import Path
from playwright.async_api import Page
import uuid

# Import validation utilities
from validation import (
    validate_output_path,
    sanitize_filename,
    ValidationError
)


class ScreenshotHandler:
    """
    Handles screenshot capture with various options
    """

    def __init__(self, screenshot_dir: str = "/screenshots"):
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    async def capture_full_page(
        self,
        page: Page,
        format: str = "png"
    ) -> Tuple[bytes, str, Dict]:
        """
        Capture full page screenshot

        Args:
            page: Playwright page
            format: Image format (png, jpeg, webp)

        Returns:
            Tuple of (image_data, image_hash, metadata)
        """
        viewport = page.viewport_size
        screenshot_bytes = await page.screenshot(
            full_page=True,
            type=format
        )

        image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

        metadata = {
            'full_page': True,
            'viewport': viewport,
            'format': format,
            'url': page.url
        }

        return screenshot_bytes, image_hash, metadata

    async def capture_viewport(
        self,
        page: Page,
        format: str = "png"
    ) -> Tuple[bytes, str, Dict]:
        """
        Capture visible viewport only

        Args:
            page: Playwright page
            format: Image format

        Returns:
            Tuple of (image_data, image_hash, metadata)
        """
        viewport = page.viewport_size
        screenshot_bytes = await page.screenshot(
            full_page=False,
            type=format
        )

        image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

        metadata = {
            'full_page': False,
            'viewport': viewport,
            'format': format,
            'url': page.url
        }

        return screenshot_bytes, image_hash, metadata

    async def capture_element(
        self,
        page: Page,
        selector: str,
        format: str = "png"
    ) -> Optional[Tuple[bytes, str, Dict]]:
        """
        Capture screenshot of specific element

        Args:
            page: Playwright page
            selector: CSS selector for element
            format: Image format

        Returns:
            Tuple of (image_data, image_hash, metadata) or None if element not found
        """
        try:
            element = await page.query_selector(selector)
            if not element:
                return None

            screenshot_bytes = await element.screenshot(type=format)
            image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

            metadata = {
                'full_page': False,
                'selector': selector,
                'format': format,
                'url': page.url
            }

            return screenshot_bytes, image_hash, metadata
        except Exception as e:
            print(f"Error capturing element {selector}: {e}")
            return None

    async def capture_all_forms(
        self,
        page: Page,
        format: str = "png"
    ) -> List[Tuple[bytes, str, Dict]]:
        """
        Capture screenshots of all forms on the page

        Args:
            page: Playwright page
            format: Image format

        Returns:
            List of tuples (image_data, image_hash, metadata)
        """
        screenshots = []

        forms = await page.query_selector_all('form')

        for i, form in enumerate(forms):
            try:
                screenshot_bytes = await form.screenshot(type=format)
                image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

                metadata = {
                    'full_page': False,
                    'selector': f'form:nth-of-type({i + 1})',
                    'element_type': 'form',
                    'index': i,
                    'format': format,
                    'url': page.url
                }

                screenshots.append((screenshot_bytes, image_hash, metadata))
            except Exception as e:
                print(f"Error capturing form {i}: {e}")
                continue

        return screenshots

    async def save_to_disk(
        self,
        image_data: bytes,
        filename: Optional[str] = None,
        format: str = "png"
    ) -> str:
        """
        Save screenshot to disk

        Args:
            image_data: Image bytes
            filename: Optional filename (auto-generated if not provided)
            format: Image format

        Returns:
            Saved file path
        """
        if not filename:
            filename = f"{uuid.uuid4()}.{format}"

        filepath = self.screenshot_dir / filename
        filepath.write_bytes(image_data)

        return str(filepath)

    @staticmethod
    def compute_hash(image_data: bytes) -> str:
        """
        Compute SHA256 hash of image data

        Args:
            image_data: Image bytes

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(image_data).hexdigest()

    async def capture_multiple_viewports(
        self,
        page: Page,
        viewports: List[Dict[str, int]],
        format: str = "png"
    ) -> List[Tuple[bytes, str, Dict]]:
        """
        Capture screenshots at different viewport sizes

        Args:
            page: Playwright page
            viewports: List of viewport configurations [{'width': 1920, 'height': 1080}, ...]
            format: Image format

        Returns:
            List of tuples (image_data, image_hash, metadata)
        """
        screenshots = []
        original_viewport = page.viewport_size

        for viewport_config in viewports:
            try:
                await page.set_viewport_size(viewport_config)
                # Wait a bit for responsive design to settle
                await page.wait_for_timeout(500)

                screenshot_bytes = await page.screenshot(
                    full_page=False,
                    type=format
                )

                image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

                metadata = {
                    'full_page': False,
                    'viewport': viewport_config,
                    'format': format,
                    'url': page.url,
                    'responsive_test': True
                }

                screenshots.append((screenshot_bytes, image_hash, metadata))
            except Exception as e:
                print(f"Error capturing viewport {viewport_config}: {e}")
                continue

        # Restore original viewport
        if original_viewport:
            await page.set_viewport_size(original_viewport)

        return screenshots

    async def capture_with_annotations(
        self,
        page: Page,
        annotations: List[Dict],
        format: str = "png"
    ) -> Tuple[bytes, str, Dict]:
        """
        Capture screenshot with visual annotations for findings

        Args:
            page: Playwright page
            annotations: List of annotation configs [{'selector': '...', 'color': '...', 'label': '...'}]
            format: Image format

        Returns:
            Tuple of (image_data, image_hash, metadata)
        """
        # Inject annotation overlay
        await page.evaluate("""
            (annotations) => {
                annotations.forEach((ann, index) => {
                    const element = document.querySelector(ann.selector);
                    if (element) {
                        const rect = element.getBoundingClientRect();
                        const overlay = document.createElement('div');
                        overlay.style.position = 'fixed';
                        overlay.style.left = rect.left + 'px';
                        overlay.style.top = rect.top + 'px';
                        overlay.style.width = rect.width + 'px';
                        overlay.style.height = rect.height + 'px';
                        overlay.style.border = `3px solid ${ann.color || 'red'}`;
                        overlay.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                        overlay.style.pointerEvents = 'none';
                        overlay.style.zIndex = '999999';

                        if (ann.label) {
                            const label = document.createElement('div');
                            label.textContent = ann.label;
                            label.style.position = 'absolute';
                            label.style.top = '-25px';
                            label.style.left = '0';
                            label.style.backgroundColor = ann.color || 'red';
                            label.style.color = 'white';
                            label.style.padding = '2px 8px';
                            label.style.fontSize = '12px';
                            label.style.fontWeight = 'bold';
                            label.style.borderRadius = '3px';
                            overlay.appendChild(label);
                        }

                        document.body.appendChild(overlay);
                        overlay.className = 'playwright-annotation';
                    }
                });
            }
        """, annotations)

        # Capture with annotations
        screenshot_bytes = await page.screenshot(full_page=True, type=format)
        image_hash = hashlib.sha256(screenshot_bytes).hexdigest()

        # Remove annotations
        await page.evaluate("""
            () => {
                document.querySelectorAll('.playwright-annotation').forEach(el => el.remove());
            }
        """)

        metadata = {
            'full_page': True,
            'annotated': True,
            'annotation_count': len(annotations),
            'format': format,
            'url': page.url
        }

        return screenshot_bytes, image_hash, metadata
