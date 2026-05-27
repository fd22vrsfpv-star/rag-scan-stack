"""
Metadata Extractor — Downloads interesting files discovered by content analyzer
and runs exiftool to extract pentest-relevant metadata (authors, software,
internal paths, GPS, emails, timestamps).
"""

import os
import json
import logging
import subprocess
import tempfile
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("metadata-extractor")

# File extensions worth downloading for metadata extraction
METADATA_EXTENSIONS = frozenset({
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp', '.webp',
    '.svg', '.mp3', '.mp4', '.avi', '.mov',
    '.odt', '.ods', '.odp', '.rtf',
})

# Max file size to download (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Pentest-relevant exiftool fields to extract
INTERESTING_FIELDS = {
    # Author / user info
    'Author', 'Creator', 'LastModifiedBy', 'Company', 'Manager',
    'Artist', 'Copyright', 'OwnerName', 'CameraOwnerName',
    # Software / tools
    'Producer', 'CreatorTool', 'Software', 'Application',
    'PDFVersion', 'AppVersion',
    # Internal paths (leaked from document properties)
    'Subject', 'Title', 'Description', 'Keywords',
    'HyperlinkBase', 'Template', 'SourceFile',
    # Network / location
    'GPSLatitude', 'GPSLongitude', 'GPSPosition',
    'GPSCity', 'GPSCountry',
    # Timestamps
    'CreateDate', 'ModifyDate', 'MetadataDate',
    # Email / identifiers
    'XMPToolkit', 'DocumentID', 'InstanceID',
    # Embedded objects
    'EmbeddedDocumentCount', 'PageCount', 'WordCount',
    # Printer / hostname leaks
    'PrinterName', 'MachineName', 'ComputerName',
    'UserName', 'LastSavedBy',
}


async def extract_file_metadata(
    interesting_files: List[Dict],
    page_url: str,
    page=None,
    max_files: int = 20,
) -> List[Dict]:
    """
    Download interesting files and extract metadata via exiftool.

    Args:
        interesting_files: List of {path, category} from content analyzer
        page_url: Base URL of the page (for resolving relative paths)
        page: Playwright Page object (for downloading via browser context)
        max_files: Max files to process

    Returns:
        List of {path, url, file_type, size_bytes, metadata: {field: value}, alerts: [...]}
    """
    results = []
    processed = 0

    # Filter to files worth extracting metadata from
    candidates = []
    for f in interesting_files:
        path = f.get('path', '')
        lower = path.lower()
        if any(lower.endswith(ext) for ext in METADATA_EXTENSIONS):
            candidates.append(f)
    candidates = candidates[:max_files]

    if not candidates:
        return results

    parsed_base = urlparse(page_url)
    base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for file_info in candidates:
        path = file_info['path']
        # Resolve to absolute URL
        if path.startswith('http'):
            file_url = path
        elif path.startswith('/'):
            file_url = f"{base_url}{path}"
        else:
            file_url = urljoin(page_url, path)

        try:
            result = await _download_and_extract(file_url, path, page)
            if result:
                results.append(result)
                processed += 1
        except Exception as e:
            logger.debug("Metadata extraction failed for %s: %s", path, e)

    logger.info("Extracted metadata from %d/%d files", processed, len(candidates))
    return results


async def _download_and_extract(url: str, path: str, page=None) -> Optional[Dict]:
    """Download a single file and run exiftool on it."""
    tmp_path = None
    try:
        # Download via Playwright context (uses same cookies/auth)
        if page:
            try:
                resp = await page.context.request.get(url)
                if not resp.ok:
                    return None
                body = await resp.body()
                if len(body) > MAX_FILE_SIZE:
                    logger.debug("Skipping %s: too large (%d bytes)", path, len(body))
                    return None
                if len(body) < 100:
                    return None

                # Write to temp file
                ext = os.path.splitext(path)[1] or '.bin'
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp.write(body)
                    tmp_path = tmp.name
            except Exception as e:
                logger.debug("Download failed for %s: %s", url, e)
                return None
        else:
            return None

        # Run exiftool
        metadata = _run_exiftool(tmp_path)
        if not metadata:
            return None

        # Extract pentest-relevant fields
        interesting = {}
        alerts = []
        for key, value in metadata.items():
            clean_key = key.split(':')[-1].strip() if ':' in key else key.strip()
            if clean_key in INTERESTING_FIELDS and value and str(value).strip():
                val_str = str(value).strip()
                if val_str and val_str not in ('(none)', '-', '0', 'Unknown'):
                    interesting[clean_key] = val_str

        # Generate alerts for high-value findings
        if any(k in interesting for k in ('Author', 'Creator', 'LastModifiedBy', 'UserName', 'LastSavedBy', 'CameraOwnerName')):
            user_fields = [interesting[k] for k in ('Author', 'Creator', 'LastModifiedBy', 'UserName', 'LastSavedBy', 'CameraOwnerName') if k in interesting]
            alerts.append({'type': 'user_disclosure', 'detail': f"User/author names: {', '.join(set(user_fields))}"})

        if any(k in interesting for k in ('Company', 'Manager')):
            org_fields = [interesting[k] for k in ('Company', 'Manager') if k in interesting]
            alerts.append({'type': 'org_disclosure', 'detail': f"Organization info: {', '.join(org_fields)}"})

        if any(k in interesting for k in ('GPSLatitude', 'GPSLongitude', 'GPSPosition')):
            gps = interesting.get('GPSPosition') or f"{interesting.get('GPSLatitude', '')}, {interesting.get('GPSLongitude', '')}"
            alerts.append({'type': 'gps_disclosure', 'detail': f"GPS coordinates: {gps}"})

        if any(k in interesting for k in ('PrinterName', 'MachineName', 'ComputerName')):
            host_fields = [interesting[k] for k in ('PrinterName', 'MachineName', 'ComputerName') if k in interesting]
            alerts.append({'type': 'hostname_disclosure', 'detail': f"Internal hostnames: {', '.join(host_fields)}"})

        if any(k in interesting for k in ('Template', 'HyperlinkBase')):
            path_fields = [interesting[k] for k in ('Template', 'HyperlinkBase') if k in interesting]
            alerts.append({'type': 'path_disclosure', 'detail': f"Internal paths: {', '.join(path_fields)}"})

        if interesting.get('CreatorTool') or interesting.get('Producer') or interesting.get('Software'):
            sw = interesting.get('CreatorTool') or interesting.get('Producer') or interesting.get('Software')
            alerts.append({'type': 'software_disclosure', 'detail': f"Software: {sw}"})

        if not interesting:
            return None

        file_size = os.path.getsize(tmp_path) if tmp_path else 0
        file_type = metadata.get('FileType', metadata.get('MIMEType', 'unknown'))

        return {
            'path': path,
            'url': url,
            'file_type': file_type,
            'size_bytes': file_size,
            'metadata': interesting,
            'alerts': alerts,
        }

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _run_exiftool(file_path: str) -> Optional[Dict]:
    """Run exiftool on a file and return parsed JSON output."""
    try:
        result = subprocess.run(
            ['exiftool', '-json', '-n', file_path],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        if data and isinstance(data, list):
            return data[0]
        return None
    except FileNotFoundError:
        logger.warning("exiftool not installed — skipping metadata extraction")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("exiftool timed out on %s", file_path)
        return None
    except (json.JSONDecodeError, Exception) as e:
        logger.debug("exiftool parse error: %s", e)
        return None
