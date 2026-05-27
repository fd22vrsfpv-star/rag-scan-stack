"""
Standardized asset management utilities for ETL parsers.
Prevents duplicate asset creation by providing consistent upsert logic.
"""

import uuid
import logging

logger = logging.getLogger(__name__)

def ensure_asset(cur, ip: str = None, hostname: str = None) -> str:
    """
    Ensure an asset exists, returning its ID. Creates if missing, updates if needed.

    This function prevents duplicate assets by:
    1. Checking for existing asset by IP first (primary key)
    2. If found, updating hostname if provided and different
    3. If not found, creating new asset with both IP and hostname
    4. Using proper UPSERT with ON CONFLICT handling

    Args:
        cur: Database cursor
        ip: IP address (should be primary identifier)
        hostname: Optional hostname to associate

    Returns:
        Asset UUID as string

    Raises:
        ValueError: If neither ip nor hostname provided
    """
    if not ip and not hostname:
        raise ValueError("Either ip or hostname must be provided")

    # Case 1: IP provided (most common, should be primary)
    if ip:
        # Use UPSERT to handle duplicates gracefully
        cur.execute("""
            INSERT INTO assets (id, ip, hostname)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET
                hostname = COALESCE(EXCLUDED.hostname, assets.hostname),
                last_seen = now(),
                modified_at = now()
            RETURNING id
        """, (str(uuid.uuid4()), ip, hostname))

        result = cur.fetchone()
        asset_id = str(result["id"]) if result else None

        if asset_id:
            logger.debug(f"Asset ensured for IP {ip}: {asset_id}")
            return asset_id

    # Case 2: Hostname only (fallback, less reliable)
    if hostname and not ip:
        # Check if hostname already exists
        cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
        row = cur.fetchone()

        if row:
            asset_id = str(row["id"])
            logger.debug(f"Found existing asset by hostname {hostname}: {asset_id}")
            return asset_id

        # Create new asset with hostname only
        asset_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO assets (id, hostname)
            VALUES (%s, %s)
        """, (asset_id, hostname))

        logger.debug(f"Created new asset for hostname {hostname}: {asset_id}")
        return asset_id

    raise Exception("Failed to ensure asset - this should not happen")


def resolve_asset_id(cur, ip: str = None, hostname: str = None, create_if_missing: bool = True) -> str:
    """
    Legacy compatibility function - just calls ensure_asset.

    Args:
        cur: Database cursor
        ip: IP address
        hostname: Hostname
        create_if_missing: If False, returns None instead of creating

    Returns:
        Asset UUID as string, or None if create_if_missing=False and not found
    """
    if not create_if_missing:
        # Just check existence without creating
        if ip:
            cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
        elif hostname:
            cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
        else:
            return None

        row = cur.fetchone()
        return str(row["id"]) if row else None

    return ensure_asset(cur, ip, hostname)