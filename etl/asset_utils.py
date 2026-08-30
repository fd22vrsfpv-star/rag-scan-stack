"""
Standardized asset management utilities for ETL parsers.
Prevents duplicate asset creation by providing consistent upsert logic.
"""

import uuid
import logging

logger = logging.getLogger(__name__)

def resolve_engagement_for_ip(cur, ip: str):
    """The engagement whose SCOPE contains `ip`, when exactly one does.

    Assets were being created with engagement_id NULL by every scan ingest
    (parse_nmap and friends insert (id, ip, hostname) only), while the discovery
    ingests — parse_subfinder, parse_dnsx — did stamp it. The result: an
    engagement with a populated scope and real assets, none of which were linked
    to it. Every engagement-scoped query then returned nothing, and the KB
    recommendation drain in particular could not see a single asset.

    Scope is the authoritative statement of what belongs to an engagement, so it
    is what resolves the link. Returns None when NO scope matches, and also when
    MORE THAN ONE does: guessing an owner for a host two engagements both claim
    would silently attribute findings to the wrong engagement, which is worse
    than leaving it unstamped.
    """
    if not ip:
        return None
    try:
        cur.execute(
            """
            SELECT DISTINCT st.engagement_id::text
              FROM public.scope_targets st
             WHERE st.engagement_id IS NOT NULL
               AND st.target <> ''
               AND (
                    (st.target_type = 'ip' AND st.target = host(%s::inet)::text)
                 OR (st.target_type = 'cidr'
                     AND st.target ~ '^[0-9]+([.][0-9]+){3}/[0-9]+$'
                     AND %s::inet <<= st.target::inet)
               )
             LIMIT 2
            """,
            (ip, ip),
        )
        rows = cur.fetchall()
    except Exception as e:
        logger.debug("engagement resolution failed for %s: %s", ip, e)
        return None
    if len(rows) != 1:
        if len(rows) > 1:
            logger.info("ip %s is in more than one engagement scope — leaving unstamped", ip)
        return None
    r = rows[0]
    return (r.get("engagement_id") if isinstance(r, dict) else r[0])


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

    # A hostname equal to the IP is not information, and the unique index
    # ix_assets_ip_hostname(ip, COALESCE(hostname, '')) treats it as a DIFFERENT
    # row from hostname=NULL. That produced two asset rows for one host, and
    # since ports hang off asset_id, a duplicate copy of every port on it.
    # Mirrored in playwright_scanner/db_utils.py and by CHECK
    # assets_hostname_not_ip.
    if ip and hostname and hostname.strip() == ip.strip():
        hostname = None

    # Case 1: IP provided (most common, should be primary)
    if ip:
        # An asset row with NO hostname is this host before its name was known —
        # it is not a virtual host. ix_assets_ip_hostname is
        # UNIQUE(ip, COALESCE(hostname,'')), so (ip, '') and (ip, 'name') are two
        # legal rows, and inserting the second is how one machine became two:
        # 192.168.1.150 held its 57 ports on the nameless row and its hostname,
        # 758 web findings and 7 credentials on the named one. Anything joining
        # ports to findings through asset_id returned nothing.
        #
        # public.merge_duplicate_assets() repairs that after the fact; these two
        # lookups stop it happening in the first place.
        adopted = None
        if hostname:
            # Name the existing nameless row rather than adding a sibling. Only
            # when this address has no OTHER named row: several names on one
            # address is a genuine vhost set, and adopting would attach the
            # nameless row's data to whichever name happened to arrive first.
            cur.execute("""
                UPDATE assets a
                   SET hostname = %s, last_seen = now(), modified_at = now()
                 WHERE a.ip = %s::inet
                   AND COALESCE(NULLIF(btrim(a.hostname), ''), '') = ''
                   AND NOT EXISTS (
                        SELECT 1 FROM assets b
                         WHERE b.ip = a.ip AND b.id <> a.id
                           AND COALESCE(NULLIF(btrim(b.hostname), ''), '') <> '')
                RETURNING a.id
            """, (hostname, ip))
            row = cur.fetchone()
            if row:
                adopted = str(row["id"])
        else:
            # No hostname on offer, so any row for this address is this host.
            # Prefer the nameless row; otherwise reuse the single named one. With
            # two or more names this returns nothing and the upsert below creates
            # or reuses the nameless anchor — an IP-only observation genuinely
            # cannot say which vhost it belongs to.
            cur.execute("""
                SELECT a.id FROM assets a
                 WHERE a.ip = %s::inet
                   AND (SELECT count(DISTINCT NULLIF(btrim(b.hostname), ''))
                          FROM assets b WHERE b.ip = a.ip) <= 1
                 ORDER BY (COALESCE(NULLIF(btrim(a.hostname), ''), '') = '') DESC,
                          a.first_seen NULLS LAST, a.id
                 LIMIT 1
            """, (ip,))
            row = cur.fetchone()
            if row:
                adopted = str(row["id"])
                cur.execute("UPDATE assets SET last_seen = now(), modified_at = now()"
                            " WHERE id = %s::uuid", (adopted,))

        if adopted:
            eid = resolve_engagement_for_ip(cur, ip)
            if eid:
                try:
                    cur.execute(
                        "UPDATE assets SET engagement_id = %s::uuid "
                        " WHERE id = %s::uuid AND engagement_id IS NULL",
                        (eid, adopted),
                    )
                except Exception as e:
                    logger.debug("engagement stamp failed for asset %s: %s", adopted, e)
            logger.debug(f"Asset reused for IP {ip}: {adopted}")
            return adopted

        # Use UPSERT to handle duplicates gracefully
        # The conflict target must match an existing unique index EXACTLY, and
        # the only one on assets is
        #     ix_assets_ip_hostname ON assets(ip, COALESCE(hostname, ''))
        # so `ON CONFLICT (ip)` matched nothing and raised
        #     InvalidColumnReference: there is no unique or exclusion constraint
        #     matching the ON CONFLICT specification
        # on every row. A masscan run that found 23 open ports ingested none of
        # them: 23 records seen, 23 errors, 0 ports — and the scan still reported
        # "completed", because ingestion errors are counted per-record rather
        # than failing the job.
        cur.execute("""
            INSERT INTO assets (id, ip, hostname)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip, COALESCE(hostname, '')) DO UPDATE SET
                last_seen = now(),
                modified_at = now()
            RETURNING id
        """, (str(uuid.uuid4()), ip, hostname))

        result = cur.fetchone()
        asset_id = str(result["id"]) if result else None

        # Link the asset to its engagement if scope says which one it belongs to.
        # Only ever FILLS a NULL — never overwrites an existing value, so an
        # operator's manual assignment always wins over inference.
        if asset_id:
            eid = resolve_engagement_for_ip(cur, ip)
            if eid:
                try:
                    cur.execute(
                        "UPDATE assets SET engagement_id = %s::uuid "
                        " WHERE id = %s::uuid AND engagement_id IS NULL",
                        (eid, asset_id),
                    )
                except Exception as e:
                    logger.debug("engagement stamp failed for asset %s: %s", asset_id, e)

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