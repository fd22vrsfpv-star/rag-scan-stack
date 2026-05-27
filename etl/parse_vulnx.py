import os, json, logging, uuid
import psycopg2
from psycopg2.extras import Json, RealDictCursor
from .fingerprint import vuln_fingerprint

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
log = logging.getLogger(__name__)


def _normalize_product_name(product):
    """Normalize product names for better matching."""
    if not product:
        return ""

    normalized = product.lower().strip()

    # Handle common service name variations
    name_mappings = {
        'proftpd': ['proftp', 'pro-ftp', 'pro_ftp', 'proftpd-server'],
        'apache': ['apache http server', 'httpd', 'apache2'],
        'nginx': ['nginx http server'],
        'openssh': ['ssh', 'openssh_', 'ssh-server'],
        'mysql': ['mysql server', 'mysqld'],
        'postgresql': ['postgres', 'pgsql'],
    }

    for canonical, variations in name_mappings.items():
        if normalized == canonical or any(v in normalized for v in variations):
            return canonical

    return normalized


def _extract_products_from_cve(summary, refs_list):
    """Enhanced product extraction with version context and better pattern matching."""
    products = []
    summary_lower = summary.lower()

    # Product patterns with version capture (including 'v' prefix)
    import re
    product_patterns = [
        (r'vsftpd\s+v?(\d+\.[\d.]+)', 'vsftpd'),
        (r'proftpd\s+v?(\d+\.[\d.]+)', 'proftpd'),
        (r'apache\s+http\s+server\s+v?(\d+\.[\d.]+)', 'apache'),
        (r'nginx\s+v?(\d+\.[\d.]+)', 'nginx'),
        (r'openssh\s+v?(\d+\.[\d.]+)', 'openssh'),
        (r'mysql\s+v?(\d+\.[\d.]+)', 'mysql'),
        (r'postgresql\s+v?(\d+\.[\d.]+)', 'postgresql'),
        # Generic pattern for any product version (with optional 'v' prefix)
        (r'(\w+)\s+v?(\d+\.[\d.]+)', None),
    ]

    for pattern, canonical_name in product_patterns:
        matches = re.finditer(pattern, summary_lower, re.IGNORECASE)
        for match in matches:
            product_name = canonical_name or match.group(1)
            version = match.group(1) if canonical_name else match.group(2)
            products.append({"product": product_name, "version": version})

    # If no version-based patterns matched, fall back to simple keyword matching
    if not products:
        common_products = [
            'apache', 'nginx', 'mysql', 'postgresql', 'ssh', 'openssh', 'ftp', 'vsftpd', 'proftpd',
            'samba', 'smb', 'bind', 'dns', 'telnet', 'vnc', 'irc', 'unrealircd', 'ruby', 'python',
            'php', 'java', 'tomcat', 'iis', 'exchange', 'outlook', 'windows', 'linux'
        ]

        for product in common_products:
            if product in summary_lower:
                products.append({"product": product, "version": None})

    # If still no products found, create a generic entry to match any software
    if not products:
        products.append({"product": "", "version": None})

    return products


def _load_jsonl(path):
    results = []
    with open(path, 'r') as f:
        content = f.read().strip()
        if not content:
            return results

        # First try to parse as single JSON object (VulnX format)
        try:
            data = json.loads(content)
            if isinstance(data, dict) and 'results' in data:
                # VulnX format: {"results": [...], "count": N, ...}
                return data.get('results', [])
            elif isinstance(data, list):
                # Array of objects
                return data
            else:
                # Single object
                return [data]
        except json.JSONDecodeError:
            # Fall back to JSONL format (line by line)
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return results


def parse_vulnx(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, cves_upserted=0, vulns_updated=0, vulns_created=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    cve_id = rec.get("cve_id", "").strip()
                    if not cve_id:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    summary = rec.get("cve_description", "") or ""
                    cvss = rec.get("cvss_score") or rec.get("cvss")
                    published = rec.get("published_at")
                    refs_list = rec.get("references") or []
                    refs = Json(refs_list) if refs_list else Json([])

                    cur.execute("""
                        INSERT INTO cve (id, summary, cvss, published, refs, last_modified)
                        VALUES (%s, %s, %s, %s, %s, now())
                        ON CONFLICT (id) DO UPDATE SET
                            summary = EXCLUDED.summary,
                            cvss = EXCLUDED.cvss,
                            refs = EXCLUDED.refs,
                            last_modified = now()
                    """, (cve_id, summary, cvss, published, refs))
                    stats["cves_upserted"] += 1

                    # Create vulnerability findings for software that matches this CVE
                    # Get affected products/versions from CVE description and match to assets
                    affected_products = _extract_products_from_cve(summary, refs_list)

                    for product_info in affected_products:
                        # Find assets with matching software using enhanced matching
                        if not product_info.get('product'):
                            # Empty product - skip to avoid matching everything
                            continue

                        cve_product = _normalize_product_name(product_info['product'])
                        cve_version = product_info.get('version')

                        # Enhanced matching: prioritize exact product matches and consider service context
                        cur.execute("""
                            SELECT DISTINCT a.id, a.ip, a.hostname, p.port, p.product, p.version,
                                   CASE
                                       WHEN LOWER(p.product) = %s THEN 3
                                       WHEN LOWER(p.product) LIKE %s THEN 2
                                       WHEN %s LIKE CONCAT('%%', LOWER(p.product), '%%') THEN 1
                                       ELSE 0
                                   END as match_strength
                            FROM assets a
                            JOIN ports p ON a.id = p.asset_id
                            WHERE (
                                LOWER(p.product) = %s
                                OR LOWER(p.product) LIKE %s
                                OR %s LIKE CONCAT('%%', LOWER(p.product), '%%')
                            )
                            AND p.product IS NOT NULL
                            AND LENGTH(p.product) >= 3
                            ORDER BY match_strength DESC, p.port ASC
                        """, (
                            cve_product,           # exact match check
                            f"%{cve_product}%",    # contains match check
                            cve_product,           # reverse contains check
                            cve_product,           # exact match filter
                            f"%{cve_product}%",    # contains match filter
                            cve_product            # reverse contains filter
                        ))

                        matching_assets = cur.fetchall()

                        # Filter assets by service context to prevent cross-contamination
                        # Use both port numbers AND service names for better accuracy
                        filtered_assets = []
                        for asset in matching_assets:
                            should_include = True
                            asset_product = (asset.get('product') or '').lower()
                            asset_port = asset.get('port')

                            # Enhanced filtering: check product name match AND service context
                            # Only exclude if there's a clear mismatch (different service families)

                            # vsftpd/ProFTPD CVEs should not affect SSH services
                            if cve_product in ['vsftpd', 'proftpd']:
                                if ('ssh' in asset_product or asset_port == 22) and 'ftp' not in asset_product:
                                    should_include = False
                            # OpenSSH CVEs should not affect FTP services
                            elif cve_product == 'openssh':
                                if ('ftp' in asset_product or asset_port == 21) and 'ssh' not in asset_product:
                                    should_include = False
                            # Apache CVEs should not affect clearly different services (SSH, FTP, database)
                            elif cve_product == 'apache':
                                if asset_port in [21, 22, 3306, 5432] and not any(web in asset_product for web in ['http', 'apache', 'web']):
                                    should_include = False
                            # MySQL CVEs should not affect web/SSH/FTP services
                            elif cve_product == 'mysql':
                                if asset_port in [21, 22, 80, 443] and 'mysql' not in asset_product:
                                    should_include = False

                            # Additional safety check: if product names are completely different families, skip
                            if should_include and asset.get('match_strength', 0) <= 1:
                                # Low match strength - do extra validation
                                service_families = {
                                    'ftp': ['vsftpd', 'proftpd', 'pure-ftpd', 'wu-ftpd'],
                                    'ssh': ['openssh', 'dropbear', 'ssh'],
                                    'web': ['apache', 'nginx', 'iis', 'lighttpd'],
                                    'db': ['mysql', 'postgresql', 'mongodb', 'mariadb']
                                }

                                cve_family = None
                                asset_family = None

                                for family, products in service_families.items():
                                    if cve_product in products:
                                        cve_family = family
                                    if any(p in asset_product for p in products):
                                        asset_family = family

                                # If families are clearly different, exclude
                                if cve_family and asset_family and cve_family != asset_family:
                                    should_include = False

                            if should_include:
                                filtered_assets.append(asset)

                        for asset in filtered_assets:
                            # Create vulnerability record for this asset
                            vuln_id = str(uuid.uuid4())

                            # Determine severity from CVSS
                            severity = "info"
                            if cvss:
                                if cvss >= 9.0:
                                    severity = "critical"
                                elif cvss >= 7.0:
                                    severity = "high"
                                elif cvss >= 4.0:
                                    severity = "medium"
                                elif cvss >= 0.1:
                                    severity = "low"

                            output_text = f"VulnX CVE Finding: {cve_id}\n\n{summary}"
                            if refs_list:
                                output_text += f"\n\nReferences:\n" + "\n".join(refs_list[:5])

                            metadata = {
                                "source": "vulnx",
                                "product": asset["product"],
                                "version": asset["version"],
                                "port": asset["port"],
                                "cvss_score": float(cvss) if cvss else None,
                            }

                            fp = vuln_fingerprint(
                                ip=asset["ip"],
                                port=asset["port"],
                                script="vulnx",
                                cves=[cve_id],
                            )

                            # Create descriptive title with service and CVE
                            service_name = asset["product"] or "Unknown Service"
                            version_info = f" {asset['version']}" if asset["version"] else ""
                            cve_short = cve_id.replace('CVE-', 'CVE-') if cve_id.startswith('CVE-') else cve_id
                            title = f"{service_name}{version_info} - {cve_short}"

                            cur.execute("""
                                INSERT INTO vulns (id, asset_id, port_id, script, output, severity, cve, metadata, fingerprint, title)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (id) DO NOTHING
                            """, (
                                vuln_id,
                                str(asset["id"]),
                                None,  # Don't link to port_id to avoid inheriting nmap source
                                "vulnx",
                                output_text[:4000],
                                severity,
                                [cve_id],
                                Json(metadata),
                                fp,
                                title
                            ))

                            if cur.rowcount > 0:
                                stats["vulns_created"] += 1

                                # Also insert into findings table for Findings Explorer
                                findings_id = str(uuid.uuid4())
                                findings_details = {
                                    "source": "vulnx",
                                    "cve": [cve_id],
                                    "cvss": float(cvss) if cvss else None,
                                    "description": summary[:500],
                                    "product": asset["product"],
                                    "version": asset["version"],
                                    "ip": asset["ip"],
                                    "evidence": f"CVE: {cve_id}\nProduct: {asset['product']} {asset['version'] or ''}",
                                    "reference": refs_list[:3] if refs_list else [],
                                }

                                cur.execute("""
                                    INSERT INTO findings (id, title, severity, asset_id, port, details)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                    ON CONFLICT (id) DO NOTHING
                                """, (
                                    findings_id,
                                    title,
                                    severity,
                                    str(asset["id"]),
                                    asset["port"],
                                    Json(findings_details)
                                ))

                                # Create follow-up item for High+ severity findings to show in Software table
                                if cvss and float(cvss) >= 7.0:  # High+ severity only
                                    # Check for existing follow-up to avoid duplicates
                                    cur.execute("""
                                        SELECT 1 FROM follow_up_items
                                        WHERE rule_id = 'software_known_cve'
                                        AND target = %s
                                        AND title LIKE %s
                                        LIMIT 1
                                    """, (asset["ip"], f"%{asset['product']}%{cve_id}%"))

                                    if not cur.fetchone():
                                        follow_up_id = str(uuid.uuid4())
                                        follow_up_title = f"Vulnerable: {asset['product']} {asset['version'] or 'unknown'} on {asset['ip']} — {cve_id}"
                                        follow_up_reason = f"VulnX detected high-severity {cve_id} affecting {asset['product']} v{asset['version'] or 'unknown'} on {asset['ip']} ({asset.get('hostname') or 'no hostname'}). CVSS: {cvss}. {summary[:200]}"

                                        # Build metadata for consistency with rule engine output
                                        follow_up_metadata = {
                                            "source": "vulnx_parser",
                                            "product": asset["product"],
                                            "version": asset["version"],
                                            "cve_ids": [cve_id],
                                            "refs": [{"label": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "type": "cve"}],
                                            "software_link": f"/assets?tab=software&search={asset['product']}",
                                            "cvss_score": float(cvss),
                                        }

                                        cur.execute("""
                                            INSERT INTO follow_up_items
                                            (id, finding_source, finding_id, title, target, severity, reason, rule_id, confidence, tags, metadata)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                            ON CONFLICT (title, COALESCE(target, ''), COALESCE(rule_id, '')) DO NOTHING
                                        """, (
                                            follow_up_id,
                                            "vulnx",
                                            vuln_id,
                                            follow_up_title,
                                            asset["ip"],
                                            severity,
                                            follow_up_reason,
                                            "software_known_cve",
                                            0.85,
                                            ["cve", "vulnx", "vulnerability"],
                                            Json(follow_up_metadata)
                                        ))

                    # Cross-reference: update vulns that reference this CVE but lack CVSS
                    if cvss is not None:
                        cur.execute("""
                            UPDATE vulns SET cvss = %s, updated_at = now()
                            WHERE %s = ANY(cve) AND cvss IS NULL
                        """, (cvss, cve_id))
                        stats["vulns_updated"] += cur.rowcount

                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")

            conn.commit()
    finally:
        conn.close()

    log.info(f"[vulnx] Parsed {stats['records_seen']} records, upserted {stats['cves_upserted']} CVEs, "
             f"created {stats['vulns_created']} vulns, updated {stats['vulns_updated']} vulns")
    return stats
