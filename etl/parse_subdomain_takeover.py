#!/usr/bin/env python3
"""
ETL Parser for Subdomain Takeover Detection Results
Parses results from subdomain takeover tools like SubOver, Subjack, or custom detection
"""

import json
import logging
import sys
from typing import Dict, List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Get database connection using environment variables"""
    db_dsn = os.environ.get("DB_DSN", "postgresql://app:app@localhost:5432/scans")
    return psycopg2.connect(db_dsn)

def parse_subjack_results(data: Dict) -> List[Dict]:
    """Parse Subjack JSON output format"""
    findings = []

    # Subjack format: {"subdomain": "test.example.com", "service": "github", "status": "vulnerable"}
    if isinstance(data, list):
        for item in data:
            if item.get("status") == "vulnerable":
                findings.append({
                    "subdomain": item.get("subdomain", ""),
                    "service": item.get("service", "unknown"),
                    "status": "vulnerable",
                    "evidence": f"CNAME points to {item.get('service', 'unknown')} but service is unclaimed",
                    "confidence": "high"
                })

    return findings

def parse_subover_results(data: Dict) -> List[Dict]:
    """Parse SubOver JSON output format"""
    findings = []

    # SubOver format: {"subdomain": "test.example.com", "service": "S3", "response": "NoSuchBucket"}
    if isinstance(data, list):
        for item in data:
            if "vulnerable" in str(item).lower() or "takeover" in str(item).lower():
                findings.append({
                    "subdomain": item.get("subdomain", item.get("domain", "")),
                    "service": item.get("service", "unknown"),
                    "status": "vulnerable",
                    "evidence": item.get("response", "Subdomain takeover possible"),
                    "confidence": "high"
                })

    return findings

def parse_custom_takeover_results(data: Dict) -> List[Dict]:
    """Parse custom subdomain takeover detection results"""
    findings = []

    # Generic format
    if "findings" in data:
        for item in data["findings"]:
            if item.get("vulnerable", False):
                findings.append({
                    "subdomain": item.get("subdomain", item.get("domain", "")),
                    "service": item.get("service", item.get("provider", "unknown")),
                    "status": item.get("status", "vulnerable"),
                    "evidence": item.get("evidence", item.get("reason", "Subdomain takeover detected")),
                    "confidence": item.get("confidence", "medium")
                })

    return findings

def normalize_subdomain_takeover_finding(raw_finding: Dict, source: str, scan_id: str) -> Dict:
    """Normalize a subdomain takeover finding to our database schema"""

    subdomain = raw_finding.get("subdomain", "").strip()
    service = raw_finding.get("service", "unknown").lower()
    evidence = raw_finding.get("evidence", "")
    confidence = raw_finding.get("confidence", "medium")

    # Map confidence to severity
    severity_map = {
        "high": "high",
        "medium": "medium",
        "low": "low"
    }
    severity = severity_map.get(confidence, "medium")

    # Create title based on service
    title = f"Subdomain Takeover Possible - {service.title()}"
    if "s3" in service.lower():
        title = "AWS S3 Bucket Subdomain Takeover"
    elif "azure" in service.lower():
        title = "Azure Subdomain Takeover"
    elif "github" in service.lower():
        title = "GitHub Pages Subdomain Takeover"
    elif "heroku" in service.lower():
        title = "Heroku App Subdomain Takeover"

    # Build description
    description = f"Subdomain '{subdomain}' appears vulnerable to takeover via {service.title()}. "
    description += evidence if evidence else "CNAME record points to unclaimed service."

    return {
        "source": source,
        "scan_id": scan_id,
        "subdomain": subdomain,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "service_provider": service,
        "evidence": evidence,
        "risk_score": 8.0 if confidence == "high" else 6.0,
        "remediation": f"Either claim the {service.title()} service or remove the CNAME record for {subdomain}",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            "https://github.com/EdOverflow/can-i-take-over-xyz"
        ]
    }

def insert_subdomain_takeover_findings(findings: List[Dict], conn):
    """Insert subdomain takeover findings into recon_findings table"""
    if not findings:
        logger.info("No subdomain takeover findings to insert")
        return 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        inserted_count = 0

        for finding in findings:
            try:
                # Insert into recon_findings table with takeover-specific data
                cur.execute("""
                    INSERT INTO recon_findings (
                        source, scan_id, domain, subdomain, title, description,
                        severity, evidence_data, discovered_at, tags, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source, scan_id, domain, subdomain, title) DO UPDATE SET
                        description = EXCLUDED.description,
                        evidence_data = EXCLUDED.evidence_data,
                        discovered_at = EXCLUDED.discovered_at,
                        metadata = EXCLUDED.metadata
                """, (
                    finding["source"],
                    finding["scan_id"],
                    finding["subdomain"].split('.', 1)[-1] if '.' in finding["subdomain"] else finding["subdomain"],  # Extract domain
                    finding["subdomain"],
                    finding["title"],
                    finding["description"],
                    finding["severity"],
                    json.dumps({
                        "service_provider": finding["service_provider"],
                        "confidence": finding["confidence"],
                        "evidence": finding["evidence"],
                        "risk_score": finding["risk_score"]
                    }),
                    datetime.now(),
                    ["subdomain_takeover", "dns", "security"],
                    json.dumps({
                        "takeover_type": "subdomain",
                        "service_provider": finding["service_provider"],
                        "remediation": finding["remediation"],
                        "references": finding["references"]
                    })
                ))
                inserted_count += 1
                logger.info(f"Inserted takeover finding: {finding['subdomain']} -> {finding['service_provider']}")

            except Exception as e:
                logger.error(f"Error inserting subdomain takeover finding {finding['subdomain']}: {e}")
                continue

    conn.commit()
    logger.info(f"Inserted {inserted_count} subdomain takeover findings")
    return inserted_count

def parse_subdomain_takeover_file(file_path: str, source: str = "subdomain_takeover", scan_id: Optional[str] = None) -> int:
    """
    Parse a subdomain takeover results file and insert findings into database

    Args:
        file_path: Path to the subdomain takeover results file (JSON)
        source: Source identifier for the scan
        scan_id: Optional scan ID, if not provided will extract from filename

    Returns:
        Number of findings inserted
    """

    if not scan_id:
        # Extract scan_id from filename if not provided
        scan_id = os.path.basename(file_path).replace('.json', '')

    logger.info(f"Parsing subdomain takeover results from {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return 0
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return 0
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return 0

    # Try different parsing methods based on the data structure
    raw_findings = []

    # Try Subjack format first
    raw_findings = parse_subjack_results(data)

    # If no findings, try SubOver format
    if not raw_findings:
        raw_findings = parse_subover_results(data)

    # If still no findings, try custom format
    if not raw_findings:
        raw_findings = parse_custom_takeover_results(data)

    if not raw_findings:
        logger.warning(f"No subdomain takeover findings found in {file_path}")
        return 0

    # Normalize findings
    normalized_findings = []
    for raw_finding in raw_findings:
        try:
            normalized_finding = normalize_subdomain_takeover_finding(raw_finding, source, scan_id)
            normalized_findings.append(normalized_finding)
        except Exception as e:
            logger.error(f"Error normalizing finding {raw_finding}: {e}")
            continue

    # Insert into database
    if normalized_findings:
        try:
            with get_db_connection() as conn:
                return insert_subdomain_takeover_findings(normalized_findings, conn)
        except Exception as e:
            logger.error(f"Database error: {e}")
            return 0

    return 0

def main():
    """Command line interface for the parser"""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <subdomain_takeover_results.json>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        count = parse_subdomain_takeover_file(file_path)
        print(f"Successfully inserted {count} subdomain takeover findings")
    except Exception as e:
        logger.error(f"Error parsing subdomain takeover results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()