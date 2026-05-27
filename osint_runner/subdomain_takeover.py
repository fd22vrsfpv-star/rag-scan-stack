#!/usr/bin/env python3
"""
Subdomain Takeover Detection
Custom implementation to detect subdomain takeover vulnerabilities
"""

import asyncio
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional, Set
import aiohttp
import dns.resolver
import dns.exception
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Known vulnerable CNAME fingerprints for subdomain takeover
VULNERABLE_SERVICES = {
    # AWS S3
    "s3.amazonaws.com": {
        "service": "aws_s3",
        "indicators": ["NoSuchBucket", "The specified bucket does not exist"],
        "confidence": "high"
    },
    "s3-website": {
        "service": "aws_s3_website",
        "indicators": ["NoSuchBucket", "The specified bucket does not exist"],
        "confidence": "high"
    },
    # Azure
    "azurewebsites.net": {
        "service": "azure",
        "indicators": ["404 Not Found", "This site is currently unavailable"],
        "confidence": "high"
    },
    "cloudapp.azure.com": {
        "service": "azure",
        "indicators": ["404 Not Found", "This site is currently unavailable"],
        "confidence": "high"
    },
    # GitHub Pages
    "github.io": {
        "service": "github_pages",
        "indicators": ["There isn't a GitHub Pages site here", "404 Not Found"],
        "confidence": "high"
    },
    # Heroku
    "herokuapp.com": {
        "service": "heroku",
        "indicators": ["No such app", "This application does not exist"],
        "confidence": "high"
    },
    # Shopify
    "myshopify.com": {
        "service": "shopify",
        "indicators": ["Sorry, this shop is currently unavailable", "This shop is currently unavailable"],
        "confidence": "medium"
    },
    # Tumblr
    "tumblr.com": {
        "service": "tumblr",
        "indicators": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
        "confidence": "medium"
    },
    # Bitbucket
    "bitbucket.io": {
        "service": "bitbucket",
        "indicators": ["Repository not found", "This repository does not exist"],
        "confidence": "high"
    },
    # Fastly
    "fastly.com": {
        "service": "fastly",
        "indicators": ["Fastly error: unknown domain", "unknown domain"],
        "confidence": "high"
    },
    # HubSpot
    "hubspot.com": {
        "service": "hubspot",
        "indicators": ["This HubSpot portal does not exist", "Portal does not exist"],
        "confidence": "high"
    },
    # Surge.sh
    "surge.sh": {
        "service": "surge",
        "indicators": ["project not found", "Repository not found"],
        "confidence": "high"
    }
}

class SubdomainTakeoverDetector:
    def __init__(self, timeout: int = 30, user_agent: str = "SubTakeOver Scanner"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = None
        self.findings = []

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": self.user_agent}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def resolve_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME record for a subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for answer in answers:
                return str(answer.target).rstrip('.')
        except dns.exception.DNSException:
            pass
        return None

    def check_cname_vulnerability(self, cname: str) -> Optional[Dict]:
        """Check if CNAME points to a vulnerable service"""
        if not cname:
            return None

        for service_pattern, service_info in VULNERABLE_SERVICES.items():
            if service_pattern in cname.lower():
                return service_info

        return None

    async def check_http_response(self, subdomain: str) -> Optional[Dict]:
        """Check HTTP response for takeover indicators"""
        if not self.session:
            return None

        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{subdomain}"
                async with self.session.get(url, allow_redirects=True) as response:
                    content = await response.text()

                    # Check response indicators
                    for service_pattern, service_info in VULNERABLE_SERVICES.items():
                        for indicator in service_info["indicators"]:
                            if indicator.lower() in content.lower():
                                return {
                                    "service": service_info["service"],
                                    "confidence": service_info["confidence"],
                                    "evidence": f"HTTP response contains: {indicator}",
                                    "status_code": response.status,
                                    "url": url
                                }

                    # Check for generic 404s pointing to cloud services
                    if response.status == 404:
                        for service_pattern in VULNERABLE_SERVICES.keys():
                            if service_pattern in content.lower():
                                service_info = VULNERABLE_SERVICES[service_pattern]
                                return {
                                    "service": service_info["service"],
                                    "confidence": "medium",
                                    "evidence": f"404 response mentions {service_pattern}",
                                    "status_code": response.status,
                                    "url": url
                                }

            except Exception as e:
                logger.debug(f"HTTP check failed for {url}: {e}")
                continue

        return None

    async def check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Check a single subdomain for takeover vulnerability"""
        logger.info(f"Checking subdomain: {subdomain}")

        # Step 1: Check CNAME record
        cname = self.resolve_cname(subdomain)
        if not cname:
            logger.debug(f"No CNAME record found for {subdomain}")
            return None

        logger.debug(f"{subdomain} -> CNAME: {cname}")

        # Step 2: Check if CNAME points to vulnerable service
        cname_vuln = self.check_cname_vulnerability(cname)
        if not cname_vuln:
            logger.debug(f"CNAME {cname} not in vulnerable services list")
            return None

        # Step 3: Verify with HTTP response
        http_check = await self.check_http_response(subdomain)
        if not http_check:
            logger.debug(f"HTTP check did not confirm vulnerability for {subdomain}")
            return None

        # Vulnerability confirmed
        finding = {
            "subdomain": subdomain,
            "cname": cname,
            "service": http_check["service"],
            "confidence": http_check["confidence"],
            "evidence": http_check["evidence"],
            "status_code": http_check.get("status_code"),
            "url": http_check.get("url"),
            "vulnerable": True,
            "discovered_at": time.time()
        }

        logger.warning(f"TAKEOVER DETECTED: {subdomain} -> {cname} ({http_check['service']})")
        return finding

    async def scan_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Scan multiple subdomains for takeover vulnerabilities"""
        logger.info(f"Scanning {len(subdomains)} subdomains for takeover vulnerabilities")

        # Process subdomains in batches to avoid overwhelming services
        batch_size = 10
        findings = []

        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(subdomains) + batch_size - 1)//batch_size}")

            tasks = [self.check_subdomain(subdomain.strip()) for subdomain in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, dict) and result.get("vulnerable"):
                    findings.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Error checking subdomain: {result}")

            # Small delay between batches
            await asyncio.sleep(1)

        logger.info(f"Scan complete. Found {len(findings)} potential takeover vulnerabilities")
        return findings

def read_subdomains_from_file(file_path: str) -> List[str]:
    """Read subdomains from a text file"""
    subdomains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract domain from URL if needed
                    if line.startswith('http'):
                        parsed = urlparse(line)
                        subdomains.append(parsed.hostname)
                    else:
                        subdomains.append(line)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")

    return list(set(subdomains))  # Remove duplicates

async def main():
    """Main function for CLI usage"""
    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_takeover.py <subdomains_file> [output_file]")
        print("  subdomains_file: Text file with one subdomain per line")
        print("  output_file: Optional output JSON file (default: stdout)")
        sys.exit(1)

    subdomains_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Configuration from environment
    timeout = int(os.environ.get("TAKEOVER_TIMEOUT", "30"))
    user_agent = os.environ.get("TAKEOVER_USER_AGENT", "Mozilla/5.0 (SubTakeOver Scanner)")

    # Read subdomains
    subdomains = read_subdomains_from_file(subdomains_file)
    if not subdomains:
        logger.error("No subdomains found in input file")
        sys.exit(1)

    logger.info(f"Loaded {len(subdomains)} subdomains from {subdomains_file}")

    # Run scan
    async with SubdomainTakeoverDetector(timeout=timeout, user_agent=user_agent) as detector:
        findings = await detector.scan_subdomains(subdomains)

    # Prepare output
    output_data = {
        "scan_info": {
            "tool": "subdomain_takeover",
            "version": "1.0.0",
            "scan_time": time.time(),
            "total_subdomains": len(subdomains),
            "vulnerable_count": len(findings)
        },
        "findings": findings
    }

    # Output results
    output_json = json.dumps(output_data, indent=2)
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output_json)
            logger.info(f"Results written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing output file: {e}")
            print(output_json)
    else:
        print(output_json)

if __name__ == "__main__":
    asyncio.run(main())