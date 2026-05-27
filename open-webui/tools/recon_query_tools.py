"""
title: Recon & Query Tools
author: RAG-Scan-Stack
version: 2.0.0
description: OSINT reconnaissance, asset/port/finding queries, and exploit search
"""

import json
import requests
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        RAG_API_URL: str = Field(
            default="https://rag-api:8000",
            description="URL of the RAG API"
        )
        OSINT_URL: str = Field(
            default="https://osint-runner:8024",
            description="URL of the OSINT runner (subfinder, dnsx, asnmap)"
        )
        SCAN_RECOMMENDER_URL: str = Field(
            default="https://scan-recommender:8013",
            description="URL of the scan recommender"
        )
        API_KEY: str = Field(
            default="changeme",
            description="API key for RAG API"
        )

    def __init__(self):
        self.valves = self.Valves()

    def _api_headers(self):
        return {"X-API-Key": self.valves.API_KEY}

    def start_subfinder(self, domains: str) -> str:
        """
        Start passive subdomain enumeration to discover subdomains of a target domain.

        :param domains: Comma-separated domain names (e.g., 'example.com,target.org')
        :return: Job ID for tracking
        """
        try:
            domain_list = [d.strip() for d in domains.split(",")]
            r = requests.post(
                f"{self.valves.OSINT_URL}/jobs/subfinder",
                json={"domains": domain_list},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_dnsx(self, domains: str, record_types: str = "a,aaaa,cname,mx") -> str:
        """
        Start DNS resolution and enumeration for domains.

        :param domains: Comma-separated domain names to resolve
        :param record_types: DNS record types to query (e.g., 'a,aaaa,cname,mx,ns,txt')
        :return: Job ID for tracking
        """
        try:
            domain_list = [d.strip() for d in domains.split(",")]
            r = requests.post(
                f"{self.valves.OSINT_URL}/jobs/dnsx",
                json={"domains": domain_list, "record_types": record_types},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_asnmap(self, targets: str) -> str:
        """
        Map ASN numbers to CIDR ranges for network discovery.

        :param targets: Comma-separated ASN numbers, IPs, or domains
        :return: Job ID for tracking
        """
        try:
            target_list = [t.strip() for t in targets.split(",")]
            r = requests.post(
                f"{self.valves.OSINT_URL}/jobs/asnmap",
                json={"targets": target_list},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def query_assets(self, ip: str = None) -> str:
        """
        Query discovered assets (hosts) from the database.

        :param ip: Filter by IP pattern (optional)
        :return: List of discovered assets
        """
        try:
            params = {"limit": 100}
            if ip:
                params["ip"] = ip
            r = requests.get(
                f"{self.valves.RAG_API_URL}/assets",
                params=params,
                headers=self._api_headers(),
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def query_open_ports(self, ip: str = None) -> str:
        """
        Query discovered open ports and services from the database.

        :param ip: Filter by IP address (optional)
        :return: List of open ports with service details
        """
        try:
            params = {"limit": 100}
            if ip:
                params["ip"] = ip
            r = requests.get(
                f"{self.valves.RAG_API_URL}/ports/open",
                params=params,
                headers=self._api_headers(),
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def query_findings(self, severity: str = None, ip: str = None) -> str:
        """
        Query vulnerability findings from all scanners.

        :param severity: Filter by severity (info, low, medium, high, critical)
        :param ip: Filter by IP address
        :return: List of vulnerability findings
        """
        try:
            params = {"limit": 100}
            if severity:
                params["severity"] = severity
            if ip:
                params["ip"] = ip
            r = requests.get(
                f"{self.valves.RAG_API_URL}/vulns",
                params=params,
                headers=self._api_headers(),
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def search_exploits(self, query: str) -> str:
        """
        Search the exploit database using semantic search (RAG).

        :param query: Search query (e.g., 'vsftpd 2.3.4 backdoor', 'Apache RCE', 'CVE-2021-44228')
        :return: Matching exploits with details
        """
        try:
            r = requests.get(
                f"{self.valves.SCAN_RECOMMENDER_URL}/rag/ask",
                params={"q": query, "top_k": 10},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_next_scan_recommendation(self, target_ip: str = None) -> str:
        """
        Get AI-powered recommendation for what to scan next based on current findings.

        :param target_ip: Target IP to get recommendations for
        :return: Recommended next scan action
        """
        try:
            params = {}
            if target_ip:
                params["target"] = target_ip
            r = requests.get(
                f"{self.valves.SCAN_RECOMMENDER_URL}/next_scan",
                params=params,
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})
