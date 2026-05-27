"""
title: Scanning Tools
author: RAG-Scan-Stack
version: 2.0.0
description: Port scanning, vulnerability scanning, and web application scanning tools
"""

import json
import requests
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        NMAP_URL: str = Field(
            default="https://nmap_scanner:8012",
            description="URL of the Nmap scanner"
        )
        NUCLEI_URL: str = Field(
            default="https://nuclei-runner:8011",
            description="URL of the Nuclei runner"
        )
        WEB_SCANNER_URL: str = Field(
            default="https://web-scanner:8010",
            description="URL of the web scanner"
        )
        PD_RUNNER_URL: str = Field(
            default="https://pd-runner:8023",
            description="URL of the PD runner (httpx, naabu, katana, tlsx)"
        )

    def __init__(self):
        self.valves = self.Valves()

    def start_masscan(self, target: str, ports: str = "1-1000", rate: int = 1000) -> str:
        """
        Start a fast Masscan port discovery scan. Use this FIRST for quick port enumeration.

        :param target: Target IP address or CIDR range (e.g., '192.168.1.0/24')
        :param ports: Port range to scan (e.g., '1-1000', '1-65535', '22,80,443')
        :param rate: Packets per second (default: 1000)
        :return: Job ID for tracking
        """
        try:
            r = requests.post(
                f"{self.valves.NMAP_URL}/jobs/masscan-only",
                json={"targets": [target], "ports": ports, "rate": rate},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_nmap_scan(self, target: str, ports: str = "1-1000") -> str:
        """
        Start an Nmap scan with service detection. Run AFTER masscan finds open ports.

        :param target: Target IP, hostname, or CIDR range
        :param ports: Port range to scan (e.g., '22,80,443' or '1-1000')
        :return: Job ID for tracking
        """
        try:
            r = requests.post(
                f"{self.valves.NMAP_URL}/jobs/masscan-then-nmap",
                json={"targets": [target], "ports": ports, "rate": 1000},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_naabu(self, targets: str, ports: str = "1-1000") -> str:
        """
        Start a fast port scan using Naabu (alternative to Masscan/Nmap).

        :param targets: Comma-separated IPs or CIDR ranges
        :param ports: Port specification (e.g., '80,443', '1-1000')
        :return: Job ID for tracking
        """
        try:
            target_list = [t.strip() for t in targets.split(",")]
            r = requests.post(
                f"{self.valves.PD_RUNNER_URL}/jobs/naabu",
                json={"targets": target_list, "ports": ports},
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_nuclei_scan(self, target: str = None, severity: str = "medium,high,critical") -> str:
        """
        Start a Nuclei vulnerability scan. Scans from database targets if no target specified.

        :param target: Target IP or URL (optional - uses discovered targets if omitted)
        :param severity: Severity filter (e.g., 'medium,high,critical')
        :return: Job ID for tracking
        """
        try:
            payload = {"severity": severity}
            if target:
                payload["target"] = target
            else:
                payload["limit"] = 25
            r = requests.post(
                f"{self.valves.NUCLEI_URL}/jobs/nuclei-scan",
                json=payload,
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_web_scan(self, target_url: str = None) -> str:
        """
        Start a web scan with Gobuster directory bruteforcing and ZAP proxy scanning.

        :param target_url: Target URL (e.g., 'http://192.168.1.150'). Scans from DB if omitted.
        :return: Job ID for tracking
        """
        try:
            payload = {"do_gobuster": True, "do_zap": True, "limit": 25}
            if target_url:
                payload["target_url"] = target_url
            r = requests.post(
                f"{self.valves.WEB_SCANNER_URL}/jobs/web-scan",
                json=payload,
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_httpx_probe(self, targets: str = "from_db", ports: str = None) -> str:
        """
        Probe HTTP services for live hosts, status codes, titles, and technology detection.

        :param targets: Comma-separated targets or 'from_db' to use discovered assets
        :param ports: Ports to probe (e.g., '80,443,8080')
        :return: Job ID for tracking
        """
        try:
            if targets == "from_db":
                payload = {"targets": "from_db"}
            else:
                payload = {"targets": [t.strip() for t in targets.split(",")]}
            if ports:
                payload["ports"] = ports
            payload["tech_detect"] = True
            r = requests.post(
                f"{self.valves.PD_RUNNER_URL}/jobs/httpx",
                json=payload,
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def start_katana(self, targets: str = "from_db", depth: int = 3) -> str:
        """
        Crawl web applications to discover endpoints, forms, and JavaScript files.

        :param targets: Comma-separated URLs or 'from_db' to use discovered web assets
        :param depth: Maximum crawl depth (default: 3)
        :return: Job ID for tracking
        """
        try:
            if targets == "from_db":
                payload = {"targets": "from_db"}
            else:
                payload = {"targets": [t.strip() for t in targets.split(",")]}
            payload["depth"] = depth
            payload["js_crawl"] = True
            r = requests.post(
                f"{self.valves.PD_RUNNER_URL}/jobs/katana",
                json=payload,
                timeout=30
            )
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})
