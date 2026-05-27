"""
title: Status & Health Tools
author: RAG-Scan-Stack
version: 2.0.0
description: Service health checks and active job monitoring across all scanners
"""

import json
import requests
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        AUTOGEN_URL: str = Field(
            default="https://autogen-agents:8015",
            description="URL of the autogen-agents service"
        )
        RAG_API_URL: str = Field(
            default="https://rag-api:8000",
            description="URL of the RAG API"
        )
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
        EXPLOIT_RUNNER_URL: str = Field(
            default="https://exploit-runner:8017",
            description="URL of the exploit runner"
        )
        PD_RUNNER_URL: str = Field(
            default="https://pd-runner:8023",
            description="URL of the PD runner"
        )
        OSINT_URL: str = Field(
            default="https://osint-runner:8024",
            description="URL of the OSINT runner"
        )
        BRUTUS_URL: str = Field(
            default="https://brutus-runner:8025",
            description="URL of the Brutus credential runner"
        )
        SCAN_RECOMMENDER_URL: str = Field(
            default="https://scan-recommender:8013",
            description="URL of the scan recommender"
        )

    def __init__(self):
        self.valves = self.Valves()

    def check_services_health(self) -> str:
        """
        Check the health of all RAG-Scan-Stack services.

        :return: Status of all services (healthy/unhealthy/unreachable)
        """
        services = {
            "autogen_agents": f"{self.valves.AUTOGEN_URL}/health",
            "rag_api": f"{self.valves.RAG_API_URL}/health",
            "nmap_scanner": f"{self.valves.NMAP_URL}/health",
            "nuclei_runner": f"{self.valves.NUCLEI_URL}/health",
            "web_scanner": f"{self.valves.WEB_SCANNER_URL}/health",
            "exploit_runner": f"{self.valves.EXPLOIT_RUNNER_URL}/health",
            "pd_runner": f"{self.valves.PD_RUNNER_URL}/health",
            "osint_runner": f"{self.valves.OSINT_URL}/health",
            "brutus_runner": f"{self.valves.BRUTUS_URL}/health",
            "scan_recommender": f"{self.valves.SCAN_RECOMMENDER_URL}/health",
        }
        results = {}
        for name, url in services.items():
            try:
                r = requests.get(url, timeout=5)
                results[name] = "healthy" if r.status_code == 200 else f"unhealthy ({r.status_code})"
            except:
                results[name] = "unreachable"
        return json.dumps(results, indent=2)

    def get_active_jobs(self) -> str:
        """
        Get status of all active scan jobs across all scanners.

        :return: Active jobs from nmap, nuclei, web, pd-runner, osint, brutus
        """
        results = {}
        scanners = [
            ("nmap", f"{self.valves.NMAP_URL}/jobs"),
            ("nuclei", f"{self.valves.NUCLEI_URL}/jobs"),
            ("web", f"{self.valves.WEB_SCANNER_URL}/jobs"),
            ("pd_runner", f"{self.valves.PD_RUNNER_URL}/jobs"),
            ("osint", f"{self.valves.OSINT_URL}/jobs"),
            ("brutus", f"{self.valves.BRUTUS_URL}/jobs"),
        ]
        for name, url in scanners:
            try:
                r = requests.get(url, timeout=10)
                results[name] = r.json()
            except:
                results[name] = "unreachable"
        return json.dumps(results, indent=2)
