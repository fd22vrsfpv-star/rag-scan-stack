"""
title: RAG-Scan-Stack All Tools
author: RAG-Scan-Stack
version: 1.0.1
description: Complete pentest toolkit - scanning, exploits, AI sessions, and utilities
build_date: 2026-02-02
tool_count: 30

================================================================================
                        RAG-SCAN-STACK TOOL REFERENCE
================================================================================

UTILITIES (4 tools):
  - echo(message)                    Echo back a message (test tool calling)
  - get_time()                       Get current server time
  - add(a, b)                        Add two numbers
  - check_health()                   Check all service health status

SCANNING (5 tools):
  - start_nmap_scan(target, scan_type, ports)    Start Nmap port scan
  - start_masscan(target, ports, rate)           Fast Masscan port discovery
  - start_nuclei_scan(target, severity)          Nuclei vulnerability scan
  - start_web_scan(target_url, wordlist)         Web scan (Gobuster + ZAP)
  - start_playwright_scan(target_url)            Browser-based security scan

SCAN STATUS (4 tools):
  - get_nmap_status(job_id)          Get Nmap/Masscan job status
  - get_nuclei_status(job_id)        Get Nuclei job status
  - get_web_scan_status(job_id)      Get web scan job status
  - get_active_jobs()                Get all active scan jobs

DATABASE QUERIES (3 tools):
  - query_ports(target)              Query discovered open ports
  - query_findings(severity, target) Query vulnerability findings
  - query_assets(asset_type)         Query discovered assets

EXPLOIT SEARCH (2 tools):
  - search_exploits(query, limit)              Semantic exploit search
  - search_exploits_enhanced(query, keywords)  Enhanced search with keywords

METASPLOIT (6 tools):
  - run_msf_module(module_path, rhosts, rport, payload)  Run MSF module
  - run_edb_script(edb_id, target, options)              Run ExploitDB script
  - list_msf_sessions()              List active Metasploit sessions
  - run_session_command(session_id, command)  Execute command in session
  - list_msf_jobs()                  List running MSF jobs
  - get_msf_status()                 Get Metasploit framework status

AI PENTEST SESSIONS (5 tools):
  - start_pentest_session(session_name, target, task)  Start AI pentest
  - get_session_status(session_id)   Get pentest session status
  - get_session_messages(session_id) Get session conversation history
  - list_sessions(status)            List all pentest sessions
  - stop_session(session_id)         Stop a running session

RECOMMENDATIONS (1 tool):
  - get_recommendation(target)       Get AI-powered next scan recommendation

================================================================================
"""

import json
import requests
from datetime import datetime
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        RAG_API_URL: str = Field(default="https://rag-api:8000", description="RAG API URL")
        API_KEY: str = Field(default="changeme", description="API key")

    def __init__(self):
        self.valves = self.Valves()

    # ==========================================================================
    #                              UTILITIES
    # ==========================================================================

    def echo(self, message: str) -> str:
        """
        Echo back a message. Test that tools are working.

        :param message: Message to echo
        :return: Echoed message
        """
        return f"Echo: {message}"

    def get_time(self) -> str:
        """
        Get current server time.

        :return: Current datetime
        """
        return f"Current time: {datetime.now().isoformat()}"

    def add(self, a: float, b: float) -> str:
        """
        Add two numbers.

        :param a: First number
        :param b: Second number
        :return: Sum
        """
        return f"{a} + {b} = {a + b}"

    def check_health(self) -> str:
        """
        Check health of all RAG-Scan-Stack services.

        :return: Service status
        """
        services = {
            "mcp_server": "https://mcp-server:8016/health",
            "autogen_agents": "https://autogen-agents:8015/health",
            "rag_api": "https://rag-api:8000/health",
            "nmap_scanner": "https://nmap_scanner:8012/health",
            "nuclei_runner": "https://nuclei-runner:8011/health",
            "web_scanner": "https://web-scanner:8010/health",
            "exploit_runner": "https://exploit-runner:8017/health",
            "playwright": "https://playwright-scanner:8014/health",
        }
        results = {}
        for name, url in services.items():
            try:
                r = requests.get(url, timeout=5)
                results[name] = "healthy" if r.status_code == 200 else "unhealthy"
            except:
                results[name] = "unreachable"
        return json.dumps(results, indent=2)

    # ==========================================================================
    #                              SCANNING
    # ==========================================================================

    def start_nmap_scan(self, target: str, scan_type: str = "default", ports: str = None) -> str:
        """
        Start Nmap port scan.

        :param target: IP, hostname, or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)
        :param scan_type: default, quick, full, stealth, udp
        :param ports: Specific ports (e.g., 22,80,443 or 1-1000)
        :return: Job ID
        """
        data = {"target": target, "scan_type": scan_type}
        if ports:
            data["ports"] = ports
        try:
            r = requests.post("https://nmap_scanner:8012/scan", json=data, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def start_masscan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> str:
        """
        Start fast Masscan port discovery.

        :param target: IP or CIDR range
        :param ports: Port range (default: 1-65535)
        :param rate: Packets per second
        :return: Job ID
        """
        try:
            r = requests.post("https://nmap_scanner:8012/masscan",
                json={"target": target, "ports": ports, "rate": rate}, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def start_nuclei_scan(self, target: str, severity: str = None) -> str:
        """
        Start Nuclei vulnerability scan.

        :param target: Target URL (e.g., http://192.168.1.1)
        :param severity: Filter: info, low, medium, high, critical
        :return: Job ID
        """
        data = {"target": target}
        if severity:
            data["severity"] = severity
        try:
            r = requests.post("https://nuclei-runner:8011/scan", json=data, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def start_web_scan(self, target_url: str, wordlist: str = "common") -> str:
        """
        Start web scan with Gobuster + ZAP.

        :param target_url: Target URL
        :param wordlist: common, medium, large
        :return: Job ID
        """
        try:
            r = requests.post("https://web-scanner:8010/scan",
                json={"target_url": target_url, "wordlist": wordlist}, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def start_playwright_scan(self, target_url: str) -> str:
        """
        Start Playwright browser-based security scan.

        :param target_url: Target URL
        :return: Job ID
        """
        try:
            r = requests.post("https://playwright-scanner:8014/scan",
                json={"url": target_url}, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    # ==========================================================================
    #                           SCAN STATUS
    # ==========================================================================

    def get_nmap_status(self, job_id: str) -> str:
        """
        Get Nmap/Masscan job status.

        :param job_id: Job ID from scan start
        :return: Job status and results
        """
        try:
            r = requests.get(f"https://nmap_scanner:8012/job/{job_id}", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_nuclei_status(self, job_id: str) -> str:
        """
        Get Nuclei job status.

        :param job_id: Job ID
        :return: Status and findings
        """
        try:
            r = requests.get(f"https://nuclei-runner:8011/job/{job_id}", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_web_scan_status(self, job_id: str) -> str:
        """
        Get web scan job status.

        :param job_id: Job ID
        :return: Status and results
        """
        try:
            r = requests.get(f"https://web-scanner:8010/job/{job_id}", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_active_jobs(self) -> str:
        """
        Get all active scan jobs across all scanners.

        :return: Active jobs
        """
        results = {}
        scanners = [
            ("nmap", "https://nmap_scanner:8012/jobs"),
            ("nuclei", "https://nuclei-runner:8011/jobs"),
            ("web", "https://web-scanner:8010/jobs"),
            ("playwright", "https://playwright-scanner:8014/jobs"),
        ]
        for name, url in scanners:
            try:
                r = requests.get(url, timeout=10)
                results[name] = r.json()
            except:
                results[name] = "unreachable"
        return json.dumps(results, indent=2)

    # ==========================================================================
    #                         DATABASE QUERIES
    # ==========================================================================

    def query_ports(self, target: str = None) -> str:
        """
        Query discovered open ports from database.

        :param target: Optional target IP filter
        :return: Discovered ports and services
        """
        params = {"target": target} if target else {}
        try:
            r = requests.get(f"{self.valves.RAG_API_URL}/ports", params=params,
                headers={"X-API-Key": self.valves.API_KEY}, timeout=30)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def query_findings(self, severity: str = None, target: str = None) -> str:
        """
        Query vulnerability findings.

        :param severity: Filter: info, low, medium, high, critical
        :param target: Optional target filter
        :return: Vulnerability findings
        """
        params = {}
        if severity:
            params["severity"] = severity
        if target:
            params["target"] = target
        try:
            r = requests.get(f"{self.valves.RAG_API_URL}/findings", params=params,
                headers={"X-API-Key": self.valves.API_KEY}, timeout=30)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def query_assets(self, asset_type: str = None) -> str:
        """
        Query discovered assets.

        :param asset_type: Filter by type: host, service, url
        :return: Discovered assets
        """
        params = {"type": asset_type} if asset_type else {}
        try:
            r = requests.get(f"{self.valves.RAG_API_URL}/assets", params=params,
                headers={"X-API-Key": self.valves.API_KEY}, timeout=30)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    # ==========================================================================
    #                          EXPLOIT SEARCH
    # ==========================================================================

    def search_exploits(self, query: str, limit: int = 10) -> str:
        """
        Search exploit database using semantic search (RAG).

        :param query: Search query (e.g., Apache RCE, SSH bypass, SMB vuln)
        :param limit: Max results
        :return: Matching exploits
        """
        try:
            r = requests.post(f"{self.valves.RAG_API_URL}/search",
                json={"query": query, "limit": limit},
                headers={"X-API-Key": self.valves.API_KEY}, timeout=30)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def search_exploits_enhanced(self, query: str, keywords: str = None) -> str:
        """
        Enhanced exploit search with keyword + semantic matching.

        :param query: Semantic search query
        :param keywords: Additional keywords to filter
        :return: Matching exploits
        """
        data = {"query": query}
        if keywords:
            data["keywords"] = keywords
        try:
            r = requests.post(f"{self.valves.RAG_API_URL}/search/enhanced",
                json=data, headers={"X-API-Key": self.valves.API_KEY}, timeout=30)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    # ==========================================================================
    #                            METASPLOIT
    # ==========================================================================

    def run_msf_module(self, module_path: str, rhosts: str, rport: int = None, payload: str = None) -> str:
        """
        Run a Metasploit module.

        :param module_path: Module path (e.g., exploit/unix/ftp/vsftpd_234_backdoor)
        :param rhosts: Target host(s)
        :param rport: Target port (optional)
        :param payload: Payload (optional, e.g., cmd/unix/interact)
        :return: Job status
        """
        data = {"module_path": module_path, "rhosts": rhosts}
        if rport:
            data["rport"] = rport
        if payload:
            data["payload"] = payload
        try:
            r = requests.post("https://exploit-runner:8017/run_msf", json=data, timeout=60, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def run_edb_script(self, edb_id: str, target: str, options: str = None) -> str:
        """
        Run an ExploitDB script by EDB-ID.

        :param edb_id: ExploitDB ID (e.g., 12345)
        :param target: Target host/URL
        :param options: Additional options
        :return: Execution result
        """
        data = {"edb_id": edb_id, "target": target}
        if options:
            data["options"] = options
        try:
            r = requests.post("https://exploit-runner:8017/run_edb", json=data, timeout=60, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def list_msf_sessions(self) -> str:
        """
        List active Metasploit sessions (shells, meterpreter).

        :return: Active sessions
        """
        try:
            r = requests.get("https://exploit-runner:8017/sessions", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def run_session_command(self, session_id: str, command: str) -> str:
        """
        Execute command in active Metasploit session.

        :param session_id: Session ID
        :param command: Command to run
        :return: Command output
        """
        try:
            r = requests.post("https://exploit-runner:8017/session_command",
                json={"session_id": session_id, "command": command}, timeout=60, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def list_msf_jobs(self) -> str:
        """
        List running Metasploit jobs.

        :return: Active MSF jobs
        """
        try:
            r = requests.get("https://exploit-runner:8017/msf_jobs", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_msf_status(self) -> str:
        """
        Get Metasploit framework status.

        :return: MSF status, sessions, jobs
        """
        try:
            r = requests.get("https://exploit-runner:8017/status", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    # ==========================================================================
    #                        AI PENTEST SESSIONS
    # ==========================================================================

    def start_pentest_session(self, session_name: str, target: str, task: str) -> str:
        """
        Start autonomous AI-powered pentest session.

        :param session_name: Name for this session
        :param target: Target description (IP, hostname, or description)
        :param task: Initial task for AI agents
        :return: Session ID
        """
        try:
            r = requests.post("https://autogen-agents:8015/start_session",
                json={
                    "session_name": session_name,
                    "target_description": target,
                    "initial_task": task,
                    "max_rounds": 200
                }, timeout=60, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_session_status(self, session_id: str) -> str:
        """
        Get pentest session status.

        :param session_id: Session UUID
        :return: Session status and details
        """
        try:
            r = requests.get(f"https://autogen-agents:8015/session/{session_id}", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def get_session_messages(self, session_id: str) -> str:
        """
        Get conversation history from pentest session.

        :param session_id: Session UUID
        :return: Message history
        """
        try:
            r = requests.get(f"https://autogen-agents:8015/session/{session_id}/messages", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def list_sessions(self, status: str = None) -> str:
        """
        List all pentest sessions.

        :param status: Filter: active, completed, failed, stopped
        :return: Session list
        """
        params = {"status": status} if status else {}
        try:
            r = requests.get("https://autogen-agents:8015/sessions", params=params, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def stop_session(self, session_id: str) -> str:
        """
        Stop a running pentest session.

        :param session_id: Session UUID
        :return: Stop confirmation
        """
        try:
            r = requests.post(f"https://autogen-agents:8015/session/{session_id}/stop", timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    # ==========================================================================
    #                          RECOMMENDATIONS
    # ==========================================================================

    def get_recommendation(self, target: str = None) -> str:
        """
        Get AI-powered recommendation for next scan/action.

        :param target: Optional target to get recommendations for
        :return: Recommended next steps
        """
        params = {"target": target} if target else {}
        try:
            r = requests.get("https://scan-recommender:8013/recommend", params=params, timeout=30, verify=False)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"
