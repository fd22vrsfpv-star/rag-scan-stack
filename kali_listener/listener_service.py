"""
Kali Listener Service - FastAPI service for managing reverse shell listeners.
Handles nc/socat listeners and captures callback connections.
"""

import os
import uuid
import signal
import subprocess
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from log_manager import setup_logging, get_log_handler

# Configuration
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
PORT_START = int(os.environ.get("LISTENER_PORT_START", "9080"))
PORT_END = int(os.environ.get("LISTENER_PORT_END", "9180"))
API_PORT = int(os.environ.get("API_PORT", "8019"))

# Logger
logger = setup_logging("kali-listener")

# Track active listeners in memory
active_listeners: Dict[str, Dict[str, Any]] = {}


# --- Pydantic Models ---

class ListenerStartRequest(BaseModel):
    port: int = Field(..., ge=PORT_START, le=PORT_END, description="Port for listener")
    listener_type: str = Field(default="nc", description="Type: nc or socat")
    pending_exploit_id: Optional[str] = Field(None, description="UUID of pending exploit")
    timeout: int = Field(default=300, ge=30, le=3600, description="Timeout in seconds")

class ListenerResponse(BaseModel):
    id: str
    listener_type: str
    port: int
    status: str
    pid: Optional[int] = None
    pending_exploit_id: Optional[str] = None
    started_at: Optional[str] = None

class CallbackRegisterRequest(BaseModel):
    pending_exploit_id: str
    listener_id: str
    callback_type: str = Field(default="reverse_shell")
    validation_commands: List[str] = Field(default=["whoami", "id", "hostname"])

class CallbackResponse(BaseModel):
    id: str
    pending_exploit_id: str
    listener_id: str
    callback_type: str
    validation_status: str
    validation_output: Optional[str] = None
    parsed_validation: Optional[Dict[str, Any]] = None
    received_at: Optional[str] = None

class ListenerListResponse(BaseModel):
    listeners: List[ListenerResponse]
    total: int

class LogEntry(BaseModel):
    timestamp: str
    level: str
    logger: str
    message: str


# --- Tool Execution Models ---

class ToolExecuteRequest(BaseModel):
    """Request to execute a pentest tool."""
    tool: str = Field(..., description="Tool name (nmap, hydra, nikto, etc.)")
    command: str = Field(..., description="Full command to execute")
    target: str = Field(..., description="Target IP/hostname")
    port: Optional[int] = Field(None, description="Target port if applicable")
    timeout: int = Field(default=300, ge=30, le=3600, description="Execution timeout in seconds")
    scan_id: Optional[str] = Field(None, description="Associated scan ID for result linking")
    service: Optional[str] = Field(None, description="Service being tested")


class ToolExecutionResponse(BaseModel):
    """Response for tool execution."""
    id: str
    tool: str
    command: str
    target: str
    port: Optional[int] = None
    status: str  # pending, running, completed, failed, timeout
    exit_code: Optional[int] = None
    output: Optional[str] = None
    error: Optional[str] = None
    parsed_results: Optional[Dict[str, Any]] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class ToolExecutionListResponse(BaseModel):
    """List of tool executions."""
    executions: List[ToolExecutionResponse]
    total: int

class HealthResponse(BaseModel):
    status: str
    service: str
    active_listeners: int
    port_range: str


# --- Structured Job Models (NetExec, Impacket, Hashcat) ---

class NetExecReq(BaseModel):
    targets: List[str]
    protocol: str = Field(default="smb", description="smb, ldap, winrm, mssql, rdp, ssh, ftp")
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None                 # NTLM hash for pass-the-hash
    domain: Optional[str] = None
    module: Optional[str] = None               # spider_plus, enum_shares, etc.
    options: Optional[str] = None              # extra module options
    timeout: int = Field(default=600, ge=30, le=3600)

class ImpacketReq(BaseModel):
    tool: str = Field(..., description="secretsdump, psexec, wmiexec, smbexec, GetUserSPNs, GetNPUsers")
    target: str
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None                 # NTLM hash
    domain: Optional[str] = None
    extra_args: Optional[str] = None
    timeout: int = Field(default=600, ge=30, le=3600)

class HashcatReq(BaseModel):
    hashes: List[str]                           # hash strings to crack
    hash_type: int = Field(default=0, description="Hashcat mode: 0=md5, 1000=ntlm, 13100=kerberoast, 18200=asreproast, 5600=netntlmv2")
    wordlist: Optional[str] = "/app/wordlists/rockyou.txt"
    rules: Optional[str] = None
    timeout: int = Field(default=3600, ge=60, le=7200)

class JobResponse(BaseModel):
    ok: bool = True
    job_id: str
    status: str = "queued"
    status_url: str


# --- Structured Job Tracking ---

API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")

# Whitelisted impacket tool names → binary names
IMPACKET_TOOLS = {
    "secretsdump": "impacket-secretsdump",
    "psexec": "impacket-psexec",
    "wmiexec": "impacket-wmiexec",
    "smbexec": "impacket-smbexec",
    "GetUserSPNs": "impacket-GetUserSPNs",
    "GetNPUsers": "impacket-GetNPUsers",
}

# Hash type name → hashcat mode
HASH_TYPE_MAP = {
    "md5": 0, "ntlm": 1000, "kerberoast": 13100,
    "asreproast": 18200, "netntlmv2": 5600,
}

structured_jobs: Dict[str, Dict[str, Any]] = {}

import tempfile, pathlib, requests as req_lib

REPORT_DIR = pathlib.Path("/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _ingest_results(tool: str, output_path: str, job_id: str = None, **extra_params) -> dict:
    """POST results file to rag-api ingest endpoint."""
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return {"ok": True, "skipped": "no output"}
    try:
        files = {"file": (f"{tool}.txt", open(output_path, "rb"), "application/octet-stream")}
        headers = {"x-api-key": API_KEY}
        params = {}
        if job_id:
            params["job_id"] = job_id
        params.update(extra_params)
        r = req_lib.post(f"{API_BASE}/ingest/{tool}", files=files, headers=headers, params=params, timeout=300)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"Ingest to /ingest/{tool} failed: {e}")
        return {"ok": False, "error": str(e)}


async def _run_structured_job(job_id: str, tool: str, cmd: list, output_file: str,
                               ingest_as: str = None, timeout: int = 600, **ingest_params):
    """Run a structured job command and ingest results."""
    logger.info(f"[{job_id[:8]}] Running {tool}: {' '.join(cmd)}")
    structured_jobs[job_id]["status"] = "running"
    structured_jobs[job_id]["started_at"] = datetime.now().isoformat()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            structured_jobs[job_id]["status"] = "timeout"
            structured_jobs[job_id]["error"] = f"Timed out after {timeout}s"
            structured_jobs[job_id]["completed_at"] = datetime.now().isoformat()
            return

        exit_code = proc.returncode
        out_text = stdout.decode("utf-8", errors="replace")
        err_text = stderr.decode("utf-8", errors="replace")

        # If no separate output file, write stdout to one
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            if out_text.strip():
                with open(output_file, "w") as f:
                    f.write(out_text)

        findings_count = 0
        if os.path.exists(output_file):
            with open(output_file) as f:
                findings_count = sum(1 for line in f if line.strip())

        # Ingest
        ingest_tool = ingest_as or tool
        ing = _ingest_results(ingest_tool, output_file, job_id=job_id, **ingest_params)

        structured_jobs[job_id].update({
            "status": "completed" if exit_code in (0, 1) else "failed",
            "exit_code": exit_code,
            "findings_count": findings_count,
            "ingest": ing,
            "completed_at": datetime.now().isoformat(),
        })
        if exit_code not in (0, 1):
            structured_jobs[job_id]["error"] = err_text[:500]

        logger.info(f"[{job_id[:8]}] {tool} completed: exit={exit_code}, findings={findings_count}")

    except Exception as e:
        structured_jobs[job_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat(),
        })
        logger.error(f"[{job_id[:8]}] {tool} failed: {e}")


# --- Database Functions ---

def get_db_connection():
    """Get database connection."""
    return psycopg2.connect(DB_DSN)


def db_create_listener(listener_id: str, listener_type: str, port: int,
                       pending_exploit_id: Optional[str] = None) -> None:
    """Create listener record in database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO active_listeners
                (id, listener_type, port, status, pending_exploit_id, started_at)
                VALUES (%s, %s, %s, 'pending', %s, now())
            """, (listener_id, listener_type, port, pending_exploit_id))
        conn.commit()
    finally:
        conn.close()


def db_update_listener_status(listener_id: str, status: str, pid: Optional[int] = None) -> None:
    """Update listener status in database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if status == 'stopped':
                cur.execute("""
                    UPDATE active_listeners
                    SET status = %s, stopped_at = now()
                    WHERE id = %s
                """, (status, listener_id))
            else:
                cur.execute("""
                    UPDATE active_listeners
                    SET status = %s, pid = %s
                    WHERE id = %s
                """, (status, pid, listener_id))
        conn.commit()
    finally:
        conn.close()


def db_get_active_listeners() -> List[Dict]:
    """Get all active listeners from database."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, listener_type, port, status, pid, pending_exploit_id,
                       started_at, stopped_at
                FROM active_listeners
                WHERE status IN ('pending', 'active')
                ORDER BY started_at DESC
            """)
            return cur.fetchall()
    finally:
        conn.close()


def db_register_callback(callback_id: str, pending_exploit_id: str, listener_id: str,
                        callback_type: str, validation_commands: List[str]) -> None:
    """Register expected callback in database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO exploit_callbacks
                (id, pending_exploit_id, listener_id, callback_type,
                 validation_status, validation_commands)
                VALUES (%s, %s, %s, %s, 'pending', %s)
            """, (callback_id, pending_exploit_id, listener_id, callback_type,
                  json.dumps(validation_commands)))
        conn.commit()
    finally:
        conn.close()


def db_update_callback(callback_id: str, validation_status: str,
                      validation_output: Optional[str] = None,
                      parsed_validation: Optional[Dict] = None) -> None:
    """Update callback with validation results."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE exploit_callbacks
                SET validation_status = %s, validation_output = %s,
                    parsed_validation = %s, received_at = now()
                WHERE id = %s
            """, (validation_status, validation_output,
                  json.dumps(parsed_validation) if parsed_validation else None,
                  callback_id))
        conn.commit()
    finally:
        conn.close()


def db_get_callback_by_exploit(pending_exploit_id: str) -> Optional[Dict]:
    """Get callback record for a pending exploit."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, pending_exploit_id, listener_id, callback_type,
                       validation_status, validation_output, parsed_validation,
                       received_at
                FROM exploit_callbacks
                WHERE pending_exploit_id = %s
                ORDER BY received_at DESC NULLS LAST
                LIMIT 1
            """, (pending_exploit_id,))
            return cur.fetchone()
    finally:
        conn.close()


# --- Tool Execution Database Functions ---

def db_create_tool_execution(exec_id: str, tool: str, command: str, target: str,
                             port: Optional[int], scan_id: Optional[str],
                             service: Optional[str]) -> None:
    """Create a tool execution record in database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tool_executions
                (id, tool, command, target, port, scan_id, service, status, started_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', now())
            """, (exec_id, tool, command, target, port, scan_id, service))
        conn.commit()
    finally:
        conn.close()


def db_update_tool_execution(exec_id: str, status: str, exit_code: Optional[int] = None,
                             output: Optional[str] = None, error: Optional[str] = None,
                             parsed_results: Optional[Dict] = None) -> None:
    """Update tool execution with results."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tool_executions
                SET status = %s, exit_code = %s, output = %s, error = %s,
                    parsed_results = %s, completed_at = now()
                WHERE id = %s
            """, (status, exit_code, output, error,
                  json.dumps(parsed_results) if parsed_results else None, exec_id))
        conn.commit()
    finally:
        conn.close()


def db_get_tool_execution(exec_id: str) -> Optional[Dict]:
    """Get a tool execution record."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, tool, command, target, port, scan_id, service,
                       status, exit_code, output, error, parsed_results,
                       started_at, completed_at
                FROM tool_executions
                WHERE id = %s
            """, (exec_id,))
            return cur.fetchone()
    finally:
        conn.close()


def db_list_tool_executions(limit: int = 50, target: Optional[str] = None,
                            tool: Optional[str] = None) -> List[Dict]:
    """List tool executions with optional filters."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT id, tool, command, target, port, scan_id, service,
                       status, exit_code, output, error, parsed_results,
                       started_at, completed_at
                FROM tool_executions
                WHERE 1=1
            """
            params = []
            if target:
                query += " AND target = %s"
                params.append(target)
            if tool:
                query += " AND tool = %s"
                params.append(tool)
            query += " ORDER BY started_at DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, params)
            return cur.fetchall()
    finally:
        conn.close()


# --- Listener Management ---

async def start_nc_listener(listener_id: str, port: int, timeout: int) -> subprocess.Popen:
    """Start netcat listener and return process."""
    # nc -lvnp <port> with output capture
    cmd = ["nc", "-lvnp", str(port)]
    logger.info(f"[{listener_id[:8]}] Starting nc listener: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        preexec_fn=os.setsid  # Create new process group for clean termination
    )

    return proc


async def start_socat_listener(listener_id: str, port: int, timeout: int) -> subprocess.Popen:
    """Start socat listener and return process."""
    # socat TCP-LISTEN:<port>,reuseaddr,fork STDOUT
    cmd = ["socat", f"TCP-LISTEN:{port},reuseaddr,fork", "STDOUT"]
    logger.info(f"[{listener_id[:8]}] Starting socat listener: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        preexec_fn=os.setsid
    )

    return proc


async def monitor_listener(listener_id: str, proc: subprocess.Popen, timeout: int):
    """Monitor listener for connections and timeout."""
    logger.info(f"[{listener_id[:8]}] Monitoring listener (timeout: {timeout}s)")

    try:
        # Wait for process to complete or timeout
        stdout, stderr = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: proc.communicate()
            ),
            timeout=timeout
        )

        output = stdout.decode('utf-8', errors='replace') if stdout else ""
        error = stderr.decode('utf-8', errors='replace') if stderr else ""

        if output:
            logger.info(f"[{listener_id[:8]}] Received connection output:\n{output}")
            # Store callback data
            if listener_id in active_listeners:
                active_listeners[listener_id]["output"] = output
                active_listeners[listener_id]["status"] = "received"

        if error:
            logger.debug(f"[{listener_id[:8]}] Stderr: {error}")

        db_update_listener_status(listener_id, "stopped")

    except asyncio.TimeoutError:
        logger.warning(f"[{listener_id[:8]}] Listener timed out after {timeout}s")
        stop_listener_process(listener_id)
        db_update_listener_status(listener_id, "stopped")

    except Exception as e:
        logger.error(f"[{listener_id[:8]}] Monitor error: {e}")
        stop_listener_process(listener_id)
        db_update_listener_status(listener_id, "stopped")

    finally:
        if listener_id in active_listeners:
            active_listeners[listener_id]["status"] = "stopped"


def stop_listener_process(listener_id: str) -> bool:
    """Stop a listener process by ID."""
    if listener_id not in active_listeners:
        return False

    listener = active_listeners[listener_id]
    proc = listener.get("process")

    if proc and proc.poll() is None:
        try:
            # Kill the process group
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
            logger.info(f"[{listener_id[:8]}] Stopped listener (SIGTERM)")
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            logger.info(f"[{listener_id[:8]}] Killed listener (SIGKILL)")
        except Exception as e:
            logger.error(f"[{listener_id[:8]}] Error stopping: {e}")
            return False

    return True


def is_port_available(port: int) -> bool:
    """Check if port is available."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except socket.error:
            return False


# --- Validation Parsing ---

def parse_validation_output(output: str) -> Dict[str, Any]:
    """Parse validation command output to extract user info."""
    parsed = {
        "user": None,
        "uid": None,
        "gid": None,
        "groups": None,
        "hostname": None,
        "access_level": "unknown"
    }

    lines = output.strip().split('\n')

    for line in lines:
        line = line.strip()

        # Parse 'id' command output: uid=1000(user) gid=1000(user) groups=...
        if line.startswith('uid='):
            import re
            uid_match = re.search(r'uid=(\d+)\(([^)]+)\)', line)
            gid_match = re.search(r'gid=(\d+)\(([^)]+)\)', line)
            groups_match = re.search(r'groups=(.+)', line)

            if uid_match:
                parsed["uid"] = int(uid_match.group(1))
                parsed["user"] = uid_match.group(2)
            if gid_match:
                parsed["gid"] = int(gid_match.group(1))
            if groups_match:
                parsed["groups"] = groups_match.group(1)

        # Simple whoami output (single word)
        elif line and not parsed["user"] and len(line.split()) == 1:
            if not any(c in line for c in ['=', ':', '/']):
                parsed["user"] = line

        # Hostname (usually a single word without special chars)
        elif line and not parsed["hostname"]:
            if len(line.split()) == 1 and parsed["user"] and line != parsed["user"]:
                parsed["hostname"] = line

    # Determine access level
    parsed["access_level"] = determine_access_level(parsed)

    return parsed


def determine_access_level(parsed: Dict[str, Any]) -> str:
    """Determine access level from parsed validation output."""
    user = (parsed.get("user") or "").lower()
    uid = parsed.get("uid")
    groups = (parsed.get("groups") or "").lower()

    # Root/Administrator
    if user in ["root", "administrator", "system", "nt authority\\system"]:
        return "root"
    if uid == 0:
        return "root"

    # Admin (has sudo/wheel/admin group)
    admin_groups = ["sudo", "wheel", "admin", "administrators", "root"]
    if any(g in groups for g in admin_groups):
        return "admin"

    # Service accounts
    service_accounts = ["www-data", "apache", "nginx", "mysql", "postgres",
                       "redis", "tomcat", "jenkins", "git", "daemon"]
    if user in service_accounts:
        return "service"

    # Regular user
    return "user"


# --- Tool Output Parsers ---

def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse nmap scan output."""
    import re
    results = {
        "open_ports": [],
        "services": [],
        "os_detection": None,
        "vulnerabilities": []
    }

    lines = output.split('\n')
    for line in lines:
        # Parse open ports: "22/tcp   open  ssh     OpenSSH 8.2p1"
        port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if port_match:
            port_info = {
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "service": port_match.group(3),
                "version": port_match.group(4).strip() if port_match.group(4) else None
            }
            results["open_ports"].append(port_info["port"])
            results["services"].append(port_info)

        # Parse OS detection
        if "OS details:" in line:
            results["os_detection"] = line.split("OS details:")[1].strip()

        # Parse script output for vulns
        if "VULNERABLE" in line or "CVE-" in line:
            results["vulnerabilities"].append(line.strip())

    return results


def parse_hydra_output(output: str) -> Dict[str, Any]:
    """Parse hydra brute force output."""
    import re
    results = {
        "credentials_found": [],
        "attempts": 0,
        "success": False
    }

    lines = output.split('\n')
    for line in lines:
        # Parse successful login: "[22][ssh] host: 192.168.1.1   login: admin   password: admin123"
        cred_match = re.search(r'\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)', line)
        if cred_match:
            results["credentials_found"].append({
                "port": int(cred_match.group(1)),
                "service": cred_match.group(2),
                "host": cred_match.group(3),
                "username": cred_match.group(4),
                "password": cred_match.group(5)
            })
            results["success"] = True

        # Parse attempt count
        if "valid password" in line.lower() or "valid pair" in line.lower():
            results["success"] = True

    return results


def parse_nikto_output(output: str) -> Dict[str, Any]:
    """Parse nikto web scanner output."""
    import re
    results = {
        "server": None,
        "findings": [],
        "vulnerabilities": []
    }

    lines = output.split('\n')
    for line in lines:
        # Server info
        if "+ Server:" in line:
            results["server"] = line.split("+ Server:")[1].strip()

        # Findings (lines starting with +)
        if line.strip().startswith("+") and "OSVDB" in line:
            results["findings"].append(line.strip())
            # Check for vulns
            if any(word in line.lower() for word in ["vulnerable", "exploit", "injection", "xss"]):
                results["vulnerabilities"].append(line.strip())

    return results


def parse_enum4linux_output(output: str) -> Dict[str, Any]:
    """Parse enum4linux SMB enumeration output."""
    import re
    results = {
        "domain": None,
        "users": [],
        "shares": [],
        "groups": [],
        "password_policy": None
    }

    lines = output.split('\n')
    in_users_section = False
    in_shares_section = False

    for line in lines:
        # Domain
        if "Domain Name:" in line:
            results["domain"] = line.split("Domain Name:")[1].strip()

        # Users
        if "user:" in line.lower():
            user_match = re.search(r'user:\[([^\]]+)\]', line, re.IGNORECASE)
            if user_match:
                results["users"].append(user_match.group(1))

        # Shares
        if "Disk|" in line or "IPC|" in line:
            share_match = re.match(r'\s*(\S+)\s+Disk', line)
            if share_match:
                results["shares"].append(share_match.group(1))

    return results


def parse_ssh_audit_output(output: str) -> Dict[str, Any]:
    """Parse ssh-audit output."""
    import re
    results = {
        "ssh_version": None,
        "weak_algorithms": [],
        "recommendations": [],
        "vulnerabilities": []
    }

    lines = output.split('\n')
    for line in lines:
        # SSH version
        if "ssh" in line.lower() and ("banner" in line.lower() or "software" in line.lower()):
            results["ssh_version"] = line.strip()

        # Weak algorithms (marked with fail or warn)
        if "(fail)" in line.lower() or "(warn)" in line.lower():
            results["weak_algorithms"].append(line.strip())

        # CVEs
        if "CVE-" in line:
            results["vulnerabilities"].append(line.strip())

    return results


def parse_whatweb_output(output: str) -> Dict[str, Any]:
    """Parse whatweb fingerprinting output."""
    import re
    results = {
        "technologies": [],
        "cms": None,
        "server": None,
        "frameworks": []
    }

    # WhatWeb outputs in format: URL [status] key[value], key[value]...
    for match in re.finditer(r'(\w+)\[([^\]]+)\]', output):
        key, value = match.groups()
        results["technologies"].append({"name": key, "version": value})

        # Identify specific types
        if key.lower() in ["apache", "nginx", "iis", "lighttpd"]:
            results["server"] = f"{key}/{value}"
        elif key.lower() in ["wordpress", "drupal", "joomla", "magento"]:
            results["cms"] = f"{key}/{value}"
        elif key.lower() in ["jquery", "bootstrap", "angular", "react", "vue"]:
            results["frameworks"].append(f"{key}/{value}")

    return results


def parse_tool_output(tool: str, output: str) -> Optional[Dict[str, Any]]:
    """Parse tool output based on tool type."""
    parsers = {
        "nmap": parse_nmap_output,
        "hydra": parse_hydra_output,
        "nikto": parse_nikto_output,
        "enum4linux": parse_enum4linux_output,
        "ssh-audit": parse_ssh_audit_output,
        "whatweb": parse_whatweb_output,
    }

    parser = parsers.get(tool.lower())
    if parser:
        try:
            return parser(output)
        except Exception as e:
            logger.warning(f"Failed to parse {tool} output: {e}")
            return None
    return None


# --- Tool Execution ---

# Track active tool executions
active_executions: Dict[str, Dict[str, Any]] = {}

# Allowed tools for security
ALLOWED_TOOLS = {
    "nmap", "hydra", "medusa", "nikto", "whatweb", "enum4linux",
    "smbclient", "smbmap", "ssh-audit", "netexec", "crackmapexec", "nbtscan",
    "snmpwalk", "onesixtyone", "ldapsearch", "dig", "host", "nslookup",
    "redis-cli", "psql", "mysql", "rpcclient", "showmount"
}


async def execute_tool(exec_id: str, tool: str, command: str, timeout: int):
    """Execute a tool command and capture output."""
    logger.info(f"[{exec_id[:8]}] Executing: {command}")

    # Update status to running
    db_update_tool_execution(exec_id, "running")
    active_executions[exec_id]["status"] = "running"

    start_time = datetime.now()

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )

            output = stdout.decode('utf-8', errors='replace')
            error = stderr.decode('utf-8', errors='replace')
            exit_code = proc.returncode

            # Calculate duration
            duration = (datetime.now() - start_time).total_seconds()

            # Parse output
            parsed_results = parse_tool_output(tool, output)

            # Update database
            status = "completed" if exit_code == 0 else "failed"
            db_update_tool_execution(
                exec_id, status, exit_code, output, error, parsed_results
            )

            # Update in-memory tracking
            active_executions[exec_id].update({
                "status": status,
                "exit_code": exit_code,
                "output": output,
                "error": error,
                "parsed_results": parsed_results,
                "completed_at": datetime.now().isoformat(),
                "duration_seconds": duration
            })

            logger.info(f"[{exec_id[:8]}] Completed with exit code {exit_code} in {duration:.1f}s")

        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = (datetime.now() - start_time).total_seconds()

            db_update_tool_execution(exec_id, "timeout", -1, None, f"Execution timed out after {timeout}s")
            active_executions[exec_id].update({
                "status": "timeout",
                "error": f"Execution timed out after {timeout}s",
                "completed_at": datetime.now().isoformat(),
                "duration_seconds": duration
            })
            logger.warning(f"[{exec_id[:8]}] Timed out after {timeout}s")

    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        db_update_tool_execution(exec_id, "failed", -1, None, str(e))
        active_executions[exec_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat(),
            "duration_seconds": duration
        })
        logger.error(f"[{exec_id[:8]}] Execution error: {e}")


# --- FastAPI App ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("=" * 60)
    logger.info("KALI LISTENER SERVICE STARTING")
    logger.info(f"Port Range: {PORT_START}-{PORT_END}")
    logger.info(f"API Port: {API_PORT}")
    logger.info("=" * 60)
    yield
    # Cleanup on shutdown
    logger.info("Shutting down - stopping all listeners...")
    for listener_id in list(active_listeners.keys()):
        stop_listener_process(listener_id)
    logger.info("Kali Listener Service stopped")


app = FastAPI(
    title="Kali Listener Service",
    description="Manage reverse shell listeners for exploit validation",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    active = sum(1 for l in active_listeners.values() if l.get("status") == "active")
    return HealthResponse(
        status="healthy",
        service="kali-listener",
        active_listeners=active,
        port_range=f"{PORT_START}-{PORT_END}"
    )


@app.post("/listeners/start", response_model=ListenerResponse)
async def start_listener(request: ListenerStartRequest, background_tasks: BackgroundTasks):
    """Start a new listener on specified port."""

    # Validate port
    if not PORT_START <= request.port <= PORT_END:
        raise HTTPException(
            status_code=400,
            detail=f"Port must be between {PORT_START} and {PORT_END}"
        )

    # Check port availability
    if not is_port_available(request.port):
        raise HTTPException(status_code=409, detail=f"Port {request.port} is already in use")

    # Validate listener type
    if request.listener_type not in ["nc", "socat"]:
        raise HTTPException(status_code=400, detail="listener_type must be 'nc' or 'socat'")

    listener_id = str(uuid.uuid4())

    # Create DB record
    try:
        db_create_listener(listener_id, request.listener_type, request.port,
                          request.pending_exploit_id)
    except Exception as e:
        logger.error(f"Failed to create listener record: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    # Start the listener process
    try:
        if request.listener_type == "nc":
            proc = await start_nc_listener(listener_id, request.port, request.timeout)
        else:
            proc = await start_socat_listener(listener_id, request.port, request.timeout)

        # Track in memory
        active_listeners[listener_id] = {
            "id": listener_id,
            "type": request.listener_type,
            "port": request.port,
            "process": proc,
            "pid": proc.pid,
            "status": "active",
            "pending_exploit_id": request.pending_exploit_id,
            "started_at": datetime.now().isoformat(),
            "output": None
        }

        # Update DB status
        db_update_listener_status(listener_id, "active", proc.pid)

        # Start background monitoring
        background_tasks.add_task(monitor_listener, listener_id, proc, request.timeout)

        logger.info(f"[{listener_id[:8]}] Listener started on port {request.port} (PID: {proc.pid})")

        return ListenerResponse(
            id=listener_id,
            listener_type=request.listener_type,
            port=request.port,
            status="active",
            pid=proc.pid,
            pending_exploit_id=request.pending_exploit_id,
            started_at=active_listeners[listener_id]["started_at"]
        )

    except Exception as e:
        logger.error(f"Failed to start listener: {e}")
        db_update_listener_status(listener_id, "stopped")
        raise HTTPException(status_code=500, detail=f"Failed to start listener: {e}")


@app.post("/listeners/{listener_id}/stop")
async def stop_listener(listener_id: str):
    """Stop a running listener."""
    if listener_id not in active_listeners:
        raise HTTPException(status_code=404, detail="Listener not found")

    success = stop_listener_process(listener_id)
    if success:
        db_update_listener_status(listener_id, "stopped")
        return {"status": "stopped", "listener_id": listener_id}
    else:
        raise HTTPException(status_code=500, detail="Failed to stop listener")


@app.get("/listeners", response_model=ListenerListResponse)
async def list_listeners():
    """List all active listeners."""
    listeners = []

    for lid, ldata in active_listeners.items():
        if ldata.get("status") in ["active", "pending"]:
            listeners.append(ListenerResponse(
                id=lid,
                listener_type=ldata["type"],
                port=ldata["port"],
                status=ldata["status"],
                pid=ldata.get("pid"),
                pending_exploit_id=ldata.get("pending_exploit_id"),
                started_at=ldata.get("started_at")
            ))

    return ListenerListResponse(listeners=listeners, total=len(listeners))


@app.get("/listeners/{listener_id}", response_model=ListenerResponse)
async def get_listener(listener_id: str):
    """Get details of a specific listener."""
    if listener_id not in active_listeners:
        raise HTTPException(status_code=404, detail="Listener not found")

    ldata = active_listeners[listener_id]
    return ListenerResponse(
        id=listener_id,
        listener_type=ldata["type"],
        port=ldata["port"],
        status=ldata["status"],
        pid=ldata.get("pid"),
        pending_exploit_id=ldata.get("pending_exploit_id"),
        started_at=ldata.get("started_at")
    )


@app.get("/listeners/{listener_id}/output")
async def get_listener_output(listener_id: str):
    """Get captured output from a listener."""
    if listener_id not in active_listeners:
        raise HTTPException(status_code=404, detail="Listener not found")

    output = active_listeners[listener_id].get("output")
    return {
        "listener_id": listener_id,
        "status": active_listeners[listener_id]["status"],
        "output": output,
        "has_output": output is not None
    }


@app.post("/callbacks/register", response_model=CallbackResponse)
async def register_callback(request: CallbackRegisterRequest):
    """Register an expected callback for an exploit."""
    callback_id = str(uuid.uuid4())

    try:
        db_register_callback(
            callback_id,
            request.pending_exploit_id,
            request.listener_id,
            request.callback_type,
            request.validation_commands
        )

        logger.info(f"Registered callback {callback_id[:8]} for exploit {request.pending_exploit_id[:8]}")

        return CallbackResponse(
            id=callback_id,
            pending_exploit_id=request.pending_exploit_id,
            listener_id=request.listener_id,
            callback_type=request.callback_type,
            validation_status="pending"
        )

    except Exception as e:
        logger.error(f"Failed to register callback: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@app.get("/callbacks/poll/{pending_exploit_id}", response_model=CallbackResponse)
async def poll_callback(pending_exploit_id: str):
    """Poll for callback status for an exploit."""
    callback = db_get_callback_by_exploit(pending_exploit_id)

    if not callback:
        raise HTTPException(status_code=404, detail="No callback registered for this exploit")

    # Check if listener has received output
    listener_id = callback.get("listener_id")
    if listener_id and listener_id in active_listeners:
        listener = active_listeners[listener_id]
        output = listener.get("output")

        if output and callback.get("validation_status") == "pending":
            # Parse and update callback with validation results
            parsed = parse_validation_output(output)
            db_update_callback(
                str(callback["id"]),
                "validated",
                output,
                parsed
            )
            callback["validation_status"] = "validated"
            callback["validation_output"] = output
            callback["parsed_validation"] = parsed

    return CallbackResponse(
        id=str(callback["id"]),
        pending_exploit_id=str(callback["pending_exploit_id"]),
        listener_id=str(callback["listener_id"]),
        callback_type=callback["callback_type"],
        validation_status=callback["validation_status"],
        validation_output=callback.get("validation_output"),
        parsed_validation=callback.get("parsed_validation"),
        received_at=callback["received_at"].isoformat() if callback.get("received_at") else None
    )


@app.post("/callbacks/{callback_id}/validate")
async def validate_callback(callback_id: str, output: str):
    """Manually submit output for validation."""
    parsed = parse_validation_output(output)

    try:
        db_update_callback(callback_id, "validated", output, parsed)

        return {
            "callback_id": callback_id,
            "validation_status": "validated",
            "parsed_validation": parsed
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@app.get("/ports/available")
async def get_available_port():
    """Find and return an available port in the range."""
    for port in range(PORT_START, PORT_END + 1):
        if is_port_available(port):
            # Also check not in active_listeners
            in_use = any(l["port"] == port for l in active_listeners.values()
                        if l.get("status") == "active")
            if not in_use:
                return {"port": port, "available": True}

    raise HTTPException(status_code=503, detail="No available ports in range")


@app.get("/logs")
async def get_logs(limit: int = 100, level: Optional[str] = None):
    """Get recent logs from the service."""
    handler = get_log_handler()
    logs = handler.get_logs(limit=limit, level=level)
    return {"logs": logs, "total": len(logs)}


@app.delete("/logs")
async def clear_logs():
    """Clear all logs."""
    handler = get_log_handler()
    count = handler.clear()
    return {"cleared": count}


# --- Tool Execution Endpoints ---

@app.post("/tools/execute", response_model=ToolExecutionResponse)
async def execute_tool_endpoint(request: ToolExecuteRequest, background_tasks: BackgroundTasks):
    """
    Execute a pentest tool command and capture results.

    The tool must be in the allowed list for security reasons.
    Results are parsed automatically for common tools (nmap, hydra, nikto, etc.)
    """
    # Validate tool is allowed
    tool_lower = request.tool.lower()
    if tool_lower not in ALLOWED_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{request.tool}' is not in allowed list. Allowed: {', '.join(sorted(ALLOWED_TOOLS))}"
        )

    # Basic command validation - prevent obvious shell injection
    dangerous_chars = [';', '&&', '||', '|', '`', '$(',  '>', '<', '\n']
    for char in dangerous_chars:
        if char in request.command and char not in ['>', '<']:  # Allow basic redirection
            # Check if it's within quotes (simple check)
            if not (request.command.count('"') >= 2 or request.command.count("'") >= 2):
                raise HTTPException(
                    status_code=400,
                    detail=f"Command contains potentially dangerous character: {char}"
                )

    exec_id = str(uuid.uuid4())

    # Create database record
    try:
        db_create_tool_execution(
            exec_id, request.tool, request.command, request.target,
            request.port, request.scan_id, request.service
        )
    except Exception as e:
        logger.error(f"Failed to create execution record: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    # Track in memory
    active_executions[exec_id] = {
        "id": exec_id,
        "tool": request.tool,
        "command": request.command,
        "target": request.target,
        "port": request.port,
        "status": "pending",
        "started_at": datetime.now().isoformat()
    }

    # Start execution in background
    background_tasks.add_task(
        execute_tool, exec_id, request.tool, request.command, request.timeout
    )

    logger.info(f"[{exec_id[:8]}] Queued tool execution: {request.tool} -> {request.target}")

    return ToolExecutionResponse(
        id=exec_id,
        tool=request.tool,
        command=request.command,
        target=request.target,
        port=request.port,
        status="pending",
        started_at=active_executions[exec_id]["started_at"]
    )


@app.get("/tools/executions", response_model=ToolExecutionListResponse)
async def list_tool_executions(
    limit: int = 50,
    target: Optional[str] = None,
    tool: Optional[str] = None
):
    """List tool executions with optional filters."""
    try:
        executions = db_list_tool_executions(limit, target, tool)
    except Exception as e:
        logger.error(f"Failed to list executions: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    result = []
    for ex in executions:
        duration = None
        if ex.get("started_at") and ex.get("completed_at"):
            duration = (ex["completed_at"] - ex["started_at"]).total_seconds()

        result.append(ToolExecutionResponse(
            id=str(ex["id"]),
            tool=ex["tool"],
            command=ex["command"],
            target=ex["target"],
            port=ex.get("port"),
            status=ex["status"],
            exit_code=ex.get("exit_code"),
            output=ex.get("output"),
            error=ex.get("error"),
            parsed_results=ex.get("parsed_results"),
            started_at=ex["started_at"].isoformat() if ex.get("started_at") else None,
            completed_at=ex["completed_at"].isoformat() if ex.get("completed_at") else None,
            duration_seconds=duration
        ))

    return ToolExecutionListResponse(executions=result, total=len(result))


@app.get("/tools/executions/{exec_id}", response_model=ToolExecutionResponse)
async def get_tool_execution(exec_id: str):
    """Get details of a specific tool execution."""
    # Check in-memory first for active executions
    if exec_id in active_executions:
        ex = active_executions[exec_id]
        return ToolExecutionResponse(
            id=exec_id,
            tool=ex["tool"],
            command=ex["command"],
            target=ex["target"],
            port=ex.get("port"),
            status=ex["status"],
            exit_code=ex.get("exit_code"),
            output=ex.get("output"),
            error=ex.get("error"),
            parsed_results=ex.get("parsed_results"),
            started_at=ex.get("started_at"),
            completed_at=ex.get("completed_at"),
            duration_seconds=ex.get("duration_seconds")
        )

    # Check database
    try:
        ex = db_get_tool_execution(exec_id)
    except Exception as e:
        logger.error(f"Failed to get execution: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")

    duration = None
    if ex.get("started_at") and ex.get("completed_at"):
        duration = (ex["completed_at"] - ex["started_at"]).total_seconds()

    return ToolExecutionResponse(
        id=str(ex["id"]),
        tool=ex["tool"],
        command=ex["command"],
        target=ex["target"],
        port=ex.get("port"),
        status=ex["status"],
        exit_code=ex.get("exit_code"),
        output=ex.get("output"),
        error=ex.get("error"),
        parsed_results=ex.get("parsed_results"),
        started_at=ex["started_at"].isoformat() if ex.get("started_at") else None,
        completed_at=ex["completed_at"].isoformat() if ex.get("completed_at") else None,
        duration_seconds=duration
    )


@app.get("/tools/allowed")
async def list_allowed_tools():
    """List all allowed tools that can be executed."""
    return {
        "tools": sorted(ALLOWED_TOOLS),
        "total": len(ALLOWED_TOOLS)
    }


@app.post("/tools/execute-recommended")
async def execute_recommended_tools(
    target: str,
    service: str,
    port: int,
    scan_id: Optional[str] = None,
    recommender_url: str = "https://scan-recommender:8013",
    background_tasks: BackgroundTasks = None
):
    """
    Get tool recommendations for a service and execute them.

    This endpoint:
    1. Fetches recommendations from scan-recommender service
    2. Queues execution of each recommended tool
    3. Returns execution IDs for tracking

    Example: POST /tools/execute-recommended?target=192.168.1.1&service=ssh&port=22
    """
    import httpx

    # Get recommendations from scan-recommender
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.get(
                f"{recommender_url}/rag/tools/recommend",
                params={"service": service, "port": port}
            )
            resp.raise_for_status()
            recommendations = resp.json()
    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Failed to get tool recommendations: {e}"
        )

    # Queue execution of recommended tools
    executions = []
    tools_data = recommendations.get("tools", [])

    for tool_info in tools_data:
        tool_name = tool_info.get("name", "").lower()
        if tool_name not in ALLOWED_TOOLS:
            continue

        # Build command from template
        command_template = tool_info.get("command", "")
        if not command_template:
            continue

        # Replace placeholders
        command = command_template.replace("{target}", target).replace("{port}", str(port))

        exec_id = str(uuid.uuid4())

        # Create database record
        try:
            db_create_tool_execution(
                exec_id, tool_name, command, target, port, scan_id, service
            )
        except Exception as e:
            logger.warning(f"Failed to create execution record for {tool_name}: {e}")
            continue

        # Track in memory
        active_executions[exec_id] = {
            "id": exec_id,
            "tool": tool_name,
            "command": command,
            "target": target,
            "port": port,
            "status": "pending",
            "started_at": datetime.now().isoformat()
        }

        # Queue execution
        background_tasks.add_task(execute_tool, exec_id, tool_name, command, 300)

        executions.append({
            "id": exec_id,
            "tool": tool_name,
            "command": command,
            "status": "pending"
        })

        logger.info(f"[{exec_id[:8]}] Queued recommended tool: {tool_name}")

    return {
        "target": target,
        "service": service,
        "port": port,
        "executions": executions,
        "total_queued": len(executions)
    }


# ===============================
# Structured Job Endpoints: NetExec, Impacket, Hashcat
# ===============================

@app.get("/jobs/{job_id}")
async def get_structured_job(job_id: str):
    """Get status of a structured scan job."""
    job = structured_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/jobs")
async def list_structured_jobs(limit: int = 50):
    """List structured scan jobs."""
    jobs = sorted(structured_jobs.values(), key=lambda j: j.get("created_at", ""), reverse=True)
    return {"jobs": jobs[:limit]}


@app.post("/jobs/netexec", response_model=JobResponse)
async def run_netexec(req: NetExecReq, background_tasks: BackgroundTasks):
    """Run NetExec for AD/network credential testing and enumeration."""
    job_id = str(uuid.uuid4())
    output_file = str(REPORT_DIR / f"netexec_{job_id[:8]}.log")

    allowed_protocols = {"smb", "ldap", "winrm", "mssql", "rdp", "ssh", "ftp"}
    protocol = req.protocol.lower()
    if protocol not in allowed_protocols:
        raise HTTPException(status_code=400, detail=f"protocol must be one of: {allowed_protocols}")

    targets_str = " ".join(req.targets)
    cmd = ["netexec", protocol, targets_str, "--log", output_file]

    if req.username:
        cmd.extend(["-u", req.username])
    if req.password:
        cmd.extend(["-p", req.password])
    if req.hash:
        cmd.extend(["-H", req.hash])
    if req.domain:
        cmd.extend(["-d", req.domain])
    if req.module:
        cmd.extend(["-M", req.module])
        if req.options:
            cmd.extend(["-o", req.options])

    structured_jobs[job_id] = {
        "job_id": job_id, "type": "netexec", "status": "queued",
        "created_at": datetime.now().isoformat(),
        "protocol": protocol, "targets": req.targets,
    }

    background_tasks.add_task(
        _run_structured_job, job_id, "netexec", cmd, output_file, timeout=req.timeout
    )
    return JobResponse(job_id=job_id, status="queued", status_url=f"/jobs/{job_id}")


@app.post("/jobs/impacket", response_model=JobResponse)
async def run_impacket(req: ImpacketReq, background_tasks: BackgroundTasks):
    """Run Impacket tools (secretsdump, psexec, GetUserSPNs, etc.)."""
    job_id = str(uuid.uuid4())
    output_file = str(REPORT_DIR / f"impacket_{job_id[:8]}.txt")

    if req.tool not in IMPACKET_TOOLS:
        raise HTTPException(status_code=400, detail=f"tool must be one of: {list(IMPACKET_TOOLS.keys())}")

    binary = IMPACKET_TOOLS[req.tool]

    # Build auth string: domain/user:pass@target or domain/user@target
    auth_parts = []
    if req.domain:
        auth_parts.append(req.domain + "/")
    if req.username:
        auth_parts.append(req.username)
    if req.password:
        auth_parts.append(":" + req.password)
    auth_parts.append("@" + req.target)
    auth_string = "".join(auth_parts)

    cmd = [binary, auth_string, "-outputfile", output_file]
    if req.hash:
        cmd.extend(["-hashes", ":" + req.hash])
    if req.extra_args:
        # Split extra args safely
        import shlex
        cmd.extend(shlex.split(req.extra_args))

    structured_jobs[job_id] = {
        "job_id": job_id, "type": "impacket", "status": "queued",
        "created_at": datetime.now().isoformat(),
        "tool": req.tool, "target": req.target,
    }

    background_tasks.add_task(
        _run_structured_job, job_id, "impacket", cmd, output_file,
        timeout=req.timeout, tool=req.tool, target=req.target
    )
    return JobResponse(job_id=job_id, status="queued", status_url=f"/jobs/{job_id}")


@app.post("/jobs/hashcat", response_model=JobResponse)
async def run_hashcat(req: HashcatReq, background_tasks: BackgroundTasks):
    """Run Hashcat for hash cracking."""
    job_id = str(uuid.uuid4())
    output_file = str(REPORT_DIR / f"hashcat_{job_id[:8]}.txt")

    # Write hashes to temp file
    hash_file = str(REPORT_DIR / f"hashcat_input_{job_id[:8]}.txt")
    with open(hash_file, "w") as f:
        f.write("\n".join(req.hashes))

    wordlist = req.wordlist or "/app/wordlists/rockyou.txt"
    hash_type = req.hash_type

    cmd = ["hashcat", "-m", str(hash_type), hash_file, wordlist,
           "-o", output_file, "--force", "--potfile-disable"]
    if req.rules:
        cmd.extend(["-r", req.rules])

    structured_jobs[job_id] = {
        "job_id": job_id, "type": "hashcat", "status": "queued",
        "created_at": datetime.now().isoformat(),
        "hash_type": hash_type, "hash_count": len(req.hashes),
    }

    background_tasks.add_task(
        _run_structured_job, job_id, "hashcat", cmd, output_file,
        timeout=req.timeout, hash_type=str(hash_type)
    )
    return JobResponse(job_id=job_id, status="queued", status_url=f"/jobs/{job_id}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
