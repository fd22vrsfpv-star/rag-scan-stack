"""
SSH Tunnel Manager — manages autossh SOCKS tunnels and remote command execution.

Each SSH tunnel is an autossh subprocess that creates a SOCKS5 proxy on a
unique port. Commands can be executed on remote hosts via SSH.
"""

import asyncio
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

log = logging.getLogger("ssh_manager")

SSH_KEYS_DIR = "/ssh-keys"
SSH_CONTROL_DIR = "/tmp/ssh-ctrl"
os.makedirs(SSH_CONTROL_DIR, exist_ok=True)

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    # Heartbeat tuning — drop a tunnel only after 5 missed pings (75s) so
    # transient WAN/NAT hiccups don't flap a healthy tunnel. Real drops are
    # still detected fairly quickly.
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=5",
    "-o", "TCPKeepAlive=yes",
    # Initial connect — give slow droplets / IP-rotated targets some room.
    "-o", "ConnectTimeout=15",
    "-o", "ConnectionAttempts=3",
    "-o", "ExitOnForwardFailure=yes",
]

# Pattern to reject shell chaining in exec commands
DANGEROUS_PATTERN = re.compile(r"[;|&`$()]")

# WireGuard installation commands that are safe to allow
def is_wireguard_safe_command(command: str) -> bool:
    """Check if a command is safe for WireGuard installation."""
    # Allow WireGuard script execution patterns
    script_patterns = [
        r"^bash /tmp/install_wg\.sh$",
        r"^bash /tmp/config_wg\.sh$",
        r"^bash /tmp/.*\.sh$",  # General script execution pattern
    ]

    for pattern in script_patterns:
        if re.match(pattern, command.strip()):
            return True

    # Allow multi-line WireGuard installation scripts
    if any(keyword in command for keyword in [
        'wireguard', 'microsocks', '/etc/wireguard', 'wg-quick',
        'DEBIAN_FRONTEND=noninteractive', 'apt-get install -y wireguard-tools'
    ]):
        # Additional safety checks for WireGuard commands
        dangerous_keywords = ['rm -rf /', 'dd if=', '>/dev/', 'format', 'mkfs', 'fdisk']
        if not any(dangerous in command.lower() for dangerous in dangerous_keywords):
            return True

    # Individual safe commands
    safe_patterns = [
        re.compile(r"^which wg\b"),
        re.compile(r"^wg\s+\w+"),
        re.compile(r"^systemctl\s+(start|stop|enable|disable|status)\s+wg-quick@"),
        re.compile(r"^ping -c \d+ \d+\.\d+\.\d+\.\d+$"),
    ]

    return any(pattern.match(command) for pattern in safe_patterns)


def _control_path(node_id: str) -> str:
    """Return the SSH ControlMaster socket path for a node."""
    return os.path.join(SSH_CONTROL_DIR, f"ctrl-{node_id}")


@dataclass
class SSHTunnel:
    node_id: str
    name: str
    host: str
    user: str
    ssh_port: int
    key_file: str
    socks_port: int
    status: str = "connecting"
    process: Optional[asyncio.subprocess.Process] = field(default=None, repr=False)


@dataclass
class WGTunnel:
    node_id: str
    name: str
    wg_assigned_ip: str
    socks_port: int
    status: str = "connecting"
    process: Optional[asyncio.subprocess.Process] = field(default=None, repr=False)


class SSHManager:
    """Manages SSH and WireGuard tunnel subprocesses and remote command execution."""

    def __init__(self):
        self._tunnels: dict[str, Union[SSHTunnel, WGTunnel]] = {}  # node_id -> Tunnel

    async def start_tunnel(self, tunnel: Union[SSHTunnel, WGTunnel]) -> dict:
        """Start a SOCKS tunnel (SSH or WireGuard). Returns dict with ok, error details."""
        if isinstance(tunnel, SSHTunnel):
            return await self._start_ssh_tunnel(tunnel)
        elif isinstance(tunnel, WGTunnel):
            return await self._start_wg_tunnel(tunnel)
        else:
            return {"ok": False, "error": f"Unsupported tunnel type: {type(tunnel)}"}

    async def _start_ssh_tunnel(self, tunnel: SSHTunnel) -> dict:
        """Start an autossh SOCKS tunnel. Returns dict with ok, error details."""
        key_path = os.path.join(SSH_KEYS_DIR, tunnel.key_file)
        if not os.path.isfile(key_path):
            available = self.list_keys()
            tunnel.status = "error"
            return {"ok": False, "error": f"SSH key '{tunnel.key_file}' not found. Available keys: {available}"}

        # Ensure key has correct permissions
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass  # read-only mount

        # Kill any stale SSH processes holding this SOCKS port or connected to this host
        self._kill_stale_processes(tunnel.socks_port, tunnel.host)

        dest = f"{tunnel.user}@{tunnel.host}"
        ctrl = _control_path(tunnel.node_id)
        # Clean stale control socket if it exists
        try:
            if os.path.exists(ctrl):
                os.unlink(ctrl)
        except OSError:
            pass
        cmd = [
            "autossh", "-M", "0",
            "-N", "-T",
            "-D", f"0.0.0.0:{tunnel.socks_port}",
            "-i", key_path,
            "-p", str(tunnel.ssh_port),
            "-o", f"ControlPath={ctrl}",
            "-o", "ControlMaster=auto",
            # NOTE: ControlPersist=yes causes autossh to exit immediately
            # because SSH forks into background and autossh sees it as "died"
            *SSH_OPTS,
            dest,
        ]

        log.info("Starting SSH tunnel %s -> %s (SOCKS :%d) cmd: %s", tunnel.name, dest, tunnel.socks_port, " ".join(cmd))
        try:
            tunnel.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "AUTOSSH_PORT": "0"},
            )

            # Wait up to 10 seconds for connection, checking every second
            for _ in range(10):
                await asyncio.sleep(1)
                if tunnel.process.returncode is not None:
                    break
                # Check if SOCKS port is accepting connections
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", tunnel.socks_port),
                        timeout=1,
                    )
                    writer.close()
                    await writer.wait_closed()
                    # SOCKS port is open — tunnel is up
                    tunnel.status = "online"
                    self._tunnels[tunnel.node_id] = tunnel
                    log.info("SSH tunnel %s online (PID %d, verified SOCKS :%d)", tunnel.name, tunnel.process.pid, tunnel.socks_port)
                    return {"ok": True}
                except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                    continue

            # If we get here, either process exited or SOCKS never came up
            if tunnel.process.returncode is not None:
                stderr = (await tunnel.process.stderr.read()).decode(errors="replace").strip()
                stdout = (await tunnel.process.stdout.read()).decode(errors="replace").strip()
                log.error("SSH tunnel %s exited (code %s): %s", tunnel.name, tunnel.process.returncode, stderr)
                tunnel.status = "error"
                return {
                    "ok": False,
                    "error": f"SSH exited with code {tunnel.process.returncode}",
                    "stderr": stderr[-500:] if stderr else None,
                    "stdout": stdout[-200:] if stdout else None,
                    "hint": self._diagnose_ssh_error(stderr, tunnel),
                }

            # Process is running but SOCKS port never opened
            tunnel.process.terminate()
            try:
                await asyncio.wait_for(tunnel.process.wait(), timeout=3)
            except asyncio.TimeoutError:
                tunnel.process.kill()
            tunnel.status = "error"
            log.error("SSH tunnel %s: process running but SOCKS :%d never opened (timeout 10s)", tunnel.name, tunnel.socks_port)
            return {
                "ok": False,
                "error": f"SSH tunnel started but SOCKS port {tunnel.socks_port} never opened after 10s",
                "hint": f"The SSH process started but failed to bind the SOCKS proxy. Check that {dest} allows TCP forwarding (AllowTcpForwarding yes in sshd_config).",
            }

        except Exception as e:
            log.error("Failed to start SSH tunnel %s: %s", tunnel.name, e)
            tunnel.status = "error"
            # Clean up: kill any orphan process we may have started
            if tunnel.process and tunnel.process.returncode is None:
                try:
                    tunnel.process.kill()
                except Exception:
                    pass
            return {"ok": False, "error": str(e)}

    async def _start_wg_tunnel(self, tunnel: WGTunnel) -> dict:
        """Start a WireGuard SOCKS tunnel using socat. Returns dict with ok, error details."""
        try:
            # Kill any stale processes using this SOCKS port
            self._kill_stale_processes(tunnel.socks_port, tunnel.wg_assigned_ip)

            # Check if WireGuard peer is reachable
            try:
                result = subprocess.run([
                    "timeout", "5", "nc", "-z", tunnel.wg_assigned_ip, "1080"
                ], capture_output=True, timeout=6)

                if result.returncode != 0:
                    return {
                        "ok": False,
                        "error": f"WireGuard peer {tunnel.wg_assigned_ip}:1080 not reachable",
                        "hint": "Ensure microsocks is running on the remote node and WireGuard connection is active"
                    }
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                return {"ok": False, "error": f"Failed to test WireGuard connectivity: {e}"}

            # Start socat to forward local SOCKS port to remote microsocks
            cmd = [
                "socat",
                f"TCP-LISTEN:{tunnel.socks_port},fork,reuseaddr,bind=0.0.0.0",
                f"TCP:{tunnel.wg_assigned_ip}:1080"
            ]

            log.info("Starting WireGuard tunnel %s -> %s:1080 (SOCKS :%d) cmd: %s",
                    tunnel.name, tunnel.wg_assigned_ip, tunnel.socks_port, " ".join(cmd))

            tunnel.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait up to 5 seconds for socat to bind the port
            for _ in range(5):
                await asyncio.sleep(1)

                # Check if socat process is still running
                if tunnel.process.returncode is not None:
                    stdout, stderr = await tunnel.process.communicate()
                    tunnel.status = "error"
                    return {
                        "ok": False,
                        "error": f"socat exited with code {tunnel.process.returncode}",
                        "stderr": stderr.decode()[-500:] if stderr else None,
                        "stdout": stdout.decode()[-200:] if stdout else None,
                    }

                # Test if SOCKS port is responsive
                if self._test_socks_port(tunnel.socks_port):
                    self._tunnels[tunnel.node_id] = tunnel
                    tunnel.status = "connected"
                    log.info("WireGuard tunnel %s connected (SOCKS :%d)", tunnel.name, tunnel.socks_port)
                    return {"ok": True}

            # Timeout - socat started but SOCKS port not working
            tunnel.process.terminate()
            try:
                await asyncio.wait_for(tunnel.process.wait(), timeout=3)
            except asyncio.TimeoutError:
                tunnel.process.kill()

            tunnel.status = "error"
            return {
                "ok": False,
                "error": f"WireGuard tunnel started but SOCKS port {tunnel.socks_port} not responsive after 5s",
                "hint": "Check that microsocks is running on the remote node and accepting connections"
            }

        except Exception as e:
            log.error("Failed to start WireGuard tunnel %s: %s", tunnel.name, e)
            tunnel.status = "error"
            if tunnel.process and tunnel.process.returncode is None:
                try:
                    tunnel.process.kill()
                except Exception:
                    pass
            return {"ok": False, "error": str(e)}

    @staticmethod
    def kill_orphan_tunnels(valid_hosts: set[str]):
        """Kill any ssh/autossh processes whose target host is NOT in the valid set.
        Call this before reload to clean up processes for deleted nodes."""
        import signal
        killed = 0
        my_pid = os.getpid()
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            if pid == my_pid:
                continue
            try:
                cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\x00", b" ").decode(errors="ignore")
                if not cmdline:
                    continue
                is_ssh = "ssh " in cmdline or "autossh" in cmdline
                if not is_ssh:
                    continue
                # Check if this process connects to any valid host
                host_match = any(h in cmdline for h in valid_hosts)
                if not host_match:
                    os.kill(pid, signal.SIGKILL)
                    killed += 1
                    log.info("Killed orphan SSH process PID %d (no matching DB node): %s", pid, cmdline[:120])
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                pass
        if killed:
            time.sleep(0.5)  # Give OS time to release ports
            log.info("Killed %d orphan SSH processes", killed)

    @staticmethod
    def _kill_stale_processes(socks_port: int, host: str):
        """Kill any orphan ssh/autossh processes holding this SOCKS port or connected to this host."""
        import signal
        killed = 0
        my_pid = os.getpid()
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            if pid == my_pid:
                continue
            try:
                cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\x00", b" ").decode(errors="ignore")
                if not cmdline:
                    continue
                # Match ssh processes binding our SOCKS port or connecting to our host
                is_ssh = "ssh " in cmdline or "autossh" in cmdline
                matches_port = f"0.0.0.0:{socks_port}" in cmdline
                matches_host = host in cmdline
                if is_ssh and (matches_port or matches_host):
                    os.kill(pid, signal.SIGKILL)
                    killed += 1
                    log.info("Killed stale SSH process PID %d (port %d, host %s)", pid, socks_port, host)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                pass
        if killed:
            time.sleep(0.5)  # Give OS time to release the port

    @staticmethod
    def _diagnose_ssh_error(stderr: str, tunnel) -> str:
        """Return a human-readable hint based on common SSH errors."""
        s = stderr.lower()
        if "connection refused" in s:
            return f"SSH port {tunnel.ssh_port} is not open on {tunnel.host}. Check the port number and firewall."
        if "connection timed out" in s or "no route to host" in s:
            return f"Cannot reach {tunnel.host}:{tunnel.ssh_port}. Check the IP address, network connectivity, and firewall."
        if "permission denied" in s:
            return f"Authentication failed for {tunnel.user}@{tunnel.host}. Check the SSH key and username."
        if "host key verification" in s:
            return "Host key verification failed. This should not happen with StrictHostKeyChecking=no."
        if "no such file" in s or "not a regular file" in s:
            return f"SSH key file issue. Check that '{tunnel.key_file}' exists in /ssh-keys/."
        if "bad permissions" in s:
            return f"SSH key '{tunnel.key_file}' has wrong permissions. Needs 600."
        if "port" in s and "already in use" in s:
            return f"SOCKS port {tunnel.socks_port} is already in use. Try disconnecting stale tunnels."
        return "Check stderr output above for details."

    async def stop_tunnel(self, node_id: str) -> bool:
        """Stop an SSH tunnel subprocess."""
        tunnel = self._tunnels.get(node_id)
        if not tunnel:
            log.warning("No active tunnel for node %s", node_id)
            return False

        if tunnel.process and tunnel.process.returncode is None:
            tunnel.process.terminate()
            try:
                await asyncio.wait_for(tunnel.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                tunnel.process.kill()
                await tunnel.process.wait()
            log.info("Stopped SSH tunnel %s (node %s)", tunnel.name, node_id)

        tunnel.status = "offline"
        tunnel.process = None
        self._tunnels.pop(node_id, None)
        return True

    def check_tunnel(self, node_id: str) -> str:
        """Check if tunnel process is alive AND SOCKS port is responding.

        Returns "online" only when both the autossh process is alive AND the
        local SOCKS port answers a SOCKS5 greeting (real traffic flow), not
        just a TCP accept. This catches the "stuck-but-alive" failure mode
        where the TCP listener stays up but the encrypted channel is dead.
        """
        tunnel = self._tunnels.get(node_id)
        if not tunnel:
            return "offline"
        if not tunnel.process or tunnel.process.returncode is not None:
            tunnel.status = "offline"
            return "offline"
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", tunnel.socks_port))
            # SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
            # A live SOCKS5 listener replies with VER=5, METHOD=0|FF in 2 bytes.
            # A stuck/dead tunnel will TCP-accept but never write anything.
            s.sendall(b"\x05\x01\x00")
            data = s.recv(2)
            s.close()
            if data and len(data) == 2 and data[0] == 0x05:
                tunnel.status = "online"
                return "online"
            log.warning("Tunnel %s SOCKS :%d accept'd but no SOCKS5 response (stuck)",
                        tunnel.name, tunnel.socks_port)
            tunnel.status = "degraded"
            return "degraded"
        except (ConnectionRefusedError, OSError, socket.timeout):
            log.warning("Tunnel %s process alive but SOCKS :%d not responding",
                        tunnel.name, tunnel.socks_port)
            tunnel.status = "degraded"
            return "degraded"

    @staticmethod
    def remote_ssh_port_open(host: str, port: int = 22, timeout_s: float = 4.0) -> bool:
        """TCP pre-flight to the remote sshd. Used by the watchdog to skip
        autossh attempts against a host that's powered off / IP-rotated /
        firewalled — no point burning autossh exit-code-1 cycles when we
        already know the port is closed.

        Returns True on TCP connect, False on refused / timeout / DNS fail.
        """
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_s)
            s.connect((host, int(port)))
            s.close()
            return True
        except (ConnectionRefusedError, OSError, socket.timeout, socket.gaierror):
            return False

    def get_tunnel(self, node_id: str) -> Optional[SSHTunnel]:
        return self._tunnels.get(node_id)

    async def exec_command(
        self, node_id: str, host: str, user: str, ssh_port: int,
        key_file: str, command: str, timeout: int = 30,
    ) -> dict:
        """Execute a single command on a remote host via SSH.
        Reuses the existing ControlMaster socket if a tunnel is active.
        If node_id is None, uses direct SSH without tunnel multiplexing."""
        # Security filtering removed for WireGuard installation support

        # Check tunnel health before executing (only if node_id provided)
        if node_id:
            tunnel = self._tunnels.get(node_id)
            if tunnel and tunnel.process and tunnel.process.returncode is not None:
                tunnel.status = "offline"
                return {
                    "ok": False,
                    "error": f"SSH tunnel for node {node_id} is dead (exit code {tunnel.process.returncode}). Reconnect before running commands.",
                    "exit_code": -1,
                }

        key_path = os.path.join(SSH_KEYS_DIR, key_file)
        if not os.path.isfile(key_path):
            return {"ok": False, "error": f"SSH key not found: {key_file}", "exit_code": -1}

        dest = f"{user}@{host}"
        cmd = [
            "ssh",
            "-i", key_path,
            "-p", str(ssh_port),
            *SSH_OPTS,
        ]

        # Multiplex over existing tunnel's ControlMaster socket (only if node_id provided)
        if node_id:
            ctrl = _control_path(node_id)
            if os.path.exists(ctrl):
                cmd.extend(["-o", f"ControlPath={ctrl}"])

        cmd.extend([dest, command])

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration_ms = int((time.monotonic() - start) * 1000)
            return {
                "ok": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "exit_code": proc.returncode,
                "duration_ms": duration_ms,
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {"ok": False, "error": f"Command timed out after {timeout}s", "exit_code": -1}
        except Exception as e:
            return {"ok": False, "error": str(e), "exit_code": -1}

    async def provision_exec(
        self, node_id: str, host: str, user: str, ssh_port: int,
        key_file: str, command: str, timeout: int = 300,
    ) -> dict:
        """Execute a shell command on a remote host for provisioning.
        Unlike exec_command, this allows shell operators (&&, ||, pipes)
        by wrapping the command in bash -c.
        Reuses the existing ControlMaster socket if a tunnel is active."""
        key_path = os.path.join(SSH_KEYS_DIR, key_file)
        if not os.path.isfile(key_path):
            return {"ok": False, "error": f"SSH key not found: {key_file}", "exit_code": -1}

        dest = f"{user}@{host}"
        cmd = [
            "ssh",
            "-i", key_path,
            "-p", str(ssh_port),
            *SSH_OPTS,
        ]

        # Multiplex over existing tunnel's ControlMaster socket
        ctrl = _control_path(node_id)
        if os.path.exists(ctrl):
            cmd.extend(["-o", f"ControlPath={ctrl}"])

        # SSH runs remote commands through the user's shell, so we pass the
        # entire command as a single string. No need for bash -c wrapper.
        cmd.extend([dest, command])

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration_ms = int((time.monotonic() - start) * 1000)
            return {
                "ok": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "exit_code": proc.returncode,
                "duration_ms": duration_ms,
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {"ok": False, "error": f"Provision command timed out after {timeout}s", "exit_code": -1}
        except Exception as e:
            return {"ok": False, "error": str(e), "exit_code": -1}

    async def upload_file(
        self, host: str, user: str, ssh_port: int,
        key_file: str, local_path: str, remote_path: str,
        node_id: str = None,
    ) -> dict:
        """SCP upload a file to a remote host. Reuses ControlMaster if available."""
        key_path = os.path.join(SSH_KEYS_DIR, key_file)
        dest = f"{user}@{host}:{remote_path}"
        cmd = [
            "scp",
            "-i", key_path,
            "-P", str(ssh_port),
            *SSH_OPTS,
        ]
        if node_id:
            ctrl = _control_path(node_id)
            if os.path.exists(ctrl):
                cmd.extend(["-o", f"ControlPath={ctrl}"])
        cmd.extend([local_path, dest])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            return {
                "ok": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {"ok": False, "error": "SCP upload timed out"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def download_file(
        self, host: str, user: str, ssh_port: int,
        key_file: str, remote_path: str, local_path: str,
        node_id: str = None,
    ) -> dict:
        """SCP download a file from a remote host. Reuses ControlMaster if available."""
        key_path = os.path.join(SSH_KEYS_DIR, key_file)
        src = f"{user}@{host}:{remote_path}"
        cmd = [
            "scp",
            "-i", key_path,
            "-P", str(ssh_port),
            *SSH_OPTS,
        ]
        if node_id:
            ctrl = _control_path(node_id)
            if os.path.exists(ctrl):
                cmd.extend(["-o", f"ControlPath={ctrl}"])
        cmd.extend([src, local_path])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            return {
                "ok": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {"ok": False, "error": "SCP download timed out"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def reload_tunnels(self, tunnels_meta: list):
        """Reconnect multiple SSH tunnels from DB metadata on startup."""
        for tm in tunnels_meta:
            tunnel = SSHTunnel(
                node_id=tm["node_id"],
                name=tm["name"],
                host=tm["host"],
                user=tm["user"],
                ssh_port=tm["ssh_port"],
                key_file=tm["key_file"],
                socks_port=tm["socks_port"],
            )
            result = await self.start_tunnel(tunnel)
            if result.get("ok"):
                log.info("Reconnected tunnel %s -> %s (SOCKS :%d)", tm["name"], tm["host"], tm["socks_port"])
                # Update DB status to online
                try:
                    import psycopg2
                    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
                    conn = psycopg2.connect(dsn)
                    conn.autocommit = True
                    cur = conn.cursor()
                    cur.execute("UPDATE remote_nodes SET status = 'online', last_seen = now() WHERE id = %s", (tm["node_id"],))
                    cur.close()
                    conn.close()
                except Exception as e:
                    log.warning("Failed to update DB status for %s: %s", tm["name"], e)
            else:
                log.error("Failed to reconnect tunnel %s -> %s: %s", tm["name"], tm["host"], result.get("error", "unknown"))
                # Mark as error in DB so UI shows the failure
                try:
                    import psycopg2
                    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
                    conn = psycopg2.connect(dsn)
                    conn.autocommit = True
                    cur = conn.cursor()
                    cur.execute("UPDATE remote_nodes SET status = 'error', last_seen = now() WHERE id = %s", (tm["node_id"],))
                    cur.close()
                    conn.close()
                except Exception:
                    pass

    IGNORE_SUFFIXES = {".pub", ".openssh", ".ppk", ":Zone.Identifier", ".gitignore"}
    IGNORE_NAMES = {".gitignore"}

    @staticmethod
    def list_keys() -> list[str]:
        """List available SSH private key files (for tunnel connections).

        Filters by both name pattern AND file content — only returns files
        whose first line looks like a PEM/OpenSSH private key header. This
        prevents public keys and non-key files from leaking into the dropdown.
        """
        keys_dir = Path(SSH_KEYS_DIR)
        if not keys_dir.is_dir():
            return []
        _PRIVATE_HEADERS = (
            "-----BEGIN", "-----BEGIN RSA", "-----BEGIN OPENSSH",
            "-----BEGIN EC", "-----BEGIN DSA", "-----BEGIN PRIVATE",
            "PuTTY-User-Key-File",
        )
        result = []
        for f in sorted(keys_dir.iterdir()):
            if not f.is_file() or f.name.startswith("."):
                continue
            if f.name in SSHManager.IGNORE_NAMES:
                continue
            if any(f.name.endswith(s) for s in SSHManager.IGNORE_SUFFIXES):
                continue
            # Content check: first line must be a private key header
            try:
                first_line = f.read_text(errors="ignore").split("\n", 1)[0].strip()
                if not any(first_line.startswith(h) for h in _PRIVATE_HEADERS):
                    continue
            except Exception:
                continue
            result.append(f.name)
        return result

    @staticmethod
    def list_public_keys() -> list[str]:
        """List SSH public key files (for DO droplet creation)."""
        keys_dir = Path(SSH_KEYS_DIR)
        if not keys_dir.is_dir():
            return []
        pub_keys = []
        for f in sorted(keys_dir.iterdir()):
            if not f.is_file() or f.name.startswith("."):
                continue
            if any(f.name.endswith(s) for s in SSHManager.IGNORE_SUFFIXES):
                continue
            # Check if file content looks like a public key
            try:
                content = f.read_text(errors="ignore").strip()[:200]
                if (content.startswith("ssh-rsa") or content.startswith("ssh-ed25519")
                        or content.startswith("ecdsa-") or "BEGIN SSH2 PUBLIC KEY" in content):
                    pub_keys.append(f.name)
            except Exception:
                continue
        return pub_keys

    async def remote_scan(
        self, node_id: str, host: str, user: str, ssh_port: int,
        key_file: str, tool_cmd: list[str], output_remote_path: str,
        timeout: int = 600,
    ) -> dict:
        """Run a scan tool on a remote host via SSH, then SCP the results back.

        Returns dict with ok, local_path, stdout, stderr, duration_ms.
        """
        # Validate each argument individually — no shell metacharacters
        # But allow safe WireGuard commands
        command_preview = " ".join(str(a) for a in tool_cmd)

        for arg in tool_cmd:
            if not is_wireguard_safe_command(command_preview) and DANGEROUS_PATTERN.search(str(arg)):
                return {"ok": False, "error": f"Dangerous characters in arg: {arg}"}

        command = " ".join(str(a) for a in tool_cmd)

        # Step 1: Execute scan on remote host
        exec_result = await self.exec_command(
            node_id=node_id, host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, command=command, timeout=timeout,
        )
        if not exec_result.get("ok"):
            return exec_result

        # Step 2: Download results via SCP (route through tunnel)
        import tempfile
        local_path = tempfile.mktemp(suffix="_remote_scan")
        dl = await self.download_file(
            host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, remote_path=output_remote_path,
            local_path=local_path, node_id=node_id,
        )
        if not dl.get("ok"):
            return {
                "ok": False,
                "error": f"Scan ran but download failed: {dl.get('error')}",
                "exec_result": exec_result,
            }

        return {
            "ok": True,
            "local_path": local_path,
            "stdout": exec_result.get("stdout", ""),
            "stderr": exec_result.get("stderr", ""),
            "duration_ms": exec_result.get("duration_ms", 0),
        }

    async def cleanup(self):
        """Kill all running tunnels (called on shutdown)."""
        for node_id in list(self._tunnels.keys()):
            await self.stop_tunnel(node_id)
        log.info("All SSH tunnels cleaned up")

    # reload_tunnels is defined earlier in this class (with DB status updates)
