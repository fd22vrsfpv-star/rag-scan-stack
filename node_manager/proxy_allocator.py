"""
Manages SOCKS proxy port allocation for remote nodes.

Port ranges:
  - Sliver nodes:  10000-10099 (100 ports)
  - Chisel nodes:  10100-10119 (20 ports)
  - SSH tunnels:   10120-10149 (30 ports)
"""

import logging
import socket
import threading
from typing import Optional

import psycopg2

log = logging.getLogger("proxy_allocator")

SLIVER_PORT_START = 10000
SLIVER_PORT_END = 10099
CHISEL_PORT_START = 10100
CHISEL_PORT_END = 10119
SSH_PORT_START = 10120
SSH_PORT_END = 10149


class ProxyAllocator:
    def __init__(self, db_dsn: str):
        self.db_dsn = db_dsn
        self._allocated: dict[int, str] = {}  # port -> node_id
        self._lock = threading.Lock()  # Thread safety for concurrent allocations
        self._load_from_db()

    def _get_conn(self):
        return psycopg2.connect(self.db_dsn)

    def _load_from_db(self):
        """Load current port assignments from the remote_nodes table."""
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT id::text, proxy_port FROM remote_nodes WHERE proxy_port IS NOT NULL"
            )
            for node_id, port in cur.fetchall():
                self._allocated[port] = node_id
            cur.close()
            conn.close()
            log.info("Loaded %d port assignments from DB", len(self._allocated))
        except Exception as e:
            log.warning("Could not load port assignments from DB: %s", e)

    def _port_range(self, node_type: str) -> tuple[int, int]:
        if node_type == "sliver":
            return SLIVER_PORT_START, SLIVER_PORT_END
        elif node_type == "chisel":
            return CHISEL_PORT_START, CHISEL_PORT_END
        elif node_type == "ssh":
            return SSH_PORT_START, SSH_PORT_END
        else:
            raise ValueError(f"Unknown node_type: {node_type}")

    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """Check if a port is already bound by a local process."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.bind(("0.0.0.0", port))
                return False  # bind succeeded — port is free
        except OSError:
            return True  # port already in use

    def allocate(self, node_type: str, node_id: str) -> int:
        """Allocate the next available port for a node type. Thread-safe.
        Skips ports that are in use by OS processes (orphan tunnels, etc.)."""
        with self._lock:
            start, end = self._port_range(node_type)
            for port in range(start, end + 1):
                if port not in self._allocated:
                    if self.is_port_in_use(port):
                        log.warning("Port %d free in allocator but bound by OS — skipping", port)
                        continue
                    self._allocated[port] = node_id
                    log.info("Allocated port %d for node %s (%s)", port, node_id, node_type)
                    return port
            raise RuntimeError(
                f"No available ports in range {start}-{end} for {node_type}"
        )

    def ensure_port_free(self, port: int, node_id: str, node_type: str) -> int:
        """Verify a previously-assigned port is still usable for this node.
        If another node or orphan process holds it, reassign to the next free port.
        Returns the (possibly new) port."""
        with self._lock:
            current_owner = self._allocated.get(port)

            # Port is ours in the allocator — check if OS agrees
            if current_owner == node_id:
                if not self.is_port_in_use(port):
                    return port  # free and ours — good
                # Port bound by something else (orphan process)
                log.warning("Port %d assigned to %s but bound by orphan process — reassigning", port, node_id)
                del self._allocated[port]
            elif current_owner is not None:
                # Another node owns this port in the allocator
                log.warning("Port %d assigned to %s, not %s — reassigning", port, current_owner, node_id)
            else:
                # Port not in allocator — claim it if free
                if not self.is_port_in_use(port):
                    self._allocated[port] = node_id
                    return port
                log.warning("Port %d not in allocator but bound by OS — reassigning %s", port, node_id)

        # Allocate a new port (lock released, allocate() re-acquires)
        new_port = self.allocate(node_type, node_id)
        log.info("Reassigned node %s: port %d -> %d", node_id, port, new_port)
        return new_port

    def release(self, port: int) -> Optional[str]:
        """Release a port allocation. Thread-safe."""
        with self._lock:
            node_id = self._allocated.pop(port, None)
            if node_id:
                log.info("Released port %d (was node %s)", port, node_id)
            return node_id

    def get_node_port(self, node_id: str) -> Optional[int]:
        """Get the allocated port for a node, or None."""
        for port, nid in self._allocated.items():
            if nid == node_id:
                return port
        return None

    @property
    def allocated_ports(self) -> dict[int, str]:
        return dict(self._allocated)
