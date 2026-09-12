import os, json, uuid, re, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor, Json

try:
    from scope_gate import load_ingest_scope, host_in_scope
except ImportError:  # pragma: no cover
    from etl.scope_gate import load_ingest_scope, host_in_scope


DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

def _ensure_asset(cur, ip_str):
    """Find or create an asset by IP, return asset_id or None."""
    try:
        ip = str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None
    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
    row = cur.fetchone()
    if row:
        asset_id = str(row["id"])
        cur.execute("UPDATE assets SET last_seen=now() WHERE id=%s", (asset_id,))
        return asset_id
    asset_id = str(uuid.uuid4())
    cur.execute("INSERT INTO assets (id, ip) VALUES (%s,%s)", (asset_id, ip))
    return asset_id

# NetExec output markers
SUCCESS_RE = re.compile(r'^\[[\+\*]\]\s+(.+)')
FAILURE_RE = re.compile(r'^\[\-\]\s+(.+)')
# e.g. SMB  192.168.1.100  445  DC01  [+] domain\user:password (Pwn3d!)
CRED_SUCCESS_RE = re.compile(
    r'(\S+)\s+'          # protocol
    r'(\d+\.\d+\.\d+\.\d+)\s+'  # IP
    r'(\d+)\s+'          # port
    r'(\S+)\s+'          # hostname
    r'\[\+\]\s+'         # success marker
    r'(\S+?)\\(\S+?):(\S+)'     # domain\user:password or hash
)
PWNED_RE = re.compile(r'\(Pwn3d!\)', re.IGNORECASE)

# ── Structured parse ───────────────────────────────────────────────────────
#
# `parse_netexec()` below writes findings to the database. This returns the same
# information as a dict, which is what `tool_executions.parsed_results` needs
# and what nothing was producing: every netexec run came back with
# parsed_results NULL, so the learner recorded it as "unmeasured" and learned
# nothing from 6,816 bytes of output.
#
# Every netexec line is `PROTO  IP  PORT  HOST  <rest>`, where rest is either a
# [*]/[+]/[-] marker line or a row of a table the module printed. Lines that do
# NOT match that shape are command output from `-x`, and they are kept: for a
# post-exploitation run they are the entire result.

_NX_LINE = re.compile(
    r"^(?P<proto>[A-Z][A-Z0-9]{1,9})\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<port>\d{1,5})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<rest>.*)$")
_NX_MARKER = re.compile(r"^\[(?P<mark>[-+*!])\]\s*(?P<text>.*)$")
# `(name:METASPLOITABLE) (domain:localdomain) (signing:False) (SMBv1:True)`
_NX_KV = re.compile(r"\(([A-Za-z0-9 _]+):\s*([^)]*)\)")
# `localdomain\msfadmin:msfadmin` and the domainless `msfadmin:msfadmin`
_NX_CRED = re.compile(r"^(?:(?P<domain>[^\\\s]+)\\)?(?P<user>[^:\s]+):(?P<secret>\S*)")
# Initialisation chatter printed on first run. Not results, and counting them as
# output makes an empty run look productive.
_NX_NOISE = re.compile(
    r"^\[\*\]\s*(?:First time use|Creating|Initializing|Copying default)", re.I)
# netexec renders exceptions through `rich`, which draws a box. Those lines have
# no netexec prefix, so they were being kept as command output and a run that
# raised `IncompatiblePeer` reported 72 lines of "results".
#
# The test is the box-drawing itself rather than the words inside it: a traceback
# about a protocol nobody anticipated is still a traceback, and matching on
# "Traceback" or an exception name would only catch the ones already seen.
_BOX_CHARS = set("│╭╮╯╰─━┃┏┓┗┛┆┇┊┋╎╏▌▐❱╷╵┌┐└┘├┤┬┴┼")
# A log line carries a level and the source location that emitted it —
# `[23:15:19] ERROR  Incompatible ssh peer ...  ssh.py:136`. Generic to anything
# using a structured logger, which is why it is matched on the SHAPE rather than
# on the words, and no command output looks like this.
_LOG_LINE = re.compile(
    r"^(?:\[[\d:.]+\]\s*)?(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+\S.*"
    r"[\w./-]+\.(?:py|go|rb|c):\d+\s*$")


def _mask_secret_in(line: str, username: str, secret: str) -> str:
    """Mask the password where it follows the `user:` separator.

    Only there. A blunt replacement would mangle `msfadmin:msfadmin`, where the
    username and the secret are the same string and the username is not secret.
    """
    if not (line and secret):
        return line
    keep = 3 if len(secret) > 4 else 0
    masked = (secret[:keep] + "*" * (len(secret) - keep)) if keep else "*" * len(secret)
    return re.sub(rf"({re.escape(username)}:){re.escape(secret)}",
                  lambda m: m.group(1) + masked, line)


def parse_netexec_output(text: str) -> dict:
    """Structure netexec output. Pure — no database, no I/O.

    Returns credentials, host facts, table rows (shares and the like), command
    output from `-x`, and the counts a caller needs to decide whether the run
    produced anything.
    """
    out = {
        "tool": "netexec",
        "protocols": [],
        "hosts": [],            # one per (ip, port) with its advertised facts
        "credentials": [],
        "shares": [],
        "findings": [],         # [+] lines that are not credentials
        "info": [],
        "failures": [],
        "command_output": [],   # lines from -x, which have no netexec prefix
        "diagnostic_lines": [],  # rendered tracebacks — a failure, not a result
        "noise_lines": 0,
    }
    seen_hosts = {}
    table_header = None
    in_diagnostic = False

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _NX_NOISE.match(line.strip()):
            out["noise_lines"] += 1
            continue

        m = _NX_LINE.match(line)
        if not m:
            # No netexec prefix: either output from the command `-x` ran, or a
            # rendered traceback. The first is the run's entire result and
            # dropping it would make a post-exploitation step report nothing;
            # the second is a failure and counting it as output makes a run that
            # achieved nothing look productive.
            boxed = any(ch in _BOX_CHARS for ch in line)
            if boxed:
                in_diagnostic = True
            # Once a traceback has started, the unprefixed lines that follow are
            # the wrapped exception message, not output: `IncompatiblePeer:
            # Incompatible ssh peer (no` / `acceptable host key)` arrived as two
            # separate lines outside the box. A rendered traceback ends the
            # useful output, so everything after it is diagnostic until netexec
            # speaks again.
            if boxed or in_diagnostic or _LOG_LINE.match(line.strip()):
                out["diagnostic_lines"].append(line.strip()[:300])
            else:
                out["command_output"].append(line.strip())
            continue

        in_diagnostic = False   # netexec is talking again
        proto = m.group("proto").lower()
        ip, port, host = m.group("ip"), int(m.group("port")), m.group("host")
        rest = m.group("rest").strip()
        if proto not in out["protocols"]:
            out["protocols"].append(proto)

        key = (ip, port)
        if key not in seen_hosts:
            seen_hosts[key] = {"protocol": proto, "ip": ip, "port": port,
                               "hostname": host, "facts": {}}
            out["hosts"].append(seen_hosts[key])

        mk = _NX_MARKER.match(rest)
        if mk:
            mark, txt = mk.group("mark"), mk.group("text").strip()
            facts = {k.strip().lower().replace(" ", "_"): v.strip()
                     for k, v in _NX_KV.findall(txt)}
            if facts:
                seen_hosts[key]["facts"].update(facts)
            if mark == "+":
                cred = _NX_CRED.match(txt)
                # A credential line is `user:secret`; anything else marked [+]
                # is a finding in its own right (a module result, "Pwn3d!", ...).
                if cred and ":" in txt.split()[0]:
                    secret = cred.group("secret")
                    out["credentials"].append({
                        "protocol": proto, "ip": ip, "port": port,
                        "hostname": host,
                        "domain": cred.group("domain"),
                        "username": cred.group("user"),
                        "secret": secret,
                        "pwned": bool(PWNED_RE.search(txt)),
                        # The structured `secret` above is the field consumers
                        # read and it is stored deliberately, the same as
                        # credential_findings.secret_value. `raw_line` is a
                        # verbatim copy that lands in a jsonb blob the UI dumps
                        # without masking, so the secret is masked HERE — the
                        # same defect as the credential audit evidence, which
                        # re-exposed a password the row above had carefully
                        # hidden behind a Reveal click.
                        "raw_line": _mask_secret_in(line.strip(),
                                                    cred.group("user"), secret),
                    })
                else:
                    out["findings"].append({"protocol": proto, "ip": ip,
                                            "text": txt, "raw_line": line.strip()})
            elif mark == "-":
                out["failures"].append({"protocol": proto, "ip": ip, "text": txt})
            else:
                out["info"].append({"protocol": proto, "ip": ip, "text": txt})
            continue

        # A table row. netexec prints a header then a rule of dashes; the rows
        # after it are results. Columns are whitespace-separated with a variable
        # gap, and the last column can be empty (`opt   READ`) or contain
        # spaces (`IPC Service (metasploitable server ...)`).
        cells = re.split(r"\s{2,}", rest)
        if cells and cells[0].lower() in ("share", "name") and len(cells) > 1:
            # Record the COLUMN OFFSETS, not just the names. This is a
            # fixed-width table and an empty cell is meaningful: IPC$ and ADMIN$
            # have no permissions at all, so splitting on whitespace shifted the
            # Remark into Permissions and reported
            # `IPC$ | IPC Service (metasploitable server ...)` as a permission
            # string. Slicing at the header's own offsets keeps an empty cell
            # empty.
            table_header = []
            for name in cells:
                idx = rest.index(name, table_header[-1][1] + 1 if table_header else 0)
                table_header.append((name.strip().lower(), idx))
            continue
        if set(rest.replace(" ", "")) <= {"-"}:
            continue
        if table_header:
            row = {}
            for i, (name, start) in enumerate(table_header):
                end = table_header[i + 1][1] if i + 1 < len(table_header) else len(rest)
                row[name] = rest[start:end].strip()
            row.update({"ip": ip, "protocol": proto})
            if table_header[0][0] == "share":
                perms = (row.get("permissions") or "").upper()
                row["writable"] = "WRITE" in perms
                row["readable"] = "READ" in perms
                out["shares"].append(row)
            else:
                out["findings"].append({"protocol": proto, "ip": ip, "row": row})
            continue
        out["command_output"].append(rest)

    out["counts"] = {
        "credentials": len(out["credentials"]),
        "shares": len(out["shares"]),
        "writable_shares": sum(1 for s in out["shares"] if s.get("writable")),
        "findings": len(out["findings"]),
        "failures": len(out["failures"]),
        "command_output_lines": len(out["command_output"]),
        "diagnostic_lines": len(out["diagnostic_lines"]),
        "hosts": len(out["hosts"]),
    }
    # What makes this run count as having produced something. Deliberately
    # excludes `info` and `noise_lines`: a first run prints a dozen [*] lines
    # about creating its own directories, and treating those as results is how
    # a run that achieved nothing reports as productive.
    out["productive"] = bool(
        out["credentials"] or out["shares"] or out["findings"]
        or out["command_output"])
    return out


def parse_netexec(path: str, profile: str = "upload", job_id: str = None):
    r"""Parse NetExec log output.

    NetExec output format (line-based):
    SMB  192.168.1.100  445  DC01  [+] DOMAIN\admin:Password123 (Pwn3d!)
    SMB  192.168.1.100  445  DC01  [-] DOMAIN\user:wrongpass STATUS_LOGON_FAILURE
    SMB  192.168.1.100  445  DC01  [*] Windows Server 2019
    """
    stats = dict(out_of_scope=0, records_seen=0, assets_upserted=0, recon_findings_inserted=0,
                 credential_successes=0, skipped=0, errors=0, error_examples=[])

    lines = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    stats["records_seen"] = len(lines)
    if not lines:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _enforce_scope, _scope_rows = load_ingest_scope(cur)
            for line in lines:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    # Try to parse credential success lines
                    m = CRED_SUCCESS_RE.search(line)
                    if m:
                        protocol = m.group(1).lower()
                        ip = m.group(2)
                        # Ingest scope gate: netexec output can name hosts discovered on the segment, not just the target.
                        if not host_in_scope(ip, _enforce_scope, _scope_rows):
                            stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
                            cur.execute("RELEASE SAVEPOINT rec_sp")
                            continue
                        port = int(m.group(3))
                        host_name = m.group(4)
                        domain = m.group(5)
                        username = m.group(6)
                        secret = m.group(7)
                        pwned = bool(PWNED_RE.search(line))

                        asset_id = _ensure_asset(cur, ip)
                        if asset_id:
                            stats["assets_upserted"] += 1

                        data = {
                            "protocol": protocol,
                            "ip": ip,
                            "port": port,
                            "hostname": host_name,
                            "domain": domain,
                            "username": username,
                            "pwned": pwned,
                            "raw_line": line,
                        }

                        severity = "critical" if pwned else "high"
                        finding_type = "credential_valid"

                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'netexec', %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, finding_type, ip, Json(data), severity))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1
                            stats["credential_successes"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Parse informational/enumeration lines
                    sm = SUCCESS_RE.match(line)
                    if sm:
                        # Extract IP if present
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        asset_id = None
                        target = ""
                        if ip_match:
                            target = ip_match.group(1)
                            asset_id = _ensure_asset(cur, target)
                            if asset_id:
                                stats["assets_upserted"] += 1

                        data = {"raw_line": line}
                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'netexec', 'enumeration', %s, %s, 'info')
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, target, Json(data)))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Failure lines — skip (not interesting for findings)
                    if FAILURE_RE.match(line):
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    stats["skipped"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")

                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
