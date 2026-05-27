import os, subprocess, pathlib, json, re, logging, time
import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nmap_enrichment")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
BATCH_SIZE = int(os.environ.get("NMAP_PORT_BATCH", "100"))
OUT_DIR = pathlib.Path(os.environ.get("NMAP_OUT_DIR", "/tmp/nmap_out"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

SERVICE_DETECTION = os.environ.get("NMAP_SERVICE_DETECTION", "1") == "1"
VERSION_INTENSITY = int(os.environ.get("NMAP_VERSION_INTENSITY", "9"))
EXTRA_SCRIPTS = os.environ.get("NMAP_SCRIPTS", "").strip()
# Hard wall-clock cap per nmap batch to keep a stuck host from wedging
# enrichment forever. Default 1h per batch; set to 0 to disable.
NMAP_BATCH_TIMEOUT = int(os.environ.get("NMAP_BATCH_TIMEOUT", "3600"))

def _safe_name(s: str) -> str:
    return re.sub(r'[^0-9A-Za-z._-]+', '_', s)

def get_open_ports_by_host():
    with psycopg2.connect(DB_DSN) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT host(a.ip)::text AS ip, array_agg(p.port ORDER BY p.port) AS ports
            FROM ports p JOIN assets a ON a.id = p.asset_id
            WHERE COALESCE(p.is_open, true)
            GROUP BY host(a.ip) HAVING COUNT(*) > 0
        """ )
        return cur.fetchall()

def run_nmap_batch(ip, ports, batch_idx):
    safe_ip = _safe_name(ip)
    # Base path without extension - nmap -oA adds .xml, .gnmap, .nmap automatically
    base_path = OUT_DIR / f"nmap_{safe_ip}_{batch_idx}"
    base_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["nmap", "-Pn", "-sT", "-T4", "-p", ",".join(map(str, ports))]
    if SERVICE_DETECTION: cmd += ["-sV", "--version-intensity", str(VERSION_INTENSITY)]
    if EXTRA_SCRIPTS: cmd += ["--script", EXTRA_SCRIPTS]
    cmd += ["-oA", str(base_path), ip]

    logger.info(f"[nmap] Starting scan: {ip} batch {batch_idx} ({len(ports)} ports)")
    start_time = time.time()
    try:
        timeout_arg = NMAP_BATCH_TIMEOUT if NMAP_BATCH_TIMEOUT > 0 else None
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_arg)
    except subprocess.TimeoutExpired as te:
        duration = time.time() - start_time
        logger.error(
            f"[nmap] Scan exceeded {NMAP_BATCH_TIMEOUT}s wall-clock: {ip} batch {batch_idx} "
            f"({len(ports)} ports) — aborting batch"
        )
        raise RuntimeError(
            f"nmap batch timed out after {NMAP_BATCH_TIMEOUT}s (ip={ip}, ports={len(ports)})"
        ) from te
    duration = time.time() - start_time

    if cp.returncode != 0:
        logger.error(f"[nmap] Scan failed: {ip} - exit {cp.returncode}")
        raise RuntimeError(f"nmap exit {cp.returncode}: {cp.stderr or cp.stdout}")

    logger.info(f"[nmap] Completed: {ip} batch {batch_idx} in {duration:.1f}s")
    # Return the .xml file path (nmap -oA creates base.xml, base.gnmap, base.nmap)
    return str(base_path) + ".xml"

def main(progress_callback=None):
    """Run nmap enrichment on all open ports from masscan.

    Args:
        progress_callback: Optional fn(pct: int, eta_sec: int|None) called after each batch
    """
    logger.info("[nmap_enrichment] Starting nmap enrichment process")
    stats = {"hosts": 0, "batches": 0, "xml_files": 0, "parsed_xml": 0, "errors": 0, "error_examples": []}
    hosts = get_open_ports_by_host()
    stats["hosts"] = len(hosts)

    total_ports = sum(len(row["ports"] or []) for row in hosts)
    logger.info(f"[nmap_enrichment] Found {len(hosts)} hosts with {total_ports} total open ports to scan")

    # Count total batches for progress
    total_batches = sum(
        len(range(0, len(row["ports"] or []), BATCH_SIZE)) for row in hosts
    )
    completed_batches = 0
    _enrich_start = time.time()

    produced = []
    for row in hosts:
        ip, plist = row["ip"], row["ports"] or []
        logger.info(f"[nmap_enrichment] Processing host {ip} ({len(plist)} ports)")
        for i in range(0, len(plist), BATCH_SIZE):
            batch = plist[i:i+BATCH_SIZE]
            try:
                path = run_nmap_batch(ip, batch, i//BATCH_SIZE)
                produced.append(path)
                stats["batches"] += 1
                stats["xml_files"] += 1
            except Exception as e:
                stats["errors"] += 1
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"{type(e).__name__}: {e}")
            completed_batches += 1
            if progress_callback and total_batches > 0:
                pct = int(completed_batches / total_batches * 80)  # nmap scanning = 0-80%
                elapsed = time.time() - _enrich_start
                eta = int(elapsed / max(completed_batches, 1) * (total_batches - completed_batches))
                progress_callback(pct, eta)

    logger.info(f"[nmap_enrichment] Parsing {len(produced)} XML files")
    from etl.parse_nmap import parse_nmap
    for idx, path in enumerate(produced):
        try:
            parse_nmap(path, profile="from-masscan")
            stats["parsed_xml"] += 1
            logger.info(f"[nmap_enrichment] Parsed: {path}")
        except Exception as e:
            stats["errors"] += 1
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"parse {path}: {type(e).__name__}: {e}")
        if progress_callback and produced:
            pct = 80 + int((idx + 1) / len(produced) * 20)  # parsing = 80-100%
            progress_callback(pct, None)

    logger.info(f"[nmap_enrichment] Complete! hosts={stats['hosts']}, batches={stats['batches']}, parsed={stats['parsed_xml']}, errors={stats['errors']}")
    return stats

if __name__ == "__main__":
    main()
