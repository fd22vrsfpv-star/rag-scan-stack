#!/usr/bin/env python3
import json, os, re, sys
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_batch

JSON_PATH = os.environ.get("SEARCHSPLOIT_JSON", "/var/lib/searchsploit/searchsploit.json")
DSN = os.environ.get("PG_DSN", "postgres://edb_rw:ChangeMe_RW_#1@rag-postgres:5432/exploits")

cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def load_json(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)

def parse_entry(e):
    """
    SearchSploit -o -j output entries typically include keys like:
      ID, Title, Date, Author, Type, Platform, Port, Path, URL, ...
    The schema can vary; we defensively map fields.
    """
    # ID may be int or str; ensure int edb_id
    edb_id = int(e.get("ID") or e.get("id") or e.get("Exploit-ID") or 0)
    file_path = e.get("Path") or e.get("File") or e.get("path") or ""
    title = e.get("Title") or e.get("Description") or e.get("title") or ""
    date_str = e.get("Date") or e.get("date") or ""
    date_published = None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%Y"):
        try:
            if date_str:
                date_published = datetime.strptime(date_str, fmt).date()
                break
        except Exception:
            pass
    author = e.get("Author") or e.get("author")
    type_ = e.get("Type") or e.get("type")
    platform = e.get("Platform") or e.get("platform")
    port = str(e.get("Port")) if e.get("Port") is not None else None

    # CVEs: some JSON builds include "Codes" or "CVE" arrays; fall back to regex
    raw_cves = []
    for key in ("CVE", "CVEs", "Codes"):
        v = e.get(key)
        if isinstance(v, list):
            raw_cves.extend(v)
        elif isinstance(v, str):
            raw_cves.extend([v])
    if not raw_cves:
        raw_cves.extend(cve_re.findall(title or ""))
        # Secondary scan in path/title-like fields
        raw_cves.extend(cve_re.findall((e.get("Description") or "")))

    cves = sorted({c.upper() for c in raw_cves if c and "CVE-" in c.upper()})

    # Build minimal description (optional)
    desc = e.get("Description") or e.get("Desc") or ""

    return (edb_id, file_path, title, date_published, author, type_, platform, port, cves, desc)

def main():
    data = load_json(JSON_PATH)
    if isinstance(data, dict) and "RESULTS_EXPLOIT" in data:
        entries = data["RESULTS_EXPLOIT"]
    elif isinstance(data, list):
        entries = data
    else:
        print("Unrecognized JSON structure; expected RESULTS_EXPLOIT or list.", file=sys.stderr)
        sys.exit(2)

    rows = []
    for e in entries:
        try:
            row = parse_entry(e)
            if row[0] > 0:
                rows.append(row)
        except Exception as ex:
            # Skip bad rows but continue
            print(f"Warn: failed to parse entry: {ex}", file=sys.stderr)

    conn = psycopg2.connect(DSN)
    cur = conn.cursor()

    # Upsert in batches
    sql = """
    INSERT INTO edb.exploits
      (edb_id, file_path, title, date_published, author, type, platform, port, cves, description)
    VALUES
      (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (edb_id) DO UPDATE SET
      file_path      = EXCLUDED.file_path,
      title          = EXCLUDED.title,
      date_published = EXCLUDED.date_published,
      author         = EXCLUDED.author,
      type           = EXCLUDED.type,
      platform       = EXCLUDED.platform,
      port           = EXCLUDED.port,
      cves           = EXCLUDED.cves,
      description    = EXCLUDED.description;
    """

    inserted = 0
    batch_size = 2000
    for i in range(0, len(rows), batch_size):
        chunk = rows[i:i+batch_size]
        execute_batch(cur, sql, chunk, page_size=len(chunk))
        inserted += len(chunk)

    conn.commit()
    cur.close(); conn.close()
    print(json.dumps({"ok": True, "processed": len(rows)}))

if __name__ == "__main__":
    main()
