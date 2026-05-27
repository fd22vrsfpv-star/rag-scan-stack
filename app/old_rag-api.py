@app.post("/run-masscan-nmap")
def run_masscan_nmap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Text file with newline/comma separated IPs/CIDRs; supports # comments"),
    ports: str = Query("1-65535", description="Ports range/list for Masscan"),
    rate: int = Query(1000, ge=1, description="Masscan rate (pps)"),
    interface: Optional[str] = Query(None, description="Network interface for Masscan (-e)"),
    whitelist: Optional[List[str]] = Query(None, description="Optional CIDRs to include; others excluded"),
    blacklist: Optional[List[str]] = Query(None, description="Optional CIDRs to exclude"),
    idempotency_key: Optional[str] = Query(None),
    authorized: bool = Depends(auth),
):
    # Read and parse targets file
    tmp_path = _save_upload_to_tmp(file)
    try:
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    finally:
        os.remove(tmp_path)

    targets = _parse_targets_text(content, whitelist=whitelist, blacklist=blacklist)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets after applying filters")

    # Create job and queued pipeline task
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if idempotency_key:
            cur.execute("SELECT id, status FROM jobs WHERE idempotency_key=%s AND type=%s", (idempotency_key, "masscan-nmap"))
            row = cur.fetchone()
            if row:
                return {"id": str(row["id"]), "status": row["status"], "dedup": True}

        params = {
            "ports": ports,
            "rate": rate,
            "interface": interface,
            "targets_count": len(targets),
            "whitelist": whitelist or [],
            "blacklist": blacklist or [],
        }
        cur.execute(
            "INSERT INTO jobs (type, params, idempotency_key, status) VALUES (%s,%s,%s,'queued') RETURNING id",
            ("masscan-nmap", Json(params), idempotency_key),
        )
        job_id = str(cur.fetchone()["id"])
        cur.execute("INSERT INTO tasks (job_id, type, status) VALUES (%s::uuid,'pipeline','queued')", (job_id,))
        cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, 1) WHERE id=%s::uuid", (job_id,))
        conn.commit()

    # Schedule background execution and return immediately
    background_tasks.add_task(_background_run_masscan_nmap, job_id, targets, ports, rate, interface)
    return {"id": job_id, "status": "queued"}
