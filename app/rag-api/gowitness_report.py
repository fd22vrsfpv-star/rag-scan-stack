#!/usr/bin/env python3
"""One combined GoWitness report — every screenshot on one page, no clicking.

WHY THIS EXISTS
---------------
The GoWitness data was always complete and always stored: 669 examplecorp records
in `recon_findings`, every one carrying url, final_url, status_code, title,
server, technologies, TLS, the redirect target AND the screenshot path. What was
missing was a way to LOOK at it. The Screenshots tab renders a grid of
unlabelled thumbnails, so triaging 669 hosts meant opening each one to find out
whether it was a live app, a 403, or a parked GoDaddy holder.

Used two ways from one implementation:

  * `GET /recon/gowitness-report` in api.py — `fmt=json` for the UI,
    `fmt=csv` / `fmt=html` as downloads.
  * as a CLI, for a quick look without the dashboard:
        docker exec rag-api python3 /app/gowitness_report.py examplecorp

The HTML contact sheet REFERENCES screenshots through the dashboard proxy
(`/api/screenshots/<path>`) rather than embedding them: the examplecorp set alone
is 59 MB of PNG, which as base64 would be a ~79 MB file. Open it with the
dashboard up and the images resolve; the table is readable either way.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
import re
import sys
from collections import Counter

DASHBOARD = os.environ.get("DASHBOARD_URL", "https://localhost:3002")

FIELDS = ["url", "final_url", "status_code", "title", "server", "content_length",
          "protocol", "technologies", "redirect_to", "tls_issuer", "tls_protocol",
          "screenshot", "target", "first_seen"]


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s or "report")).strip("_") or "report"


def rows_from_records(records, statuses=None) -> list[dict]:
    """(data, target, engagement_id, created_at) tuples -> flat dicts.

    `statuses` filters by status code when given. A record whose status cannot
    be parsed keeps a blank rather than being dropped — a screenshot we took and
    cannot classify is still evidence, and silently losing it would make the
    count disagree with the Screenshots tab.
    """
    out = []
    for rec in records or []:
        data = rec[0] if isinstance(rec, (list, tuple)) else rec
        target = rec[1] if isinstance(rec, (list, tuple)) and len(rec) > 1 else ""
        seen = rec[3] if isinstance(rec, (list, tuple)) and len(rec) > 3 else ""
        d = data or {}
        sc = d.get("status_code")
        try:
            sc = int(sc) if sc not in (None, "") else None
        except (TypeError, ValueError):
            sc = None
        if statuses and sc not in statuses:
            continue
        tls = d.get("tls") if isinstance(d.get("tls"), dict) else {}
        out.append({
            "url": d.get("url") or "",
            "final_url": d.get("final_url") or "",
            "status_code": sc if sc is not None else "",
            "title": (d.get("title") or "").strip(),
            "server": d.get("server") or "",
            "content_length": d.get("content_length") or "",
            "protocol": d.get("protocol") or "",
            "technologies": ", ".join(d.get("technologies") or []),
            "redirect_to": d.get("redirect_to") or "",
            "tls_issuer": tls.get("issuer") or "",
            "tls_protocol": tls.get("protocol") or "",
            "screenshot": d.get("screenshot") or "",
            "target": target or "",
            "first_seen": str(seen or ""),
        })
    return out


def status_counts(rows) -> dict:
    return dict(Counter(str(r.get("status_code") or "?") for r in rows).most_common())


def badge(sc) -> str:
    """Colour by CLASS, not exact code — 2xx ok, 3xx redirect, 4xx client,
    5xx server, anything unparseable unknown."""
    try:
        n = int(sc)
    except (TypeError, ValueError):
        return "unk"
    return {2: "ok", 3: "redir", 4: "client", 5: "server"}.get(n // 100, "unk")


def to_csv(rows) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def to_html(rows, label: str, dashboard: str | None = None) -> str:
    base = (dashboard or DASHBOARD).rstrip("/")
    cls = Counter(badge(r.get("status_code")) for r in rows)
    chips = " ".join(
        f'<button class="chip" data-f="{html.escape(s)}">{html.escape(s)} <b>{n}</b></button>'
        for s, n in status_counts(rows).items())
    cards = []
    for r in rows:
        shot = r.get("screenshot") or ""
        src = f"{base}/api/screenshots/{html.escape(shot)}"
        img = (f'<img loading="lazy" src="{src}" alt="{html.escape(r.get("url",""))}">'
               if shot else '<div class="noshot">no screenshot</div>')
        redir = (f'<div class="r">&rarr; {html.escape(r["redirect_to"])}</div>'
                 if r.get("redirect_to") else "")
        cards.append(f"""
      <article class="card" data-s="{html.escape(str(r.get('status_code') or '?'))}">
        <a class="shot" href="{src}" target="_blank" rel="noopener">{img}</a>
        <div class="meta">
          <span class="badge {badge(r.get('status_code'))}">{html.escape(str(r.get('status_code') or '?'))}</span>
          <a class="u" href="{html.escape(r.get('url',''))}" target="_blank" rel="noopener">{html.escape(r.get('url',''))}</a>
          <div class="t">{html.escape(r.get('title') or '(no title)')}</div>
          {redir}
          <div class="tech">{html.escape(r.get('technologies',''))[:90]}</div>
        </div>
      </article>""")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GoWitness &mdash; {html.escape(label)}</title>
<style>
:root{{--bg:#0f1115;--fg:#e6e8ec;--mut:#9aa3b2;--line:#232834;--card:#161922;
--ok:#2f9e5e;--redir:#3b82f6;--client:#d97706;--server:#dc2626;--unk:#6b7280}}
@media(prefers-color-scheme:light){{:root{{--bg:#fbfbfd;--fg:#15181d;--mut:#5b6472;
--line:#e3e6ec;--card:#fff}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{position:sticky;top:0;z-index:5;background:var(--bg);
border-bottom:1px solid var(--line);padding:14px 16px}}
h1{{margin:0 0 2px;font-size:17px;letter-spacing:-.01em}}
.sub{{color:var(--mut);font-size:12px}}
.chips{{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}}
.chip{{cursor:pointer;border:1px solid var(--line);background:var(--card);
color:var(--fg);border-radius:999px;padding:3px 10px;font:inherit;font-size:12px}}
.chip[aria-pressed=true]{{outline:2px solid var(--redir);outline-offset:-1px}}
.chip b{{color:var(--mut);font-weight:600}}
.grid{{display:grid;gap:12px;padding:16px;
grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;
overflow:hidden;display:flex;flex-direction:column}}
.shot{{display:block;aspect-ratio:16/10;background:#0b0d12;overflow:hidden}}
.shot img{{width:100%;height:100%;object-fit:cover;object-position:top center;display:block}}
.noshot{{width:100%;height:100%;display:grid;place-items:center;color:var(--mut);font-size:12px}}
.meta{{padding:9px 10px;display:flex;flex-direction:column;gap:3px;min-width:0}}
.badge{{align-self:flex-start;font-size:11px;font-weight:700;color:#fff;
border-radius:5px;padding:1px 7px}}
.badge.ok{{background:var(--ok)}}.badge.redir{{background:var(--redir)}}
.badge.client{{background:var(--client)}}.badge.server{{background:var(--server)}}
.badge.unk{{background:var(--unk)}}
.u{{color:var(--fg);text-decoration:none;font-size:12px;word-break:break-all}}
.u:hover{{text-decoration:underline}}
.t{{color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.r{{color:var(--redir);font-size:11px;word-break:break-all}}
.tech{{color:var(--mut);font-size:11px;word-break:break-word}}
.hidden{{display:none}}
</style></head><body>
<header>
  <h1>GoWitness &mdash; {html.escape(label)}</h1>
  <div class="sub">{len(rows)} hosts &middot; {cls.get('ok',0)} 2xx &middot;
    {cls.get('redir',0)} 3xx &middot; {cls.get('client',0)} 4xx &middot;
    {cls.get('server',0)} 5xx &middot; images from {html.escape(base)}</div>
  <div class="chips"><button class="chip" data-f="" aria-pressed="true">all <b>{len(rows)}</b></button>{chips}</div>
</header>
<main class="grid">{''.join(cards)}</main>
<script>
const chips=[...document.querySelectorAll('.chip')],cards=[...document.querySelectorAll('.card')];
chips.forEach(c=>c.addEventListener('click',()=>{{
  const f=c.dataset.f;
  chips.forEach(x=>x.setAttribute('aria-pressed',String(x===c)));
  cards.forEach(k=>k.classList.toggle('hidden', !!f && k.dataset.s!==f));
}}));
</script></body></html>"""


# ── CLI ────────────────────────────────────────────────────────────────────

def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="GoWitness contact sheet + CSV")
    ap.add_argument("match", nargs="?", help="host/URL substring, e.g. examplecorp")
    ap.add_argument("--engagement")
    ap.add_argument("--status", help="comma-separated codes, e.g. 200,403")
    ap.add_argument("--out", help="output path without extension")
    a = ap.parse_args()
    if not a.match and not a.engagement:
        ap.error("give a match substring or --engagement")
    import psycopg2
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        sys.exit("DB_DSN not set — run inside rag-api")
    where, args = ["source = 'gowitness'"], []
    if a.match:
        where.append("(data->>'url' ILIKE %s OR COALESCE(target,'') ILIKE %s)")
        args += [f"%{a.match}%", f"%{a.match}%"]
    if a.engagement:
        where.append("engagement_id = %s")
        args.append(a.engagement)
    statuses = ({int(s) for s in a.status.split(",") if s.strip().isdigit()}
                if a.status else None)
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT data, target, engagement_id, created_at FROM recon_findings "
                    "WHERE " + " AND ".join(where) + " ORDER BY data->>'url'", args)
        rows = rows_from_records(cur.fetchall(), statuses)
    if not rows:
        print("no gowitness records matched")
        return 2
    label = a.match or a.engagement
    base = a.out or f"/tmp/gowitness_{slug(label)}"
    with open(base + ".csv", "w", encoding="utf-8") as fh:
        fh.write(to_csv(rows))
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(to_html(rows, label))
    print(f"{len(rows)} records -> {base}.csv  {base}.html")
    print("status:", json.dumps(status_counts(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
