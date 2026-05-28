from typing import Optional, Any
import os
import re
import json
import logging
import pathlib
import httpx
from utils import safe_json

log = logging.getLogger("scans")
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel
from config import get_settings
from polling import register_job, active_jobs, _persist, pending_queue
from timeouts import TIMEOUT_NORMAL, TIMEOUT_SCAN

router = APIRouter()

# Max concurrent scans — prevents overwhelming scanners when batching
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))


def get_max_concurrent() -> int:
    return MAX_CONCURRENT_SCANS


def set_max_concurrent(value: int):
    global MAX_CONCURRENT_SCANS
    MAX_CONCURRENT_SCANS = max(1, min(value, 50))  # clamp 1-50


def _count_active_scans() -> int:
    """Count currently running/queued scans."""
    return sum(1 for info in active_jobs.values()
               if info.get("status") in ("running", "queued"))


BLOCK_LOCAL_SCANS = os.environ.get("BLOCK_LOCAL_SCANS", "").lower() in ("1", "true", "yes")
# Also check app_settings at runtime (cached 60s so we don't hit DB every request)
_block_local_cache: dict = {"val": None, "ts": 0}


def _is_local_blocked() -> bool:
    """Check if local (non-proxied) scans are blocked. Reads from env OR app_settings."""
    import time
    if BLOCK_LOCAL_SCANS:
        return True
    now = time.time()
    if _block_local_cache["ts"] > now - 60:
        return bool(_block_local_cache["val"])
    # Check DB setting
    try:
        import httpx as _hx
        s = get_settings()
        r = _hx.get(f"{s.rag_api_url}/settings/config/block_local_scans",
                     headers={"x-api-key": s.api_key}, verify=False, timeout=3)
        val = r.json().get("value", "") if r.status_code == 200 else ""
        _block_local_cache["val"] = val.lower() in ("1", "true", "yes")
        _block_local_cache["ts"] = now
    except Exception:
        _block_local_cache["ts"] = now
    return bool(_block_local_cache["val"])


def _check_proxy_required(proxy: str | None, scan_type: str):
    """If 'block local scans' is enabled, reject any scan without a proxy."""
    if not _is_local_blocked():
        return
    # Allow passive/OSINT tools that don't touch the target directly
    PASSIVE_TYPES = {"subfinder", "dnsx", "crtsh", "uncover", "chaos", "vulnx",
                     "recon-pipeline", "greyhatwarfare", "whois", "cloud-tenant"}
    if scan_type in PASSIVE_TYPES:
        return
    if not proxy:
        raise HTTPException(
            403,
            f"Local scans are blocked. All active scans must route through a proxy/tunnel. "
            f"Set a proxy in the scan form or enable a tunnel in the Recon Agent. "
            f"To disable this restriction: Settings → General → 'Block local scans' toggle, "
            f"or unset BLOCK_LOCAL_SCANS env var."
        )


def _check_scan_limit():
    """Raise 429 if at the concurrent scan limit."""
    active = _count_active_scans()
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"Scan limit reached: {active}/{MAX_CONCURRENT_SCANS} active. "
                                 f"Wait for running scans to complete.")


def _ensure_target_list(p: dict, key: str = "targets") -> list[str]:
    """Normalize targets: split comma-separated strings into a proper list."""
    val = p.get(key) or p.get("target") or ""
    if isinstance(val, list):
        # Flatten any comma-separated entries within the list
        result = []
        for item in val:
            result.extend(t.strip() for t in str(item).split(",") if t.strip())
        return result
    return [t.strip() for t in str(val).split(",") if t.strip()]


def _extract_first_url(p: dict) -> str:
    """Extract first URL from target_url or target_urls (string or list)."""
    if p.get("target_url"):
        return str(p["target_url"]).strip().split("\n")[0].strip()
    urls = p.get("target_urls", "")
    if isinstance(urls, list):
        return urls[0] if urls else ""
    if isinstance(urls, str):
        for line in urls.split("\n"):
            line = line.strip()
            if line:
                return line
    return ""


def _extract_all_urls(p: dict) -> list:
    """Extract all URLs from target_url or target_urls."""
    urls = []
    if p.get("target_urls"):
        raw = p["target_urls"]
        if isinstance(raw, list):
            urls = [u.strip() for u in raw if u.strip()]
        elif isinstance(raw, str):
            urls = [u.strip() for u in raw.split("\n") if u.strip()]
    elif p.get("target_url"):
        urls = [str(p["target_url"]).strip()]
    return urls


def _ensure_url(val: str) -> str:
    """Ensure a value has an http(s) scheme so Pydantic HttpUrl accepts it."""
    if not val:
        return val
    val = val.strip()
    if not val:
        return val
    if not val.startswith(("http://", "https://")):
        val = f"https://{val}"
    return val


def _inject_burp_proxy(p: dict) -> dict:
    """If burp_proxy is enabled, inject HTTP proxy URL for tool to route through Burp."""
    if p.get("burp_proxy") in (True, "true", "1"):
        s = get_settings()
        p["http_proxy"] = s.burp_proxy_url
        # Remove the toggle key so it doesn't confuse downstream tools
        p.pop("burp_proxy", None)
    return p


def _coerce_int(v: Any) -> Optional[int]:
    """Best-effort int coercion. Returns None for empty / non-numeric / <=0."""
    if v in (None, "", False):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


_TOP_PORTS_RE = re.compile(r"^--top-ports[\s=]*(\d+)$")


def _normalize_ports(p: dict) -> None:
    """If `ports` field starts with --top-ports, MUST move it into extra_args
    BEFORE the lambda reads p["ports"]. Handles missing-space form too
    (e.g. `--top-ports1000` → `--top-ports 1000`)."""
    ports = (p.get("ports") or "").strip()
    if not ports.startswith("--top-ports"):
        return
    m = _TOP_PORTS_RE.match(ports)
    if m:
        normalized = f"--top-ports {m.group(1)}"
    else:
        # Already had a space (e.g. "--top-ports 1000 --foo"); preserve as-is
        normalized = ports
    existing = (p.get("extra_args") or "").strip()
    p["extra_args"] = (existing + " " + normalized).strip()
    p["ports"] = ""  # cleared so masscan port validator doesn't see it


def _coerce_nmap_opts(p: dict) -> dict:
    """Coerce nmap option strings from the frontend into proper types.
    Caller MUST run _normalize_ports(p) first if --top-ports might be in `ports`."""
    opts = {}
    if p.get("service_detection"):
        opts["service_detection"] = p["service_detection"] in ("true", "1", True)
    if p.get("version_intensity"):
        try: opts["version_intensity"] = int(p["version_intensity"])
        except (ValueError, TypeError): pass
    if p.get("os_detection"):
        opts["os_detection"] = p["os_detection"] in ("true", "1", True)
    for k in ("scripts", "scan_type_flag", "timing", "script_args", "extra_args"):
        if p.get(k): opts[k] = p[k]
    return opts


_UDP_DEFAULT_PORTS = "53,67,68,69,111,123,135,137,161,445,500,514,1434,1900,5353"


def _udp_payload(p: dict) -> dict:
    """Build /jobs/nmap-udp payload. Routes --top-ports N → top_ports field
    (UDP scan validator requires raw port list, not nmap flag syntax)."""
    ports = (p.get("ports") or "").strip()
    top_ports: Optional[int] = None
    payload: dict = {
        "targets": _ensure_target_list(p),
        "timeout_seconds": _coerce_int(p.get("timeout_seconds")),
    }
    if ports.startswith("--top-ports"):
        m = _TOP_PORTS_RE.match(ports)
        if m:
            top_ports = int(m.group(1))
            payload["top_ports"] = top_ports
            # don't send `ports` — server uses one or the other
        else:
            # User wrote something unparseable; fall back to default port list
            payload["ports"] = _UDP_DEFAULT_PORTS
    else:
        payload["ports"] = ports or _UDP_DEFAULT_PORTS
    # Allow explicit top_ports field too if frontend ever sends it
    explicit_top = _coerce_int(p.get("top_ports"))
    if explicit_top:
        payload["top_ports"] = explicit_top
        payload.pop("ports", None)
    return {k: v for k, v in payload.items() if v is not None and v != ""}


def _nmap_payload(p: dict, with_proxy: bool = False) -> dict:
    """Build masscan-then-nmap payload. Normalizes --top-ports BEFORE reading ports."""
    _normalize_ports(p)
    payload = {
        "targets": _ensure_target_list(p),
        "ports": p.get("ports") or None,
        "rate": p.get("rate", 1000),
        "timeout_seconds": _coerce_int(p.get("timeout_seconds")),
        **_coerce_nmap_opts(p),
    }
    if with_proxy:
        payload["proxy"] = p.get("proxy")
    return {k: v for k, v in payload.items() if v is not None and v != ""}


# Scan type → (service_url_attr, path, payload_transform)
SCAN_ROUTES = {
    "full": ("nmap_scanner_url", "/jobs/full-scan", lambda p: {k: v for k, v in {
        "targets": _ensure_target_list(p), "rate": p.get("rate", 1000),
        "timeout_seconds": _coerce_int(p.get("timeout_seconds")),
    }.items() if v is not None}),
    "masscan": ("nmap_scanner_url", "/jobs/masscan-only", lambda p: {k: v for k, v in {
        "targets": _ensure_target_list(p), "ports": p.get("ports", "0-65535"), "rate": p.get("rate", 1000),
        "timeout_seconds": _coerce_int(p.get("timeout_seconds")),
    }.items() if v is not None}),
    "nmap": ("nmap_scanner_url", "/jobs/masscan-then-nmap", lambda p: _nmap_payload(p)),
    "nmap-tcp": ("nmap_scanner_url", "/jobs/masscan-then-nmap", lambda p: _nmap_payload(p, with_proxy=True)),
    "udp": ("nmap_scanner_url", "/jobs/nmap-udp", lambda p: _udp_payload(p)),
    "web": ("web_scanner_url", "/jobs/web-scan", lambda p: {k: v for k, v in {**{"target_url": _ensure_url(p["target_url"]) if p.get("target_url") else None, "target_urls": p.get("target_urls"), "do_gobuster": p.get("do_gobuster", True), "do_playwright": p.get("do_playwright", True), "do_katana": p.get("do_katana", True), "do_zap": p.get("do_zap", True), "limit": p.get("limit", 25)}, **({} if not _inject_burp_proxy(p).get("http_proxy") else {"http_proxy": p["http_proxy"]})}.items() if v is not None}),
    "pipeline": ("web_scanner_url", "/jobs/pipeline-scan", lambda p: {**{"target_url": _ensure_url(p.get("target_url", "")), "max_paths_to_visit": p.get("max_paths", 50)}, **({} if not _inject_burp_proxy(p).get("http_proxy") else {"http_proxy": p["http_proxy"]})}),
    "nuclei": ("nuclei_url", "/jobs/nuclei-scan", lambda p: {k: v for k, v in {
        "target": p.get("target") if not p.get("targets") else None,
        "targets": _ensure_target_list(p) if p.get("targets") else None,
        "severity": p.get("severity", "medium,high,critical"),
        "tags": p.get("tags") or None,
        "limit": p.get("limit", 25),
        "http_proxy": _inject_burp_proxy(p).get("http_proxy"),
    }.items() if v is not None}),
    "httpx": ("pd_runner_url", "/jobs/httpx", lambda p: {**{"targets": _ensure_target_list(p), "ports": p.get("ports"), "tech_detect": True}, **({} if not _inject_burp_proxy(p).get("http_proxy") else {"http_proxy": p["http_proxy"]})}),
    "naabu": ("pd_runner_url", "/jobs/naabu", lambda p: {"targets": _ensure_target_list(p), "ports": p.get("ports", "1-1000"), "rate": p.get("rate", 1000)}),
    "katana": ("pd_runner_url", "/jobs/katana", lambda p: {k: v for k, v in {
        "targets": _ensure_target_list(p), "depth": p.get("depth", 3), "js_crawl": True,
        "xhr_extraction": p.get("xhr_extraction", True), "form_extraction": p.get("form_extraction", True),
        "known_files": p.get("known_files", "all"),
        "http_proxy": _inject_burp_proxy(p).get("http_proxy"),
        "headless": p.get("headless", False),
    }.items() if v is not None}),
    "subfinder": ("osint_runner_url", "/jobs/subfinder", lambda p: {"domains": _ensure_target_list(p)}),
    "dnsx": ("osint_runner_url", "/jobs/dnsx", lambda p: {"domains": _ensure_target_list(p)}),
    "uncover": ("osint_runner_url", "/jobs/uncover", lambda p: {"query": p.get("query", ""), "engine": p.get("engine", "shodan"), "limit": p.get("limit", 100)}),
    "chaos": ("osint_runner_url", "/jobs/chaos", lambda p: {"domain": p.get("target", "")}),
    "shuffledns": ("osint_runner_url", "/jobs/shuffledns", lambda p: {"domains": _ensure_target_list(p)}),
    "vulnx": ("osint_runner_url", "/jobs/vulnx", lambda p: {k: v for k, v in {"product": p.get("product"), "version": p.get("version"), "banner": p.get("banner"), "keyword": p.get("keyword"), "cve_ids": p.get("cve_ids"), "severity": p.get("severity"), "limit": p.get("limit", 100)}.items() if v is not None}),
    "vulnx-scope": ("osint_runner_url", "/jobs/vulnx-scope", lambda p: {k: v for k, v in {"engagement_id": p.get("engagement_id"), "asset_ids": p.get("asset_ids"), "severity": p.get("severity"), "limit": p.get("limit", 100)}.items() if v is not None}),
    "recon-pipeline": ("osint_runner_url", "/jobs/recon-pipeline", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "skip_phases": p.get("skip_phases"),
            "uncover_engine": p.get("engine", "shodan"),
            "uncover_limit": p.get("limit", 100),
        }.items() if v is not None
    }),
    "crtsh": ("osint_runner_url", "/jobs/crtsh", lambda p: {"domain": p.get("target", "")}),
    "cloud-tenant": ("osint_runner_url", "/jobs/cloud-tenant", lambda p: {k: v for k, v in {
        "domain": p.get("target", "").strip(),
        "engagement_id": p.get("engagement_id"),
        "proxy": p.get("proxy"),
    }.items() if v}),
    "tlsx": ("pd_runner_url", "/jobs/tlsx", lambda p: {"targets": _ensure_target_list(p), "ports": p.get("ports")}),
    "whatweb": ("pd_runner_url", "/jobs/whatweb", lambda p: {k: v for k, v in {"targets": _ensure_target_list(p), "aggression": p.get("aggression", 1), "http_proxy": _inject_burp_proxy(p).get("http_proxy")}.items() if v is not None}),
    "playwright": ("playwright_scanner_url", "/scan", lambda p: {k: v for k, v in {
        "url": _ensure_url(p.get("target_url", "")),
        "capture_dom": p.get("capture_dom", True),
        "capture_screenshots": p.get("capture_screenshots", True),
        "run_security_checks": p.get("run_security_checks", True),
        "use_zap_proxy": p.get("use_zap_proxy", True),
        "zap_spider": p.get("zap_spider"),
        "zap_active_scan": p.get("zap_active_scan"),
        "timeout": p.get("timeout"),
    }.items() if v is not None}),
    "gobuster": ("web_scanner_url", "/jobs/gobuster", lambda p: {k: v for k, v in {"target_url": _ensure_url(p.get("target_url", "")), "wordlist": p.get("wordlist"), "timeout_sec": p.get("timeout_sec"), "http_proxy": _inject_burp_proxy(p).get("http_proxy")}.items() if v is not None}),
    "content-recon": ("web_scanner_url", "/jobs/content-recon", lambda p: {k: v for k, v in {
        "target_url": _ensure_url(_extract_first_url(p)),
        "wordlist": p.get("wordlist"),
        "max_playwright_urls": p.get("max_playwright_urls"),
        "zap_checkpoint": p.get("zap_checkpoint", True),
        "skip_gobuster": not p.get("run_gobuster", False),
        "include_spider": p.get("include_spider", False),
        "spider_depth": int(p["spider_depth"]) if p.get("spider_depth") else 3,
        "extract_pdfs": p.get("extract_pdfs", False),
        "generate_wordlist": p.get("generate_wordlist", False),
        "include_screenshots": p.get("include_screenshots", False),
        "extract_exif": p.get("extract_exif", False),
        "screenshot_all": p.get("screenshot_all", False),
        "proxy": p.get("proxy"),
    }.items() if v is not None}),
    "nikto": ("web_scanner_url", "/jobs/nikto-scan", lambda p: {k: v for k, v in {"target_url": _ensure_url(p.get("target_url", "")), "tuning": p.get("tuning"), "timeout_sec": p.get("timeout_sec")}.items() if v is not None}),
    "brutus": ("brutus_runner_url", "/jobs/brutus", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "protocols": [pr.strip() for pr in p.get("protocols", "ssh").split(",")] if isinstance(p.get("protocols"), str) else p.get("protocols", ["ssh"]),
            "usernames": [u.strip() for u in p.get("usernames", "").split(",") if u.strip()] if p.get("usernames") else None,
            "passwords": [pw.strip() for pw in p.get("passwords", "").split(",") if pw.strip()] if p.get("passwords") else None,
            "wordlist_path": p.get("wordlist_path") or None,
            "username_wordlist_path": p.get("username_wordlist_path") or None,
            "secret_type": p.get("secret_type", "password"),
        }.items() if v is not None
    }),
    # --- New tools ---
    "amass": ("osint_runner_url", "/jobs/amass", lambda p: {"domains": _ensure_target_list(p), "passive": True}),
    "gau": ("osint_runner_url", "/jobs/gau", lambda p: {"domains": _ensure_target_list(p)}),
    "waybackurls": ("osint_runner_url", "/jobs/waybackurls", lambda p: {"domains": _ensure_target_list(p)}),
    "trufflehog": ("osint_runner_url", "/jobs/trufflehog", lambda p: {
        "target": p.get("target", ""), "scan_type": p.get("scan_type", "git"),
    }),
    "censys": ("osint_runner_url", "/jobs/censys", lambda p: {
        k: v for k, v in {
            "query": p.get("query", ""),
            "search_type": p.get("search_type", "hosts"),
            "per_page": int(p["per_page"]) if p.get("per_page") else 100,
            "pages": int(p["pages"]) if p.get("pages") else 1,
        }.items() if v is not None
    }),
    "gowitness": ("osint_runner_url", "/jobs/gowitness", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "timeout": int(p["timeout"]) if p.get("timeout") else 10,
            "resolution": p.get("resolution", "1440x900"),
        }.items() if v is not None
    }),
    "whois": ("osint_runner_url", "/jobs/whois", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "proxy": p.get("proxy"),
        }.items() if v is not None
    }),
    "wafw00f": ("osint_runner_url", "/jobs/wafw00f", lambda p: {
        "targets": _ensure_target_list(p),
    }),
    "subzy": ("osint_runner_url", "/jobs/subzy", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "proxy": p.get("proxy"),
        }.items() if v is not None
    }),
    "golinkfinder": ("osint_runner_url", "/jobs/golinkfinder", lambda p: {
        k: v for k, v in {
            "target": p.get("target_url", "") or p.get("target", ""),
            "proxy": p.get("proxy"),
        }.items() if v is not None
    }),
    "email-enum": ("osint_runner_url", "/jobs/email-enum", lambda p: {
        k: v for k, v in {
            "domain": p.get("target", "") or p.get("domain", ""),
            "dkim_selectors": p.get("dkim_selectors", "").split(",") if p.get("dkim_selectors") else None,
        }.items() if v is not None
    }),
    "dns-enum": ("osint_runner_url", "/jobs/dns-enum", lambda p: {
        k: v for k, v in {
            "domain": p.get("target", "") or p.get("domain", ""),
            "reverse_cidr": p.get("reverse_cidr") or None,
        }.items() if v is not None
    }),
    "service-enum": ("osint_runner_url", "/jobs/service-enum", lambda p: {
        k: v for k, v in {
            "domain": p.get("target", "") or p.get("domain", ""),
            "services": p.get("services", "").split(",") if p.get("services") else ["email", "dns"],
            "reverse_cidr": p.get("reverse_cidr") or None,
            "dkim_selectors": p.get("dkim_selectors", "").split(",") if p.get("dkim_selectors") else None,
        }.items() if v is not None
    }),
    "greyhatwarfare": ("osint_runner_url", "/jobs/greyhatwarfare", lambda p: {
        k: v for k, v in {
            "search_query": p.get("query", ""),
            "search_type": p.get("search_type", "buckets"),
            "limit": int(p["limit"]) if p.get("limit") else 100,
        }.items() if v is not None
    }),
    "ffuf": ("pd_runner_url", "/jobs/ffuf", lambda p: {
        k: v for k, v in {
            "target_url": p.get("target_url", ""),
            "extensions": p.get("extensions") or None,
            "filter_code": p.get("filter_code") or None,
            "match_code": p.get("match_code") or None,
            "rate": int(p["rate"]) if p.get("rate") else 100,
        }.items() if v is not None
    }),
    "netexec": ("kali_listener_url", "/jobs/netexec", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "protocol": p.get("protocol", "smb"),
            "username": p.get("username") or None,
            "password": p.get("password") or None,
            "hash": p.get("hash") or None,
            "domain": p.get("domain") or None,
            "module": p.get("module") or None,
        }.items() if v is not None
    }),
    "impacket": ("kali_listener_url", "/jobs/impacket", lambda p: {
        k: v for k, v in {
            "tool": p.get("impacket_tool", "secretsdump"),
            "target": p.get("target", ""),
            "username": p.get("username") or None,
            "password": p.get("password") or None,
            "hash": p.get("hash") or None,
            "domain": p.get("domain") or None,
        }.items() if v is not None
    }),
    "hashcat": ("kali_listener_url", "/jobs/hashcat", lambda p: {
        k: v for k, v in {
            "hashes": [h.strip() for h in p.get("hashes", "").split("\n") if h.strip()] if isinstance(p.get("hashes"), str) else p.get("hashes", []),
            "hash_type": int(p["hash_type"]) if p.get("hash_type") else 0,
            "wordlist": p.get("wordlist") or None,
        }.items() if v is not None
    }),
    "passive-recon": ("osint_runner_url", "/jobs/passive-recon", lambda p: {
        k: v for k, v in {
            "targets": _ensure_target_list(p),
            "scope_name": p.get("scope_name") or None,
            "include_spider": p.get("include_spider", False),
            "spider_depth": int(p["spider_depth"]) if p.get("spider_depth") else 2,
            "include_cert_chain": p.get("include_cert_chain", True),
            "cert_chain_max_iterations": int(p["cert_chain_max_iterations"]) if p.get("cert_chain_max_iterations") else 2,
            "plan_only": p.get("plan_only", False),
            "proxy": p.get("proxy") or None,
        }.items() if v is not None
    }),
    "subdomain-takeover": ("osint_runner_url", "/jobs/subdomain-takeover", lambda p: {
        k: v for k, v in {
            "subdomains": _ensure_target_list(p),
            "timeout": int(p["timeout"]) if p.get("timeout") else 30,
            "proxy": p.get("proxy") or None,
        }.items() if v is not None
    }),
}


from pydantic import field_validator

class ScanRequest(BaseModel):
    model_config = {"extra": "allow"}  # Pass through scan-specific params (content-recon toggles, etc.)
    target: Optional[str] = None
    targets: Optional[list[str]] = None
    target_url: Optional[str] = None
    target_urls: Optional[list[str]] = None

    @field_validator('targets', mode='before')
    @classmethod
    def coerce_targets(cls, v):
        """Accept a comma-separated string or a list of strings."""
        if isinstance(v, str):
            return [t.strip() for t in v.split(',') if t.strip()]
        return v

    @field_validator('target_urls', mode='before')
    @classmethod
    def coerce_target_urls(cls, v):
        if isinstance(v, str):
            # Split on newlines, commas, or spaces
            import re
            return [t.strip() for t in re.split(r'[\n,]+', v) if t.strip()]
        return v
    ports: Optional[str] = None
    rate: Optional[int] = None
    severity: Optional[str] = None
    depth: Optional[int] = None
    limit: Optional[int] = None
    max_paths: Optional[int] = None
    do_gobuster: Optional[bool] = None
    do_zap: Optional[bool] = None
    tuning: Optional[str] = None
    timeout_sec: Optional[int] = None
    query: Optional[str] = None
    engine: Optional[str] = None
    keyword: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cve_ids: Optional[list[str]] = None
    skip_phases: Optional[list[str]] = None
    aggression: Optional[int] = None
    protocols: Optional[str] = None
    usernames: Optional[str] = None
    passwords: Optional[str] = None
    wordlist_path: Optional[str] = None
    username_wordlist_path: Optional[str] = None
    secret_type: Optional[str] = None
    proxy: Optional[str] = None
    engagement_id: Optional[str] = None
    # ffuf fields
    extensions: Optional[str] = None
    filter_code: Optional[str] = None
    match_code: Optional[str] = None
    # netexec / impacket fields
    protocol: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    module: Optional[str] = None
    impacket_tool: Optional[str] = None
    # hashcat fields
    hashes: Optional[str] = None
    hash_type: Optional[str] = None
    wordlist: Optional[str] = None
    # trufflehog fields
    scan_type: Optional[str] = None
    # censys fields
    search_type: Optional[str] = None
    per_page: Optional[int] = None
    pages: Optional[int] = None
    # gowitness fields
    timeout: Optional[int] = None
    resolution: Optional[str] = None
    # passive-recon fields
    scope_name: Optional[str] = None
    include_spider: Optional[bool] = None
    spider_depth: Optional[int] = None
    include_cert_chain: Optional[bool] = None
    cert_chain_max_iterations: Optional[int] = None
    plan_only: Optional[bool] = None
    # Test mode: run tool but skip ingestion into database
    no_ingest: Optional[bool] = None


# ── Scan Pipelines ──────────────────────────────────────────────────────
# Multi-stage orchestrated scan for 1–500 hosts. Creates a pipeline in
# rag-api, then launches PipelineOrchestrator as a background asyncio task.

_active_pipelines: dict[str, "PipelineOrchestrator"] = {}  # pipeline_id → orchestrator


class PipelineRequest(BaseModel):
    engagement_id: str
    name: str = "default"
    profile: str = "pentest"
    scope_name: Optional[str] = None
    config: Optional[dict] = None  # skip_stages, rate, ports, proxy, max_parallel, etc.


@router.post("/api/pipelines")
async def launch_pipeline(req: PipelineRequest):
    """Create a scan pipeline and start the orchestrator."""
    import asyncio
    from services.pipeline_orchestrator import PipelineOrchestrator
    s = get_settings()

    # 1. Create pipeline record in rag-api
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(
            f"{s.rag_api_url}/pipelines",
            json=req.dict(),
            headers={"x-api-key": s.api_key},
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()
    pipeline_id = data["pipeline_id"]
    targets = data.get("targets") or []

    # 2. Optionally load proxy list from remote_nodes
    proxies: list[str] = []
    config = req.config or {}
    if config.get("use_tunnels"):
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                nr = await c.get(f"{s.tunnel_manager_url}/nodes", headers={"x-api-key": s.api_key})
                if nr.status_code == 200:
                    for node in (nr.json().get("nodes") or []):
                        if node.get("status") == "online" and node.get("proxy_port"):
                            proxies.append(f"socks5://host.docker.internal:{node['proxy_port']}")
        except Exception as e:
            log.warning("Failed to load tunnel proxies: %s", e)

    # 3. Launch orchestrator
    orch = PipelineOrchestrator(
        pipeline_id=pipeline_id,
        engagement_id=req.engagement_id,
        config={**config, "profile": req.profile},
        targets=targets,
        proxies=proxies,
    )
    _active_pipelines[pipeline_id] = orch
    asyncio.create_task(orch.run())

    return {
        "ok": True,
        "pipeline_id": pipeline_id,
        "target_count": len(targets),
        "proxies": len(proxies),
        "profile": req.profile,
    }


@router.get("/api/pipelines")
async def list_pipelines(engagement_id: Optional[str] = None, status: Optional[str] = None):
    s = get_settings()
    params = {}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if status:
        params["status"] = status
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/pipelines", params=params,
                           headers={"x-api-key": s.api_key})
    return safe_json(resp)


@router.get("/api/pipelines/{pipeline_id}")
async def get_pipeline(pipeline_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/pipelines/{pipeline_id}",
                           headers={"x-api-key": s.api_key})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.get("/api/pipelines/{pipeline_id}/jobs")
async def list_pipeline_jobs(pipeline_id: str, stage: Optional[int] = None, host: Optional[str] = None):
    s = get_settings()
    params: dict = {}
    if stage is not None:
        params["stage"] = stage
    if host:
        params["host"] = host
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/pipelines/{pipeline_id}/jobs",
                           params=params, headers={"x-api-key": s.api_key})
    return safe_json(resp)


@router.post("/api/pipelines/{pipeline_id}/stop")
async def stop_pipeline(pipeline_id: str):
    s = get_settings()
    # Stop the orchestrator if running in this process
    orch = _active_pipelines.pop(pipeline_id, None)
    if orch:
        orch.stop()
    # Mark in DB
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/pipelines/{pipeline_id}/stop",
                            headers={"x-api-key": s.api_key})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/scans/cleanup-stale")
async def cleanup_stale_scans(max_age_hours: int = Query(24, ge=1)):
    """Mark stale 'running'/'queued' scans as lost if older than max_age_hours."""
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    cleaned = []
    for jid, info in list(active_jobs.items()):
        if info.get("status") not in ("running", "queued"):
            continue
        created = info.get("created_at", "")
        if not created:
            continue
        try:
            created_dt = datetime.fromisoformat(created)
            if created_dt < cutoff:
                info["status"] = "lost"
                info["completed_at"] = datetime.now(timezone.utc).isoformat()
                _persist(jid)
                cleaned.append(jid)
        except (ValueError, TypeError):
            continue
    return {"ok": True, "cleaned": len(cleaned), "job_ids": cleaned}


@router.get("/api/scans/limits")
async def scan_limits():
    """Return current scan concurrency status, including agent-launched scans."""
    bff_active = _count_active_scans()

    # Also count running scans from agent sessions
    agent_active = 0
    try:
        settings = get_settings()
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                f"{settings.autogen_url}/pentest/sessions",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code == 200:
                sessions = resp.json().get("sessions", [])
                for s in sessions:
                    if s.get("status") in ("active", "running"):
                        sid = s.get("session_id") or str(s.get("id", ""))
                        try:
                            r = await client.get(
                                f"{settings.autogen_url}/pentest/{sid}/scans",
                                headers={"x-api-key": settings.api_key},
                                timeout=3,
                            )
                            if r.status_code == 200:
                                for scan in r.json().get("scans", []):
                                    if scan.get("status") == "running" and scan.get("job_id") not in active_jobs:
                                        agent_active += 1
                        except Exception:
                            pass
    except Exception:
        pass

    total_active = bff_active + agent_active
    return {
        "active": total_active,
        "max": MAX_CONCURRENT_SCANS,
        "available": max(0, MAX_CONCURRENT_SCANS - total_active),
        "pending_queue": len(pending_queue),
    }


@router.put("/api/scans/limits")
async def update_scan_limits(body: dict):
    """Update max concurrent scans (1-50)."""
    new_max = body.get("max")
    if new_max is None or not isinstance(new_max, (int, float)):
        raise HTTPException(400, "Missing or invalid 'max' value")
    set_max_concurrent(int(new_max))
    return {"ok": True, "max": MAX_CONCURRENT_SCANS}


async def _detect_scope_for_target(target: str, api_key: str, rag_api_url: str) -> str | None:
    """Look up which scope a target belongs to via classify endpoint."""
    from urllib.parse import urlparse
    try:
        hostname = urlparse(target).hostname or target.strip()
    except Exception:
        hostname = target.strip()
    hostname = hostname.lower().rstrip(".")
    if not hostname:
        return None
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            resp = await c.get(
                f"{rag_api_url}/scope/classify/{hostname}",
                headers={"x-api-key": api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                suggestion = data.get("suggestion") or {}
                scope = suggestion.get("scope", "")
                if scope and scope != "unknown_scope":
                    return scope
    except Exception:
        pass
    return None


async def _resolve_scope_targets(scope_name: str, api_key: str, rag_api_url: str) -> list[str]:
    """Fetch web-targetable hostnames from a named scope."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.get(
                f"{rag_api_url}/scope",
                params={"name": scope_name, "limit": 2000},
                headers={"x-api-key": api_key},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            targets = []
            for item in data.get("targets", []):
                t = item.get("target", "").strip()
                if not t:
                    continue
                # Only include hostnames/domains (skip bare IPs for content-recon)
                if t.replace(".", "").isdigit():
                    continue  # Skip IPs like 192.168.1.1
                # Ensure https:// prefix for web scans
                if not t.startswith("http"):
                    t = f"https://{t}"
                targets.append(t)
            return targets
    except Exception:
        return []


class NmapResumeReq(BaseModel):
    job_id: Optional[str] = None
    log_base: Optional[str] = None
    timeout_seconds: Optional[int] = None


# IMPORTANT: this must be registered BEFORE `/api/scans/{scan_type}` so FastAPI
# matches the literal "nmap-resume" path before falling into the catch-all.
@router.post("/api/scans/nmap-resume")
async def nmap_resume(req: NmapResumeReq):
    """Trigger nmap --resume against an existing log."""
    s = get_settings()
    service_url = s.nmap_scanner_url
    payload = {k: v for k, v in req.dict().items() if v is not None}
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as c:
        resp = await c.post(
            f"{service_url}/jobs/nmap-resume",
            json=payload,
            headers={"x-api-key": s.api_key},
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()

    # Track every spawned resume job so polling picks them up
    for jid in (data.get("job_ids") or [data.get("job_id")] if data.get("job_id") else []):
        if jid:
            register_job(jid, service_url, "nmap-resume",
                         engagement_id=(active_jobs.get(req.job_id) or {}).get("engagement_id") if req.job_id else None)
    return data


@router.post("/api/scans/{scan_type}")
async def launch_scan(scan_type: str, req: ScanRequest):
    if scan_type not in SCAN_ROUTES:
        raise HTTPException(400, f"Unknown scan type: {scan_type}")

    # Block local scans if the safety switch is on
    _check_proxy_required(req.proxy, scan_type)

    # Multi-URL batching for content-recon: launch one job per URL (up to limit)
    if scan_type == "content-recon":
        raw = req.model_dump(exclude_none=True)
        all_urls = _extract_all_urls(raw)
        s = get_settings()

        # If a scope is set but no URLs provided, pull targets from scope
        if not all_urls and req.scope_name:
            scope_targets = await _resolve_scope_targets(req.scope_name, s.api_key, s.rag_api_url)
            if scope_targets:
                all_urls = scope_targets
                log.info("Resolved %d targets from scope '%s' for content-recon", len(all_urls), req.scope_name)

        # Auto-detect scope for tagging (doesn't expand targets — user must select scope to scan all)
        if not req.scope_name and all_urls:
            detected = await _detect_scope_for_target(all_urls[0], s.api_key, s.rag_api_url)
            if detected:
                req.scope_name = detected
        if len(all_urls) > 1:
            attr, path, transform = SCAN_ROUTES[scan_type]
            s = get_settings()
            service_url = getattr(s, attr)
            job_ids = []
            queued_count = 0
            # Build a reusable payload template (without target_url)
            template_raw = dict(raw)
            template_raw.pop("target_urls", None)
            template_raw.pop("target_url", None)
            payload_template = {k: v for k, v in transform(template_raw).items() if v is not None}
            if req.proxy:
                payload_template["proxy"] = req.proxy

            for url in all_urls:
                # Check concurrency limit per job
                if _count_active_scans() >= MAX_CONCURRENT_SCANS:
                    # Queue for later dispatch by poll loop
                    pending_queue.append({
                        "url": _ensure_url(url),
                        "service_url": service_url,
                        "path": path,
                        "payload_template": payload_template,
                        "proxy": req.proxy,
                        "engagement_id": req.engagement_id,
                        "scope_name": req.scope_name,
                        "scan_type": scan_type,
                        "api_key": s.api_key,
                    })
                    queued_count += 1
                    continue
                single = dict(raw)
                single["target_url"] = _ensure_url(url)
                single.pop("target_urls", None)
                payload = {k: v for k, v in transform(single).items() if v is not None}
                if req.proxy:
                    payload["proxy"] = req.proxy
                try:
                    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as c:
                        resp = await c.post(f"{service_url}{path}", json=payload,
                                            headers={"x-api-key": s.api_key})
                        if resp.status_code < 400:
                            data = resp.json()
                            jid = data.get("job_id")
                            if jid:
                                job_ids.append(jid)
                                batch_scope = req.scope_name
                                if not batch_scope:
                                    batch_scope = await _detect_scope_for_target(url, s.api_key, s.rag_api_url)
                                register_job(jid, service_url, scan_type, proxy=req.proxy,
                                             engagement_id=req.engagement_id,
                                             scope_name=batch_scope, target=url)
                except Exception:
                    pass
            return {"ok": True, "batch": True, "job_ids": job_ids,
                    "total_urls": len(all_urls), "jobs_launched": len(job_ids),
                    "queued_for_later": queued_count, "pending_queue_size": len(pending_queue),
                    "max_concurrent": MAX_CONCURRENT_SCANS,
                    "type": scan_type, "status": "queued"}

    # Resolve targets from scope if none provided explicitly
    if req.scope_name and not req.target and not req.targets and not req.target_url:
        s = get_settings()
        scope_targets = await _resolve_scope_targets(req.scope_name, s.api_key, s.rag_api_url)
        if scope_targets:
            # For web scans use URLs, for network scans strip scheme to get hostnames
            web_types = {"web", "gobuster", "nikto", "katana", "playwright", "wafw00f", "pipeline"}
            if scan_type in web_types:
                req.target_url = scope_targets[0] if len(scope_targets) == 1 else None
                if len(scope_targets) > 1:
                    req.targets = scope_targets
            else:
                # Strip https:// for nmap/nuclei/etc
                from urllib.parse import urlparse
                hosts = []
                for t in scope_targets:
                    try:
                        h = urlparse(t).hostname or t
                    except Exception:
                        h = t
                    hosts.append(h)
                req.targets = hosts
            log.info("Resolved %d targets from scope '%s' for %s", len(scope_targets), req.scope_name, scan_type)

    # Concurrency check for single launches
    _check_scan_limit()

    attr, path, transform = SCAN_ROUTES[scan_type]
    s = get_settings()
    service_url = getattr(s, attr)
    payload = {k: v for k, v in transform(req.model_dump(exclude_none=True)).items() if v is not None}

    # Inject SOCKS proxy into payload if provided (e.g. SSH tunnel)
    if req.proxy:
        payload["proxy"] = req.proxy

    # Test mode: run tool but skip DB ingestion
    if req.no_ingest:
        payload["no_ingest"] = True

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as c:
        resp = await c.post(
            f"{service_url}{path}",
            json=payload,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        data = resp.json()

    job_id = data.get("job_id") or data.get("id") or data.get("scan_id")
    scan_target = req.target_url or req.target or (req.targets[0] if req.targets else None) or "unknown"

    # Auto-detect scope from target if not explicitly set
    resolved_scope = req.scope_name
    if not resolved_scope and scan_target and scan_target != "unknown":
        resolved_scope = await _detect_scope_for_target(scan_target, s.api_key, s.rag_api_url)

    if job_id and not req.no_ingest:
        register_job(job_id, service_url, scan_type, proxy=req.proxy,
                     engagement_id=req.engagement_id,
                     scope_name=resolved_scope,
                     target=scan_target)

    # Log an informational finding so this scan execution appears in reports (skip for test mode)
    if not req.no_ingest:
        try:
            target = scan_target
            evidence_parts = [f"job_id={job_id}"]
            if req.ports:
                evidence_parts.append(f"ports={req.ports}")
            if req.severity:
                evidence_parts.append(f"severity={req.severity}")
            async with httpx.AsyncClient(verify=False, timeout=5) as note_client:
                await note_client.post(
                    f"{s.rag_api_url}/findings/note",
                    json={
                        "source": scan_type,
                        "url": target,
                        "name": f"{scan_type} scan launched",
                        "severity": "info",
                        "evidence": ", ".join(evidence_parts),
                    },
                    headers={"x-api-key": s.api_key},
                )
        except Exception:
            pass  # never block scan launch

    return {"job_id": job_id, "type": scan_type, "status": "queued", "detail": data, "no_ingest": bool(req.no_ingest)}


@router.get("/api/scans")
async def list_scans(engagement_id: Optional[str] = None):
    """Return all tracked jobs, merged with autogen agent scans and recent audit log entries.

    When ``engagement_id`` is provided, only scans belonging to that engagement
    are returned -- legacy / unscoped scans (engagement_id IS NULL) are hidden
    to prevent cross-engagement leakage.  This is the BFF-side enforcement of
    the engagement-isolation guarantee added in Option B / Phase 6.

    Resolution rules per source:
      * active_jobs: filter by info.get("engagement_id") == engagement_id
      * autogen sessions: passed through with the same engagement_id query
      * audit.jsonl: filter by entry.get("engagement_id") == engagement_id
        for entries that have it; for legacy entries without engagement_id,
        join through the rag-api's jobs.engagement_id by job_id (resolved
        lazily on demand).
    """
    from datetime import datetime, timezone, timedelta

    # Filter active_jobs by engagement_id if requested.  active_jobs entries
    # carry an "engagement_id" key when the launch site captured one
    # (Phase 4 / rag-api middleware).  Old / legacy entries without the key
    # are treated as unscoped and hidden when an engagement is active.
    if engagement_id:
        jobs = [
            {"job_id": jid, **info}
            for jid, info in active_jobs.items()
            if info.get("engagement_id") == engagement_id
        ]
        tracked_ids = {jid for jid, info in active_jobs.items()
                       if info.get("engagement_id") == engagement_id}
    else:
        jobs = [{"job_id": jid, **info} for jid, info in active_jobs.items()]
        tracked_ids = set(active_jobs.keys())

    # Merge in scans from active autogen agent sessions
    try:
        settings = get_settings()
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                f"{settings.autogen_url}/pentest/sessions",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code == 200:
                sessions = resp.json().get("sessions", [])
                active_sessions = [s for s in sessions if s.get("status") in ("active", "running")]
                # Fetch scan details for each active session in parallel
                import asyncio
                async def _get_session_scans(session):
                    sid = session.get("session_id") or str(session.get("id", ""))
                    try:
                        r = await client.get(
                            f"{settings.autogen_url}/pentest/{sid}/scans",
                            headers={"x-api-key": settings.api_key},
                            timeout=5,
                        )
                        if r.status_code == 200:
                            return sid, session, r.json().get("scans", [])
                    except Exception as e:
                        log.debug(f"Failed to fetch scans for agent session {sid}: {e}")
                    return sid, session, []

                results = await asyncio.gather(*[_get_session_scans(s) for s in active_sessions])
                for sid, session, scans in results:
                    for scan in scans:
                        jid = scan.get("job_id", "")
                        if jid and jid not in tracked_ids:
                            tracked_ids.add(jid)
                            jobs.append({
                                "job_id": jid,
                                "type": scan.get("type", "unknown"),
                                "status": scan.get("status", "running"),
                                "created_at": scan.get("started_at", ""),
                                "completed_at": scan.get("completed_at"),
                                "duration_s": scan.get("duration_seconds"),
                                "target": session.get("target_description", ""),
                                "targets": [session.get("target_description", "")],
                                "service_url": f"via agent session {session.get('session_name', sid[:8])}",
                                "execution_mode": "agent",
                                "agent_session_id": sid,
                                "agent_session_name": session.get("session_name", ""),
                                "parameters": scan.get("params"),
                            })
    except Exception as e:
        log.warning(f"Failed to fetch autogen agent scans: {e}")

    # Merge in scans from audit log that aren't tracked by BFF or autogen (last 48h only)
    audit_path = pathlib.Path("/scan_audit/audit.jsonl")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    if audit_path.exists():
        try:
            audit_jobs: dict = {}
            for line in audit_path.read_text().splitlines()[-500:]:
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                jid = entry.get("job_id")
                ts = entry.get("timestamp", "")
                if not jid or jid in tracked_ids:
                    continue
                # Skip entries older than 48h
                if ts and ts < cutoff:
                    continue
                # Cross-engagement isolation: when filtering by engagement_id,
                # only include audit entries that explicitly carry the same
                # engagement_id.  Entries written before Phase 2 (no
                # engagement_id field) are treated as legacy / unscoped and
                # hidden when an engagement is active.  Stricter than the
                # job_id-join approach but safer: a NULL audit entry whose
                # job_id maps to a different engagement is correctly excluded.
                if engagement_id:
                    entry_eid = entry.get("engagement_id")
                    if entry_eid != engagement_id:
                        continue
                event = entry.get("event", "")
                if jid not in audit_jobs:
                    # Extract proxy from audit entry or from command string
                    proxy_val = entry.get("proxy")
                    if not proxy_val:
                        cmd = entry.get("command", "")
                        if "-proxy " in cmd:
                            proxy_val = cmd.split("-proxy ")[1].split()[0]
                        elif "--proxy " in cmd:
                            proxy_val = cmd.split("--proxy ")[1].split()[0]
                        elif "--chrome-proxy " in cmd:
                            proxy_val = cmd.split("--chrome-proxy ")[1].split()[0]
                    # Extract target for display
                    target_val = entry.get("target_url") or entry.get("target")
                    if not target_val and entry.get("targets"):
                        t = entry["targets"]
                        target_val = t[0] if isinstance(t, list) and t else str(t) if t else None
                    audit_jobs[jid] = {
                        "job_id": jid,
                        "type": entry.get("scan_type", "unknown"),
                        "status": "running",
                        "created_at": ts,
                        "service_url": f"via {entry.get('source', 'audit')}",
                        "targets": entry.get("targets"),
                        "target": target_val,
                        "execution_mode": entry.get("execution_mode", "unknown"),
                        "node_id": entry.get("node_id"),
                        "source_ip": entry.get("external_ip"),
                        "parameters": entry.get("parameters"),
                        "proxy": proxy_val,
                    }
                if "completed" in event or "finished" in event:
                    # Check for partial failures or timeouts in completed scans
                    error_msg = entry.get("error", "")
                    result_data = entry.get("result", {}) if isinstance(entry.get("result"), dict) else {}

                    # Detect timeout conditions
                    if ("timeout" in error_msg.lower() or
                        "timed out" in error_msg.lower() or
                        "timeout" in str(result_data).lower()):
                        audit_jobs[jid]["status"] = "failed"
                    # Detect partial completions (some phases failed)
                    elif ("partial" in error_msg.lower() or
                          "some targets failed" in error_msg.lower() or
                          (result_data.get("errors") and len(result_data.get("errors", [])) > 0)):
                        audit_jobs[jid]["status"] = "partial"
                    # Check for zero findings in scans that should find something
                    elif (entry.get("findings_count") == 0 and
                          entry.get("scan_type") in ["nuclei", "nmap", "masscan", "full"]):
                        # Zero findings might indicate a problem, mark as partial
                        audit_jobs[jid]["status"] = "partial"
                    else:
                        audit_jobs[jid]["status"] = "completed"

                    audit_jobs[jid]["completed_at"] = ts
                    if entry.get("duration_s"):
                        audit_jobs[jid]["duration_s"] = entry["duration_s"]
                elif "failed" in event or "error" in event:
                    audit_jobs[jid]["status"] = "failed"
                    audit_jobs[jid]["completed_at"] = ts
                    if entry.get("error"):
                        audit_jobs[jid]["error"] = entry["error"]
                elif "stopped" in event or "cancelled" in event:
                    audit_jobs[jid]["status"] = "stopped"
                    audit_jobs[jid]["completed_at"] = ts
            jobs.extend(audit_jobs.values())
        except Exception:
            pass

    return {"jobs": jobs}


@router.delete("/api/scans/{job_id}")
async def delete_scan(job_id: str):
    """Delete a single scan from history."""
    if job_id not in active_jobs:
        raise HTTPException(404, "Scan not found")
    del active_jobs[job_id]
    persist_file = pathlib.Path("/scan_results/.bff_jobs") / f"{job_id}.json"
    if persist_file.exists():
        persist_file.unlink()
    return {"ok": True, "deleted": job_id}


@router.delete("/api/scans")
async def clear_scan_history(engagement_id: Optional[str] = None):
    """Delete all completed/failed/stopped/lost scans from BFF-tracked history.

    When ``engagement_id`` is provided, only scans tagged to that engagement
    are removed -- preventing the case where one engagement's "Clear History"
    accidentally wipes another engagement's tracked scans.  When omitted
    (admin / unscoped view), clears all completed/failed/stopped/lost scans.

    Note: this clears BFF-tracked active_jobs and its on-disk persistence
    only.  The rag-api jobs table and scan_audit/audit.jsonl are unchanged
    (audit log is immutable by design; jobs table is cleaned via the
    Maintenance page's "Jobs & Tasks" cleanup action).  GET /api/scans now
    also filters audit-derived rows by engagement_id, so cleared scans
    don't reappear from the audit-merge path.
    """
    if engagement_id:
        to_delete = [
            jid for jid, info in active_jobs.items()
            if info.get("status") in ("completed", "failed", "stopped", "lost")
            and info.get("engagement_id") == engagement_id
        ]
    else:
        to_delete = [
            jid for jid, info in active_jobs.items()
            if info.get("status") in ("completed", "failed", "stopped", "lost")
        ]
    persist_dir = pathlib.Path("/scan_results/.bff_jobs")
    for jid in to_delete:
        del active_jobs[jid]
        fp = persist_dir / f"{jid}.json"
        if fp.exists():
            fp.unlink()
    return {"ok": True, "deleted_count": len(to_delete)}




@router.get("/api/scans/{job_id}")
async def get_scan(job_id: str):
    s = get_settings()
    info = active_jobs.get(job_id)

    # AI check jobs are BFF-only — return local data directly
    if info and info.get("_bulk_check"):
        return {
            "job_id": job_id,
            "type": info.get("type", "ai-software-check"),
            "status": info.get("status", "unknown"),
            "target": info.get("target", ""),
            "created_at": info.get("created_at"),
            "completed_at": info.get("completed_at"),
            "progress": (info.get("last_data") or {}).get("progress", {}),
            "summary": (info.get("last_data") or {}).get("summary", ""),
        }

    if info:
        service_url = info["service_url"]
    else:
        # Try each scanner service
        service_url = None
        for attr in ["nmap_scanner_url", "web_scanner_url", "nuclei_url", "pd_runner_url", "osint_runner_url", "brutus_runner_url", "kali_listener_url"]:
            try:
                url = getattr(s, attr)
                async with httpx.AsyncClient(verify=False, timeout=5) as c:
                    resp = await c.get(f"{url}/jobs/{job_id}", headers={"x-api-key": s.api_key})
                    if resp.status_code == 200:
                        return safe_json(resp)
            except Exception:
                continue
        raise HTTPException(404, "Job not found")

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{service_url}/jobs/{job_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code == 200:
            merged = resp.json()
            # Merge BFF-tracked metadata into the scanner response
            if info:
                if info.get("proxy"):
                    merged["proxy"] = info["proxy"]
                if info.get("engagement_id"):
                    merged["engagement_id"] = info["engagement_id"]
                if info.get("scope_name"):
                    merged["scope_name"] = info["scope_name"]
                if info.get("target"):
                    merged.setdefault("target", info["target"])
                if info.get("type"):
                    merged.setdefault("type", info["type"])
                if info.get("created_at"):
                    merged.setdefault("created_at", info["created_at"])
            return merged
        raise HTTPException(resp.status_code, resp.text)


@router.post("/api/scans/{job_id}/stop")
async def stop_scan(job_id: str):
    s = get_settings()
    info = active_jobs.get(job_id)
    if not info:
        raise HTTPException(404, "Job not tracked")
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{info['service_url']}/jobs/{job_id}/stop",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code < 400:
            info["status"] = "stopped"
            data = resp.json()
            return {"ok": True, "job_id": job_id, "resumable": data.get("resumable", False)}
        raise HTTPException(resp.status_code, resp.text)


@router.post("/api/scans/{job_id}/resume")
async def resume_scan(job_id: str):
    s = get_settings()
    info = active_jobs.get(job_id)
    if not info:
        raise HTTPException(404, "Job not tracked")
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(
            f"{info['service_url']}/jobs/{job_id}/resume",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        data = resp.json()

    # Register the new resumed job
    new_job_id = data.get("job_id")
    if new_job_id:
        register_job(new_job_id, info["service_url"], "masscan-resume")

    return data


@router.get("/api/scans/{job_id}/nmap-resume-info")
async def nmap_resume_info(job_id: str):
    """Check whether an nmap job is resumable."""
    s = get_settings()
    info = active_jobs.get(job_id)
    if not info:
        raise HTTPException(404, "Job not tracked")
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(
            f"{info['service_url']}/jobs/{job_id}/nmap-resume-info",
            headers={"x-api-key": s.api_key},
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


# ── Cloud tool file-upload import proxies ──

CLOUD_IMPORT_ROUTES = {
    "prowler": "prowler",
    "scoutsuite": "scoutsuite",
    "pacu": "pacu",
    "cloudfox": "cloudfox",
    "azurehound": "azurehound",
    "microburst": "microburst",
}


@router.post("/api/import/{tool}")
async def cloud_import(
    tool: str,
    file: UploadFile = File(...),
    engagement_id: Optional[str] = Form(None),
):
    """Proxy file upload to rag-api /ingest/{tool} for cloud tool imports."""
    if tool not in CLOUD_IMPORT_ROUTES:
        raise HTTPException(400, f"Unknown import tool: {tool}")

    ingest_path = CLOUD_IMPORT_ROUTES[tool]
    s = get_settings()
    content = await file.read()
    data = {"engagement_id": engagement_id} if engagement_id else None
    async with httpx.AsyncClient(verify=False, timeout=300) as c:
        resp = await c.post(
            f"{s.rag_api_url}/ingest/{ingest_path}",
            files={"file": (file.filename, content, file.content_type or "application/octet-stream")},
            data=data,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            # Pass through structured upstream errors so the frontend gets a
            # nice {detail: {message: ...}} object instead of a stringified
            # JSON inside detail. Falls back to raw text for non-JSON errors.
            try:
                err_body = resp.json()
                err_detail = err_body.get("detail", err_body)
            except Exception:
                err_detail = resp.text
            raise HTTPException(resp.status_code, err_detail)

        # Register the ingest job so it shows up in Scan Monitor. The polling
        # layer will then GET {rag_api_url}/jobs/{job_id} on every tick to
        # surface progress + terminal state.
        body = resp.json() if resp.status_code < 400 else {}
        job_id = body.get("job_id")
        if job_id:
            try:
                from polling import register_job
                register_job(
                    job_id=job_id,
                    service_url=s.rag_api_url,
                    scan_type=f"{tool}-import",
                    engagement_id=engagement_id,
                    target=file.filename,
                )
            except Exception as e:
                # Non-fatal — the import still runs in rag-api regardless
                import logging
                logging.getLogger("bff").warning("register_job for %s import failed: %s", tool, e)

        return safe_json(resp)


@router.get("/api/import/status/{job_id}")
async def cloud_import_status(job_id: str):
    """Poll the status of an async cloud-import job (e.g. MicroBurst).
    Proxies rag-api GET /jobs/{job_id}; returns status, progress, result, error."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/jobs/{job_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
