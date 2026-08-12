"""
url_fetch.py — fetch a published guide and reduce it to readable markdown.

Feeds the walkthrough converter from a URL instead of pasted text.

SECURITY: this is server-side fetching inside a security tool, i.e. an SSRF
primitive if built naively. Anyone able to reach the API could otherwise make
this container pull cloud-metadata credentials or probe internal services.
`common/validation.py::validate_scan_target` has the private-range rules but
`common/` is not mounted into this container, so they are mirrored below — and
mirroring alone is NOT sufficient, because that helper validates a *string*.
A string check is fine for a scan target the operator typed; it is not fine
here. Four defences, all required:

  1. Scheme allowlist — http/https only (blocks file://, gopher://, ...).
  2. Resolve the hostname and validate EVERY returned address before
     connecting. `evil.com` resolving to 127.0.0.1 passes a string check.
  3. Re-validate every redirect hop. A 302 into 169.254.169.254 is the other
     standard bypass, so redirects are followed manually.
  4. Bound the response — streamed size cap, timeouts, content-type check.

`allow_internal=True` relaxes only defence 2, and is logged loudly.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("url_fetch")

ALLOWED_SCHEMES = ("http", "https")
# Raw HTML, not extracted text. 2MB sounded generous for "an article" but real
# documentation sites (Rapid7's included) routinely ship more than that once
# inlined JS bundles are counted, so it rejected legitimate pages. 10MB still
# bounds memory and, combined with the content-type allowlist, keeps this from
# being used to pull large binaries.
MAX_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
MAX_CRAWL_PAGES = 20                  # hard cap regardless of what's requested
USER_AGENT = "rag-scan-stack knowledge importer"

# Content types worth parsing. Anything else (PDF, images, archives) is refused
# rather than streamed into memory and handed to an HTML parser.
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "text/markdown")

_LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class UrlFetchError(ValueError):
    """Raised when a URL is refused or cannot be fetched."""


# ── Validation ──────────────────────────────────────────────────────────────

def _check_ip(ip_str: str, allow_internal: bool) -> None:
    """Refuse addresses that shouldn't be reachable from a fetch endpoint."""
    if allow_internal:
        return
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise UrlFetchError(f"Could not parse resolved address {ip_str!r}")

    # Cloud metadata first — it is link-local, but the specific message is what
    # tells an operator what actually got blocked.
    if ip_str.startswith("169.254.169.254"):
        raise UrlFetchError(
            "Refusing to fetch the cloud metadata endpoint (169.254.169.254). "
            "Pass allow_internal if this is a deliberate internal source."
        )
    # Ordered most-specific first purely for message quality — every branch
    # refuses. `is_private` is deliberately last because it is the broadest:
    # Python counts 0.0.0.0/8 and loopback as private too, so checking it first
    # would label everything "private" and make diagnostics worse.
    if ip.is_loopback:
        raise UrlFetchError(f"Refusing to fetch a loopback address ({ip_str}).")
    if ip.is_link_local:
        raise UrlFetchError(f"Refusing to fetch a link-local address ({ip_str}).")
    if ip.is_unspecified:
        raise UrlFetchError(f"Refusing to fetch the unspecified/reserved address ({ip_str}).")
    if ip.is_multicast or ip.is_reserved:
        raise UrlFetchError(f"Refusing to fetch a reserved address ({ip_str}).")
    if ip.is_private:
        raise UrlFetchError(
            f"Refusing to fetch a private address ({ip_str}). "
            "Pass allow_internal if this is a deliberate internal source."
        )


def resolve_and_validate(url: str, allow_internal: bool = False) -> Tuple[str, List[str]]:
    """Validate a URL and every address its host resolves to.

    Returns ``(hostname, [resolved_ips])``. Raises UrlFetchError on refusal.

    Resolution happens here rather than being left to the HTTP client so a
    hostname that points at an internal address is rejected before any
    connection is opened.
    """
    if not url or not isinstance(url, str):
        raise UrlFetchError("url must be a non-empty string")
    url = url.strip()
    if len(url) > 2048:
        raise UrlFetchError("url too long")

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlFetchError(
            f"Refusing scheme {parsed.scheme or '(none)'!r}: only http and https are allowed."
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise UrlFetchError("url has no host")

    if not allow_internal and host in _LOCALHOST_NAMES:
        raise UrlFetchError(f"Refusing to fetch {host!r}.")

    # A literal IP in the URL still goes through _check_ip via the resolve
    # below, since getaddrinfo returns it unchanged.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UrlFetchError(f"Could not resolve {host!r}: {e}")

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UrlFetchError(f"{host!r} resolved to no addresses")
    for ip in ips:
        _check_ip(ip, allow_internal)      # every address, not just the first
    return host, ips


# ── Fetch ───────────────────────────────────────────────────────────────────

def fetch_url(url: str, allow_internal: bool = False,
              proxy: Optional[str] = None) -> Dict:
    """Fetch one URL with redirects followed manually and every hop validated.

    Returns ``{url, final_url, status, content_type, html}``.
    """
    if allow_internal:
        logger.warning("[url_fetch] allow_internal=True for %s — internal address checks relaxed", url)

    proxies = {"http": proxy, "https": proxy} if proxy else None
    current = url
    seen = []

    for hop in range(MAX_REDIRECTS + 1):
        resolve_and_validate(current, allow_internal)   # re-validated per hop
        seen.append(current)
        try:
            resp = requests.get(
                current,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,text/plain"},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                allow_redirects=False,        # followed manually so each hop is checked
                stream=True,                  # so the size cap can abort mid-transfer
                proxies=proxies,
                verify=True,
            )
        except requests.RequestException as e:
            raise UrlFetchError(f"Fetch failed for {current}: {e}")

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            resp.close()
            if not loc:
                raise UrlFetchError(f"{current} returned {resp.status_code} with no Location")
            current = urljoin(current, loc)   # relative redirects are legal
            if hop == MAX_REDIRECTS:
                raise UrlFetchError(f"Too many redirects (>{MAX_REDIRECTS}) starting at {url}")
            continue

        if resp.status_code >= 400:
            resp.close()
            raise UrlFetchError(f"{current} returned HTTP {resp.status_code}")

        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype and not any(ctype.startswith(a) for a in ALLOWED_CONTENT_TYPES):
            resp.close()
            raise UrlFetchError(
                f"{current} is {ctype!r}; only HTML, plain text and markdown are supported."
            )

        # Enforce the cap while streaming — Content-Length can be absent or lie.
        chunks, total = [], 0
        try:
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise UrlFetchError(
                        f"{current} exceeds the {MAX_BYTES // (1024 * 1024)}MB limit."
                    )
                chunks.append(chunk)
        finally:
            resp.close()

        body = b"".join(chunks)
        encoding = resp.encoding or "utf-8"
        try:
            html = body.decode(encoding, errors="replace")
        except LookupError:
            html = body.decode("utf-8", errors="replace")

        return {"url": url, "final_url": current, "status": resp.status_code,
                "content_type": ctype, "html": html, "redirects": seen[:-1]}

    raise UrlFetchError(f"Too many redirects starting at {url}")   # pragma: no cover


# ── Extraction ──────────────────────────────────────────────────────────────

_STRIP_TAGS = ("script", "style", "nav", "header", "footer", "aside", "noscript",
               "form", "iframe", "svg", "button")


def extract_markdown(html: str, source_url: str = "") -> Dict:
    """Reduce an HTML page to markdown-ish text.

    Headings become `#` levels and code blocks stay fenced: the heading
    structure is what `_chunk_markdown` in exploits_rag.py splits on, and the
    command syntax is the most valuable part of a technical guide.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:  # pragma: no cover
        raise UrlFetchError(
            "beautifulsoup4 is not installed in this container — rebuild scan-recommender."
        )

    soup = BeautifulSoup(html, "html.parser")

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    h1 = soup.find("h1")
    if h1 and h1.get_text(strip=True):
        title = h1.get_text(strip=True)

    for tag in soup(list(_STRIP_TAGS)):
        tag.decompose()

    # Prefer a semantic container; fall back to whichever block has the most text.
    root = soup.find("main") or soup.find("article")
    if root is None:
        candidates = soup.find_all(["div", "section", "body"])
        root = max(candidates, key=lambda t: len(t.get_text(" ", strip=True)), default=soup) \
            if candidates else soup

    lines: List[str] = []
    for el in root.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "pre", "li",
                             "td", "th", "blockquote"]):
        text = el.get_text("\n" if el.name == "pre" else " ", strip=True)
        if not text:
            continue
        name = el.name
        if name.startswith("h") and len(name) == 2 and name[1].isdigit():
            lines.append("")
            lines.append("#" * min(int(name[1]), 6) + " " + text)
            lines.append("")
        elif name == "pre":
            lines.append("")
            lines.append("```")
            lines.append(text)
            lines.append("```")
            lines.append("")
        elif name == "li":
            lines.append(f"- {text}")
        elif name == "blockquote":
            lines.append(f"> {text}")
        else:
            lines.append(text)

    # Collapse the runs of blank lines the block-by-block walk produces.
    md = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()

    links: List[str] = []
    for a in root.find_all("a", href=True):
        href = a["href"].strip()
        if href and not href.startswith(("#", "javascript:", "mailto:")):
            links.append(urljoin(source_url, href) if source_url else href)

    return {"title": title, "markdown": md, "links": links, "chars": len(md)}


# ── Crawl ───────────────────────────────────────────────────────────────────

def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def fetch_guide(url: str, depth: int = 0, max_pages: int = 1,
                allow_internal: bool = False, proxy: Optional[str] = None) -> Dict:
    """Fetch one page, or that page plus same-origin links when depth >= 1.

    Returns ``{pages: [{url, title, markdown, chars}], markdown, errors}`` where
    `markdown` is every page concatenated under its own heading.
    """
    max_pages = max(1, min(int(max_pages or 1), MAX_CRAWL_PAGES))
    depth = max(0, min(int(depth or 0), 1))     # depth>1 is not supported by design

    pages, errors, seen = [], [], set()

    first = fetch_url(url, allow_internal=allow_internal, proxy=proxy)
    doc = extract_markdown(first["html"], first["final_url"])
    seen.add(first["final_url"].rstrip("/"))
    pages.append({"url": first["final_url"], "title": doc["title"],
                  "markdown": doc["markdown"], "chars": doc["chars"]})

    if depth >= 1 and max_pages > 1:
        for link in doc["links"]:
            if len(pages) >= max_pages:
                break
            norm = link.split("#")[0].rstrip("/")
            if not norm or norm in seen:
                continue
            if not _same_origin(first["final_url"], link):
                continue          # never wander off the origin the operator named
            seen.add(norm)
            try:
                sub = fetch_url(link, allow_internal=allow_internal, proxy=proxy)
                sdoc = extract_markdown(sub["html"], sub["final_url"])
                if sdoc["chars"] < 200:
                    continue      # nav stubs and redirects to landing pages
                pages.append({"url": sub["final_url"], "title": sdoc["title"],
                              "markdown": sdoc["markdown"], "chars": sdoc["chars"]})
            except UrlFetchError as e:
                # One bad sub-page shouldn't sink the whole import.
                errors.append({"url": link, "error": str(e)})

    parts = []
    for p in pages:
        heading = p["title"] or p["url"]
        parts.append(f"# {heading}\n\nSource: {p['url']}\n\n{p['markdown']}")
    return {"pages": pages, "markdown": "\n\n---\n\n".join(parts), "errors": errors}


def slugify(url: str, title: str = "") -> str:
    """Filename stem for the seed/playbook files."""
    base = (title or urlparse(url).path.strip("/").split("/")[-1]
            or urlparse(url).hostname or "guide")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", base).strip("-").lower()
    return (slug or "guide")[:60]
