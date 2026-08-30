"""URL fetcher tests — SSRF defences and HTML extraction.

The fetcher adds server-side URL fetching to a security tool, which is an SSRF
primitive if it goes wrong. These tests exist mainly to prove the four defences
hold:

  1. scheme allowlist
  2. DNS resolution validated (a public NAME pointing at a private ADDRESS)
  3. every redirect hop re-validated
  4. response bounded

Defences 2 and 3 are the ones a string-only check misses, so they get the most
coverage. No network: DNS is mocked, HTTP is stubbed.
"""
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scan_recommender"))

pytest.importorskip("requests")
import url_fetch as uf  # noqa: E402


def _addrinfo(*ips):
    """socket.getaddrinfo shape: (family, type, proto, canonname, sockaddr)."""
    return [(2, 1, 6, "", (ip, 80)) for ip in ips]


def _resolves_to(*ips):
    return patch.object(uf.socket, "getaddrinfo", return_value=_addrinfo(*ips))


# ── Defence 1: scheme allowlist ─────────────────────────────────────────────
class TestScheme:
    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "gopher://evil.test/_",
        "ftp://files.test/x",
        "data:text/html,<h1>x",
        "dict://127.0.0.1:11211/",
    ])
    def test_non_http_schemes_refused(self, url):
        with pytest.raises(uf.UrlFetchError, match="scheme"):
            uf.resolve_and_validate(url)

    def test_http_and_https_allowed(self):
        with _resolves_to("93.184.216.34"):
            assert uf.resolve_and_validate("http://example.test/a")[0] == "example.test"
            assert uf.resolve_and_validate("https://example.test/a")[0] == "example.test"

    def test_missing_host_refused(self):
        with pytest.raises(uf.UrlFetchError):
            uf.resolve_and_validate("http:///nohost")


# ── Defence 2: resolved addresses, not just the string ──────────────────────
class TestResolvedAddressValidation:
    @pytest.mark.parametrize("ip,expect", [
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "metadata"),
        ("169.254.1.1", "link-local"),
        ("10.0.0.5", "private"),
        ("192.168.1.10", "private"),
        ("172.16.4.9", "private"),
        ("0.0.0.0", "reserved"),
    ])
    def test_literal_ip_urls_refused(self, ip, expect):
        with _resolves_to(ip):
            with pytest.raises(uf.UrlFetchError) as e:
                uf.resolve_and_validate(f"http://{ip}/x")
        assert expect.lower() in str(e.value).lower()

    def test_public_hostname_resolving_to_loopback_is_refused(self):
        """The bypass a string-only check misses."""
        with _resolves_to("127.0.0.1"):
            with pytest.raises(uf.UrlFetchError, match="loopback"):
                uf.resolve_and_validate("http://totally-legit.test/x")

    def test_public_hostname_resolving_to_metadata_is_refused(self):
        with _resolves_to("169.254.169.254"):
            with pytest.raises(uf.UrlFetchError, match="metadata"):
                uf.resolve_and_validate("http://totally-legit.test/x")

    def test_every_resolved_address_is_checked_not_just_the_first(self):
        """Round-robin DNS with one internal address must still be refused."""
        with _resolves_to("93.184.216.34", "10.0.0.5"):
            with pytest.raises(uf.UrlFetchError, match="private"):
                uf.resolve_and_validate("http://mixed.test/x")

    def test_localhost_names_refused(self):
        for name in ("localhost", "LOCALHOST", "ip6-localhost"):
            with pytest.raises(uf.UrlFetchError):
                uf.resolve_and_validate(f"http://{name}/x")

    def test_public_address_allowed(self):
        with _resolves_to("93.184.216.34"):
            host, ips = uf.resolve_and_validate("https://docs.example.test/guide")
        assert host == "docs.example.test" and ips == ["93.184.216.34"]

    def test_unresolvable_host_is_a_clear_error(self):
        with patch.object(uf.socket, "getaddrinfo", side_effect=uf.socket.gaierror("nope")):
            with pytest.raises(uf.UrlFetchError, match="resolve"):
                uf.resolve_and_validate("http://nx.test/x")


class TestAllowInternalOverride:
    """The escape hatch: deliberate internal sources, opt-in only."""
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254"])
    def test_allow_internal_permits(self, ip):
        with _resolves_to(ip):
            assert uf.resolve_and_validate(f"http://{ip}/x", allow_internal=True)[1] == [ip]

    def test_allow_internal_permits_localhost_name(self):
        with _resolves_to("127.0.0.1"):
            assert uf.resolve_and_validate("http://localhost/x", allow_internal=True)

    def test_allow_internal_does_not_relax_the_scheme_check(self):
        """Scheme is a separate defence and must not be weakened by the flag."""
        with pytest.raises(uf.UrlFetchError, match="scheme"):
            uf.resolve_and_validate("file:///etc/passwd", allow_internal=True)


# ── Defence 3: redirects re-validated per hop ───────────────────────────────
def _resp(status=200, headers=None, body=b"<html><body><p>ok</p></body></html>"):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {"Content-Type": "text/html"}
    r.is_redirect = status in (301, 302, 303, 307, 308)
    r.encoding = "utf-8"
    r.iter_content = lambda chunk_size=None: [body]
    r.close = lambda: None
    return r


class TestRedirectRevalidation:
    def test_redirect_into_loopback_is_refused_at_the_hop(self):
        """A public URL 302'ing to 127.0.0.1 — the other standard bypass."""
        def fake_get(url, **kw):
            return _resp(302, {"Location": "http://127.0.0.1/admin"})
        def fake_resolve(host, *a, **k):
            return _addrinfo("127.0.0.1" if host == "127.0.0.1" else "93.184.216.34")
        with patch.object(uf.requests, "get", side_effect=fake_get), \
             patch.object(uf.socket, "getaddrinfo", side_effect=fake_resolve):
            with pytest.raises(uf.UrlFetchError, match="loopback"):
                uf.fetch_url("http://public.test/start")

    def test_redirect_into_metadata_is_refused(self):
        def fake_get(url, **kw):
            return _resp(302, {"Location": "http://169.254.169.254/latest/meta-data/"})
        def fake_resolve(host, *a, **k):
            return _addrinfo("169.254.169.254" if host.startswith("169.254")
                             else "93.184.216.34")
        with patch.object(uf.requests, "get", side_effect=fake_get), \
             patch.object(uf.socket, "getaddrinfo", side_effect=fake_resolve):
            with pytest.raises(uf.UrlFetchError, match="metadata"):
                uf.fetch_url("http://public.test/start")

    def test_redirect_loop_is_capped(self):
        def fake_get(url, **kw):
            return _resp(302, {"Location": "http://public.test/next"})
        with patch.object(uf.requests, "get", side_effect=fake_get), _resolves_to("93.184.216.34"):
            with pytest.raises(uf.UrlFetchError, match="[Tt]oo many redirects"):
                uf.fetch_url("http://public.test/start")

    def test_public_redirect_is_followed(self):
        calls = []
        def fake_get(url, **kw):
            calls.append(url)
            if len(calls) == 1:
                return _resp(302, {"Location": "https://public.test/final"})
            return _resp(200)
        with patch.object(uf.requests, "get", side_effect=fake_get), _resolves_to("93.184.216.34"):
            out = uf.fetch_url("http://public.test/start")
        assert out["final_url"] == "https://public.test/final"


# ── Defence 4: bounded responses ────────────────────────────────────────────
class TestResponseBounds:
    def test_oversized_body_aborts(self):
        big = b"x" * (uf.MAX_BYTES + 1024)
        with patch.object(uf.requests, "get", return_value=_resp(body=big)), \
             _resolves_to("93.184.216.34"):
            with pytest.raises(uf.UrlFetchError, match="limit"):
                uf.fetch_url("http://public.test/big")

    @pytest.mark.parametrize("ctype", ["application/pdf", "image/png", "application/zip"])
    def test_unsupported_content_type_refused(self, ctype):
        with patch.object(uf.requests, "get",
                          return_value=_resp(headers={"Content-Type": ctype})), \
             _resolves_to("93.184.216.34"):
            with pytest.raises(uf.UrlFetchError, match="supported"):
                uf.fetch_url("http://public.test/file")

    def test_http_error_surfaces(self):
        with patch.object(uf.requests, "get", return_value=_resp(404)), \
             _resolves_to("93.184.216.34"):
            with pytest.raises(uf.UrlFetchError, match="404"):
                uf.fetch_url("http://public.test/missing")


# ── Extraction ──────────────────────────────────────────────────────────────
SAMPLE = """
<html><head><title>Metasploitable 2 Guide</title>
<style>.x{color:red}</style><script>var a=1;</script></head>
<body>
<nav><a href="/nav-noise">Nav</a></nav>
<header>Site header</header>
<main>
  <h1>Metasploitable 2 Exploitability Guide</h1>
  <p>Intro paragraph about the target.</p>
  <h2>FTP on 21</h2>
  <p>vsftpd 2.3.4 contains a backdoor.</p>
  <pre>msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor</pre>
  <ul><li>Check anonymous login first</li></ul>
  <a href="/metasploit/page-two">Next chapter</a>
</main>
<footer>Copyright</footer>
</body></html>
"""


class TestExtraction:
    @pytest.fixture(autouse=True)
    def _need_bs4(self):
        pytest.importorskip("bs4", reason="beautifulsoup4 required")

    def test_boilerplate_is_stripped(self):
        md = uf.extract_markdown(SAMPLE, "https://docs.test/g/")["markdown"]
        for noise in ("var a=1", "color:red", "Site header", "Copyright", "Nav"):
            assert noise not in md, noise

    def test_headings_become_markdown(self):
        md = uf.extract_markdown(SAMPLE)["markdown"]
        assert "# Metasploitable 2 Exploitability Guide" in md
        assert "## FTP on 21" in md

    def test_code_blocks_are_fenced_and_preserved(self):
        """Command syntax is the most valuable part of a technical guide."""
        md = uf.extract_markdown(SAMPLE)["markdown"]
        assert "```" in md
        assert "use exploit/unix/ftp/vsftpd_234_backdoor" in md

    def test_list_items_kept(self):
        assert "- Check anonymous login first" in uf.extract_markdown(SAMPLE)["markdown"]

    def test_title_extracted(self):
        assert uf.extract_markdown(SAMPLE)["title"] == "Metasploitable 2 Exploitability Guide"

    def test_links_resolved_absolute(self):
        links = uf.extract_markdown(SAMPLE, "https://docs.test/g/")["links"]
        assert "https://docs.test/metasploit/page-two" in links

    def test_anchor_and_mailto_links_dropped(self):
        html = '<main><a href="#top">t</a><a href="mailto:a@b.c">m</a><a href="/real">r</a></main>'
        links = uf.extract_markdown(html, "https://d.test/")["links"]
        assert links == ["https://d.test/real"]

    def test_empty_html_is_not_an_error(self):
        assert uf.extract_markdown("<html><body></body></html>")["markdown"] == ""


class TestCrawlScoping:
    @pytest.fixture(autouse=True)
    def _need_bs4(self):
        pytest.importorskip("bs4", reason="beautifulsoup4 required")

    def test_depth_zero_fetches_one_page(self):
        with patch.object(uf, "fetch_url", return_value={
                "final_url": "https://d.test/g", "html": SAMPLE}) as m:
            out = uf.fetch_guide("https://d.test/g", depth=0)
        assert len(out["pages"]) == 1 and m.call_count == 1

    def test_offsite_links_are_not_followed(self):
        html = '<main><h1>T</h1><p>x</p><a href="https://evil.test/x">off</a></main>'
        with patch.object(uf, "fetch_url", return_value={
                "final_url": "https://d.test/g", "html": html}) as m:
            uf.fetch_guide("https://d.test/g", depth=1, max_pages=5)
        assert m.call_count == 1, "must not leave the origin the operator named"

    def test_max_pages_is_capped(self):
        assert uf.MAX_CRAWL_PAGES == 20
        with patch.object(uf, "fetch_url", return_value={
                "final_url": "https://d.test/g", "html": SAMPLE}):
            out = uf.fetch_guide("https://d.test/g", depth=1, max_pages=9999)
        assert len(out["pages"]) <= uf.MAX_CRAWL_PAGES

    def test_a_failing_subpage_does_not_sink_the_import(self):
        calls = {"n": 0}
        def fake(url, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"final_url": "https://d.test/g", "html": SAMPLE}
            raise uf.UrlFetchError("boom")
        with patch.object(uf, "fetch_url", side_effect=fake):
            out = uf.fetch_guide("https://d.test/g", depth=1, max_pages=3)
        assert len(out["pages"]) == 1
        assert out["errors"] and "boom" in out["errors"][0]["error"]


class TestSlugify:
    @pytest.mark.parametrize("url,title,expect", [
        ("https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/",
         "", "metasploitable-2-exploitability-guide"),
        ("https://d.test/x", "Metasploitable 2 Guide!", "metasploitable-2-guide"),
    ])
    def test_slug(self, url, title, expect):
        assert uf.slugify(url, title) == expect

    def test_slug_is_bounded_and_never_empty(self):
        assert 0 < len(uf.slugify("https://d.test/", "!" * 200)) <= 60


class TestMarkdownPassthrough:
    @pytest.fixture(autouse=True)
    def _needs_bs4(self):
        """These two exercise the HTML path, which needs beautifulsoup4.

        url_fetch imports bs4 lazily and raises UrlFetchError when it is
        absent, so the module imports cleanly and a module-level
        importorskip never fires. bs4 IS installed in the scan-recommender
        image; it is missing only from a bare test runner, so this skips
        rather than reporting a dependency gap as a code failure.
        """
        pytest.importorskip("bs4", reason="beautifulsoup4 not installed here; "
                                          "present in the scan-recommender image")

    """Raw .md sources must not be run through the HTML extractor.

    raw.githubusercontent.com serves markdown as text/plain. Parsing that as
    HTML reduced a 23KB HTB writeup to 168 characters, and the import failed
    with "the page may be JavaScript-rendered" — a misleading diagnosis of a
    format mismatch.
    """

    MD = "# Title\n\nSome text with `code` and a [link](https://x.test/a).\n\n## Section\n"

    def test_markdown_content_type_passes_through(self):
        doc = uf.extract_markdown(self.MD, "https://raw.x.test/f.md", "text/plain; charset=utf-8")
        assert doc["markdown"] == self.MD
        assert doc["title"] == "Title"

    def test_md_extension_passes_through_without_content_type(self):
        doc = uf.extract_markdown(self.MD, "https://raw.x.test/guide.md", "")
        assert doc["markdown"] == self.MD

    def test_html_still_parsed_when_content_type_says_so(self):
        html = "<html><body><h1>H</h1><p>hello</p></body></html>"
        doc = uf.extract_markdown(html, "https://x.test/", "text/html")
        assert "<html>" not in doc["markdown"]
        assert "hello" in doc["markdown"]

    def test_html_fragment_without_doctype_still_parsed(self):
        """Regression: a bare <main> fragment was misread as markdown, so its
        links were never extracted."""
        html = '<main><a href="/real">r</a></main>'
        doc = uf.extract_markdown(html, "https://d.test/", "")
        assert doc["links"] == ["https://d.test/real"]

    def test_markdown_wins_over_shape_when_extension_says_md(self):
        """A .md file may legitimately open with an inline HTML tag."""
        body = '<img src="badge.png">\n\n# Real Title\n'
        doc = uf.extract_markdown(body, "https://raw.x.test/README.md", "text/plain")
        assert doc["markdown"] == body
