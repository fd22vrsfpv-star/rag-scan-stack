"""Guard: ffuf can fuzz with a logged-in session.

pd-runner ffuf accepts auth headers and forwards them to -H; the crawl dispatches
authenticated ffuf with the browser's live session cookie (opt-in via
FFUF_AUTHENTICATED). Source-wiring guards (the modules need Playwright/FastAPI to
import). Sabotage-proven: drop a wire and an assertion fails.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_pd_runner_ffuf_accepts_and_forwards_headers():
    s = _src("pd_runner/pd_runner.py")
    # FfufReq declares headers, run_ffuf forwards each to -H
    assert "headers: Optional[List[str]] = None" in s
    i_model = s.index("class FfufReq")
    i_run = s.index("def run_ffuf")
    assert s.index("headers: Optional[List[str]] = None", i_model) < i_run
    assert 'cmd.extend(["-H", h])' in s


def test_crawl_dispatches_authenticated_ffuf():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "async def _run_authenticated_ffuf(" in s
    assert "_run_authenticated_ffuf(ctx, req.url" in s
    # uses the browser's session cookie and posts to pd-runner /jobs/ffuf
    assert '"Cookie: "' in s and "/jobs/ffuf" in s
    # opt-in gate (heavy/noisy) — env FFUF_AUTHENTICATED
    assert 'FFUF_AUTHENTICATED' in s
    # FUZZ keyword in the target url
    assert "/FUZZ" in s


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))
