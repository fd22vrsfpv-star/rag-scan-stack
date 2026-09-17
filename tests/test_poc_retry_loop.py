"""The closed web-PoC loop: try -> read output -> refine -> retry, up to X.

Regression/contract for the feature that closes the generate->try->look at
output->fix->retry loop for web PoCs (the MSF path already auto-corrects; the web
path was single-shot). Exercises `web_poc_executor.execute_web_poc_with_retry`
directly with a FAKE single-shot executor and a FAKE refiner, so it runs
standalone with no rag-api, DB, Playwright, or LLM.

    pytest tests/test_poc_retry_loop.py

Sabotage check: make the loop `break` after attempt 1 (drop the retry) and
test_refines_then_confirms / test_exhausts_all_attempts fail.
"""
import os
import sys
import asyncio
import pathlib

import pytest

# web_poc_executor lives in exploit_runner/ and imports only stdlib + httpx.
RUNNER = pathlib.Path(__file__).resolve().parent.parent / "exploit_runner"
sys.path.insert(0, str(RUNNER))
wpe = pytest.importorskip("web_poc_executor")


def _run(coro):
    # Python 3.12 removed the implicit current-event-loop; make a fresh one.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _FakeExecutor:
    """Stands in for execute_web_poc: confirms only when the payload equals
    ``winning`` (or on the ``succeed_on``-th call), and echoes the payload it saw
    into the output so the loop's 'read the output' step has something real."""

    def __init__(self, winning=None, succeed_on=None):
        self.winning = winning
        self.succeed_on = succeed_on
        self.calls = []

    async def __call__(self, exploit):
        md = exploit.get("metadata") or {}
        payload = md.get("payload", "")
        self.calls.append(payload)
        n = len(self.calls)
        ok = (self.winning is not None and payload == self.winning) or \
             (self.succeed_on is not None and n >= self.succeed_on)
        return {
            "success": ok,
            "output": f"[Web PoC] {'SUCCESS' if ok else 'NOT CONFIRMED'}\n"
                      f"Payload: {payload}\nEvidence: reflected={payload!r}",
            "session_type": "web_poc" if ok else None,
            "artifacts": {},
        }


def _fake_refine_factory(sequence):
    """Refiner that returns the next payload in ``sequence`` (dicts or None), and
    records the observed_output it was handed each call."""
    seen = {"outputs": [], "tried": []}

    async def _refine(*, finding, failed_payload, injection_point, parameter,
                      success_indicator, observed_output, attempt, tried_payloads=None):
        seen["outputs"].append(observed_output)
        seen["tried"].append(list(tried_payloads or []))
        idx = attempt - 1
        if idx >= len(sequence) or sequence[idx] is None:
            return None
        nxt = sequence[idx]
        return {"payload": nxt, "injection_point": injection_point,
                "parameter": parameter, "success_indicator": success_indicator,
                "description": f"refined to {nxt}"}

    _refine.seen = seen
    return _refine


def _exploit(payload="A", **md):
    m = {"payload": payload, "injection_point": "query_param",
         "parameter": "q", "success_indicator": "response_content",
         "target_url": "http://t.example/x", "issue_type": "xss"}
    m.update(md)
    return {"id": "poc-1", "target_ip": "203.0.113.9", "target_port": 80,
            "exploit_title": "XSS PoC", "exploit_type": "xss", "metadata": m}


def test_confirms_first_attempt_no_refine():
    ex = _FakeExecutor(winning="A")
    refine = _fake_refine_factory(["B", "C"])
    wpe.execute_web_poc = ex  # monkeypatch the single-shot executor
    res = _run(wpe.execute_web_poc_with_retry(_exploit("A"), max_attempts=3, refine=refine))
    assert res["success"] is True
    assert res["attempts"] == 1
    assert res["refined"] is False
    assert refine.seen["outputs"] == []      # never had to refine
    assert ex.calls == ["A"]


def test_refines_then_confirms():
    # Attempt 1 (A) fails, refine -> B, attempt 2 (B) confirms.
    ex = _FakeExecutor(winning="B")
    refine = _fake_refine_factory(["B", "C"])
    wpe.execute_web_poc = ex
    res = _run(wpe.execute_web_poc_with_retry(_exploit("A"), max_attempts=3, refine=refine))
    assert res["success"] is True
    assert res["attempts"] == 2
    assert res["refined"] is True
    assert ex.calls == ["A", "B"]            # the refined payload actually ran
    # The refiner saw the FAILED attempt's real output, not a stub.
    assert "reflected='A'" in refine.seen["outputs"][0]
    assert refine.seen["tried"][0] == ["A"]  # prior payloads passed for no-repeat


def test_exhausts_all_attempts():
    ex = _FakeExecutor(winning="never")      # nothing confirms
    refine = _fake_refine_factory(["B", "C", "D"])
    wpe.execute_web_poc = ex
    res = _run(wpe.execute_web_poc_with_retry(_exploit("A"), max_attempts=3, refine=refine))
    assert res["success"] is False
    assert res["attempts"] == 3              # bounded exactly by max_attempts
    assert ex.calls == ["A", "B", "C"]


def test_stops_when_refine_gives_up():
    # Refiner returns None after attempt 1 -> loop stops early, does not burn budget.
    ex = _FakeExecutor(winning="never")
    refine = _fake_refine_factory([None])
    wpe.execute_web_poc = ex
    res = _run(wpe.execute_web_poc_with_retry(_exploit("A"), max_attempts=5, refine=refine))
    assert res["success"] is False
    assert res["attempts"] == 1
    assert ex.calls == ["A"]


def test_max_attempts_one_is_single_shot():
    ex = _FakeExecutor(winning="never")
    refine = _fake_refine_factory(["B"])
    wpe.execute_web_poc = ex
    res = _run(wpe.execute_web_poc_with_retry(_exploit("A"), max_attempts=1, refine=refine))
    assert res["attempts"] == 1
    assert ex.calls == ["A"]
    assert refine.seen["outputs"] == []      # never refined


def test_default_budget_is_configurable_env():
    # POC_MAX_ATTEMPTS is read from env at import; just assert it is a sane int >=1.
    assert isinstance(wpe.POC_MAX_ATTEMPTS, int) and wpe.POC_MAX_ATTEMPTS >= 1
