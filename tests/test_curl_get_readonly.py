"""curl -G --data-urlencode is read-only (GET query), not a body/upload.

WHY: a deepen SQLi probe `curl -s -G '...' --data-urlencode "password=1' OR '1'='1"`
sends its data as a GET QUERY STRING (read-only), but the safe-lane filter in
kali_listener flagged --data-urlencode as a body and refused it, so read-only
confirmation probes could never run on the no-approval lane. The filter now
recognises -G/--get; uploads and non-GET methods stay blocked.

SABOTAGE PROOF: delete the get_mode handling in _readonly_arg_violation and the
'use -G to send it as a query' branch / the get_mode check disappear.
"""
import os, re, pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO, "kali_listener", "listener_service.py")

def _curl_branch():
    if not os.path.exists(SRC): pytest.skip("listener_service.py missing")
    s = open(SRC, encoding="utf-8").read()
    i = s.index("def _readonly_arg_violation")
    # the curl/wget branch up to the next elif
    seg = s[i:i + 2000]
    j = seg.index('if tool in ("curl", "wget"):')
    return seg[j:seg.index('elif tool ==', j)]

def test_curl_get_mode_recognised_and_data_allowed_in_get():
    b = _curl_branch()
    assert "get_mode" in b, "must compute a get_mode for curl"
    assert re.search(r"-G\b|--get", b), "must detect -G / --get (case-sensitive)"
    assert "data and not get_mode" in b, ("data flags must be refused ONLY when not "
                                          "in GET mode (so curl -G --data* is allowed)")

def test_uploads_and_nongets_still_blocked():
    b = _curl_branch()
    assert "--upload-file" in b and "--form" in b, "uploads must still be blocked"
    assert re.search(r"-x|--request", b), "non-GET methods (-X POST) must still be blocked"
