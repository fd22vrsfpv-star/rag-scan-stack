"""burp_export builds Burp-ingestible artifacts from a security test.

A custom test/payload is only useful once it reaches the tester's Burp. This
pins the request builder: curl commands must parse to the exact method/URL/
headers/body (the payload lands where the tester expects), and non-HTTP tools
must fall back to a valid request rather than producing a broken export.

Pure stdlib module — imported directly, runs on a bare checkout.
"""
import importlib.util
import json
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "app", "rag-api", "burp_export.py")


def _load():
    if not os.path.exists(MOD):
        pytest.skip("burp_export.py not present")
    spec = importlib.util.spec_from_file_location("burp_export", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


b = _load()


def test_parse_curl_get_with_query():
    p = b.parse_curl("curl -sk http://10.0.0.5/x?file=../../etc/passwd")
    assert p and p["method"] == "GET"
    assert p["url"] == "http://10.0.0.5/x?file=../../etc/passwd"


def test_parse_curl_post_with_headers_and_body():
    p = b.parse_curl("curl -sk -H 'Content-Type: application/json' "
                     "-d '{\"q\":1}' http://t/graphql")
    assert p["method"] == "POST"          # body implies POST
    assert p["headers"]["Content-Type"] == "application/json"
    assert p["body"] == '{"q":1}'
    assert p["url"] == "http://t/graphql"


def test_parse_curl_explicit_method():
    p = b.parse_curl("curl -X OPTIONS -o /dev/null -D - http://t/")
    assert p["method"] == "OPTIONS"


def test_non_curl_returns_none():
    assert b.parse_curl("sqlmap -u http://t/i?id=1 --batch") is None
    assert b.parse_curl("") is None


def test_raw_request_is_wellformed():
    p = b.parse_curl("curl -sk -H 'X-Test: 1' -d 'a=b' http://h:8080/p?q=1")
    raw = b.to_raw_request(p, "note")
    first = raw.splitlines()[0]
    assert first == "POST /p?q=1 HTTP/1.1"
    assert "Host: h:8080" in raw
    assert "Content-Length: 3" in raw          # body 'a=b'
    assert "a=b" in raw


def test_export_test_har_for_curl():
    t = {"id": "abcdef12", "name": "lfi", "tier": "safe", "category": "lfi_read",
         "tool": "curl", "command": "curl -sk http://10.0.0.5/x?file=/etc/passwd",
         "assertion": {"expect_substring": ["root:x:0:0"]},
         "target_ip": "10.0.0.5", "target_port": 80, "target_service": "http"}
    data, fn, ct = b.export_test(t, "har")
    assert fn.endswith(".har") and ct == "application/json"
    e = json.loads(data)["log"]["entries"][0]
    assert e["request"]["url"] == "http://10.0.0.5/x?file=/etc/passwd"
    assert "root:x:0:0" in e["request"]["comment"]  # assertion carried as note


def test_export_test_fallback_for_non_http_tool():
    t = {"id": "e", "name": "sqli", "tier": "safe", "command": "sqlmap -u http://t/i?id=1 --batch",
         "target_ip": "9.9.9.9", "target_port": 443, "target_service": "https"}
    data, fn, ct = b.export_test(t, "har")
    url = json.loads(data)["log"]["entries"][0]["request"]["url"]
    assert url == "https://9.9.9.9:443/"        # scheme from port/service
    assert "sqlmap -u" in json.loads(data)["log"]["entries"][0]["request"]["comment"]


def test_bulk_export_one_har_many_entries():
    rows = [
        {"id": "1", "name": "a", "command": "curl -sk http://t/1"},
        {"id": "2", "name": "b", "command": "curl -sk http://t/2"},
    ]
    data, fn, ct = b.export_tests(rows, "har")
    assert len(json.loads(data)["log"]["entries"]) == 2
