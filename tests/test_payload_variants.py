"""Which payload to send at THIS target, and which regex proves it there.

`assets.os` has existed for a long time and is populated on 0 of 2,295 rows;
nothing in the build-PoC pipeline referenced an OS at all. So the craft
guidance HEDGED — the lfi and path-traversal entries listed `/etc/passwd` and
`win.ini` side by side and let the model pick. A wrong pick costs a refine
iteration that the loop then reads as "the endpoint is wrong" rather than "the
OS is wrong".

And it is not only the payload: the PROOF regex is OS-specific too
(`root:x:0:0:` vs `\\[fonts\\]`), so a right payload judged by a wrong
assertion still fails.

The rule this file defends hardest: an undetermined OS means UNKNOWN, never
linux. Defaulting is how a Windows target gets attacked with /etc/passwd for
an entire build.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=.:tests python -m pytest tests/test_payload_variants.py -v'
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import payload_variants as pv  # noqa: E402
from etl import vuln_classes as vc  # noqa: E402

YAML_PATH = REPO / "knowledge" / "payload_variants.yaml"
RAW = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


# ── the table ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestTable:
    def test_it_loads(self):
        assert pv.loaded() is True
        assert pv.load()["rules"], "no detection rules compiled"

    def test_every_detection_pattern_compiles(self):
        for r in RAW["detection"]:
            re.compile(r["pattern"])

    def test_every_proof_regex_compiles(self):
        for cls, entries in RAW["variants"].items():
            for e in entries:
                for k, p in (e.get("proof") or {}).items():
                    re.compile(p)

    def test_every_rule_declares_an_axis(self):
        """A rule that sets neither os nor runtime establishes nothing."""
        for r in RAW["detection"]:
            assert r.get("os") or r.get("runtime"), r.get("id")

    def test_rule_ids_are_unique(self):
        ids = [r["id"] for r in RAW["detection"]]
        assert len(ids) == len(set(ids))

    def test_axis_values_are_from_the_declared_vocabulary(self):
        oses, rts = set(RAW["os_families"]), set(RAW["runtimes"])
        for r in RAW["detection"]:
            if r.get("os"):
                assert r["os"] in oses, r["id"]
            if r.get("runtime"):
                assert r["runtime"] in rts, r["id"]
        for cls, entries in RAW["variants"].items():
            for e in entries:
                if e.get("os"):
                    assert e["os"] in oses, cls
                if e.get("runtime"):
                    assert e["runtime"] in rts, cls

    def test_every_variant_class_is_a_real_exploitable_class(self):
        """A variant for a class the table does not know is unreachable."""
        for cls in RAW["variants"]:
            assert vc.canonical(cls) == cls, cls
            assert vc.is_exploitable(cls), cls

    def test_a_file_read_class_has_both_os_forms(self):
        """The hedge this replaces offered both at once; now each is selected."""
        for cls in ("path-traversal", "lfi"):
            oses = {e.get("os") for e in RAW["variants"][cls] if e.get("os")}
            assert {"linux", "windows"} <= oses, cls


# ── detection ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestDetect:
    def test_iis_is_windows(self):
        d = pv.detect(headers={"Server": "Microsoft-IIS/10.0"})
        assert d["os"] == "windows"
        assert d["evidence"], "no evidence recorded for the decision"

    def test_aspnet_gives_os_and_runtime(self):
        d = pv.detect(headers={"X-Powered-By": "ASP.NET"})
        assert d["os"] == "windows" and d["runtime"] == "dotnet"

    def test_ubuntu_banner_is_linux(self):
        assert pv.detect(headers={"Server": "Apache/2.4.41 (Ubuntu)"})["os"] == "linux"

    def test_php_header_gives_runtime_without_os(self):
        """A runtime is not an OS: PHP runs on both."""
        d = pv.detect(headers={"X-Powered-By": "PHP/8.1.2"})
        assert d["runtime"] == "php"
        assert d["os"] is None

    def test_jsessionid_is_java(self):
        d = pv.detect(headers={"Set-Cookie": "JSESSIONID=abc; Path=/"})
        assert d["runtime"] == "java"

    def test_a_crawled_extension_is_a_signal(self):
        assert pv.detect(paths=["/app/Default.aspx"])["os"] == "windows"
        assert pv.detect(paths=["/index.php"])["runtime"] == "php"

    def test_a_windows_path_in_the_body_is_a_signal(self):
        d = pv.detect(body=r"at C:\inetpub\wwwroot\app\default.aspx line 12")
        assert d["os"] == "windows"

    def test_nothing_establishes_it_means_unknown_not_linux(self):
        """The rule this file exists for."""
        for kw in ({}, {"headers": {"Server": "nginx"}}, {"body": "hello"},
                   {"paths": ["/", "/about"]}):
            d = pv.detect(**kw)
            assert d["os"] is None, kw
            assert d["runtime"] is None or d["os"] is None

    def test_detection_records_which_rule_fired(self):
        d = pv.detect(headers={"Server": "Microsoft-IIS/10.0"})
        assert d["evidence"][0]["rule"] == "iis_server_header"
        assert d["os_provenance"] == "scan_observed"

    def test_detection_never_raises(self):
        for bad in ({"headers": None}, {"headers": {"Server": None}},
                    {"body": 42}, {"paths": [None]}):
            pv.detect(**bad)


# ── selection ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestSelection:
    def test_a_windows_target_is_not_offered_etc_passwd(self):
        pays = pv.payloads_for("path-traversal", os="windows")
        assert pays, "no windows payloads"
        assert not any("etc/passwd" in p for p in pays)
        assert any("win.ini" in p for p in pays)

    def test_a_linux_target_is_not_offered_win_ini(self):
        pays = pv.payloads_for("path-traversal", os="linux")
        assert not any("win.ini" in p for p in pays)
        assert any("etc/passwd" in p for p in pays)

    def test_the_proof_regex_follows_the_os(self):
        """The half that is easy to miss: a right payload judged by a wrong
        regex still fails."""
        lin = pv.proof_for("path-traversal", os="linux")
        win = pv.proof_for("path-traversal", os="windows")
        assert "root:x:0:0:" in lin.values()
        assert "root:x:0:0:" not in win.values()
        assert any("fonts" in v for v in win.values())

    def test_an_unknown_os_returns_every_form_and_says_so(self):
        sel = pv.variants_for("path-traversal")
        assert sel["ambiguous"] is True
        assert "os" in sel["ambiguous_axes"]
        pays = pv.payloads_for("path-traversal")
        assert any("etc/passwd" in p for p in pays)
        assert any("win.ini" in p for p in pays), (
            "an unknown OS silently dropped the windows forms — that is a "
            "default, which is the bug")

    def test_a_known_os_is_not_ambiguous(self):
        assert pv.variants_for("path-traversal", os="linux", runtime="php")["ambiguous"] is False

    def test_a_runtime_only_entry_applies_on_either_os(self):
        """`php://filter` works on PHP on Windows; `web.xml` is Java anywhere."""
        for os_name in ("linux", "windows"):
            pays = pv.payloads_for("lfi", os=os_name, runtime="php")
            assert any("php://filter" in p for p in pays), os_name

    def test_a_runtime_entry_is_excluded_when_the_runtime_differs(self):
        pays = pv.payloads_for("lfi", os="linux", runtime="java")
        assert not any("php://filter" in p for p in pays)

    def test_payloads_are_deduplicated_and_ordered(self):
        pays = pv.payloads_for("path-traversal")
        assert len(pays) == len(set(pays))

    def test_an_unknown_class_yields_nothing_rather_than_raising(self):
        assert pv.payloads_for("not-a-class") == []
        assert pv.proof_for("not-a-class") == {}

    def test_cmdi_payloads_differ_by_os(self):
        lin = pv.payloads_for("cmdi", os="linux")
        win = pv.payloads_for("cmdi", os="windows")
        assert any("id" in p for p in lin) and not any("whoami" in p for p in lin)
        assert any("whoami" in p for p in win)

    def test_the_note_distinguishes_a_selection_from_a_guess(self):
        known = pv.note(pv.variants_for("path-traversal", os="linux", runtime="php"))
        guess = pv.note(pv.variants_for("path-traversal"))
        assert "unknown" in guess.lower()
        assert "unknown" not in known.lower()


# ── access permissions ─────────────────────────────────────────────────────

@pytest.mark.unit
class TestAccessPermissions:
    def test_the_proof_target_is_always_readable(self):
        """`/etc/passwd` is 0644 on every linux host. `/etc/shadow` is 0640
        root:shadow and the web-server user cannot read it."""
        pref = pv.preferred_proof("path-traversal", os="linux")
        assert "/etc/passwd" in pref
        assert "/etc/shadow" not in pref

    def test_an_unreadable_target_is_never_a_payload(self):
        lin = [e for e in RAW["variants"]["path-traversal"] if e.get("os") == "linux"][0]
        assert not any("shadow" in p for p in lin["payloads"])

    def test_its_signature_is_still_recognised(self):
        """Not requesting it is different from not recognising it: if the
        content arrives by some other route we must identify it."""
        assert "/etc/shadow" in pv.proof_for("path-traversal", os="linux")

    def test_an_empty_read_of_it_is_declared_not_a_refutation(self):
        """Under the repeated-outcome rule two empty results set a REQUIRED
        AXIS and walk the build away from a primitive that WAS working."""
        cav = pv.proof_caveats_for("path-traversal", os="linux")
        assert "/etc/shadow" in cav
        assert "permission" in cav["/etc/shadow"].lower()

    def test_process_only_targets_carry_the_same_caveat(self):
        cav = pv.proof_caveats_for("path-traversal", os="linux")
        assert "/proc/self/environ" in cav

    def test_access_levels_come_from_a_closed_vocabulary(self):
        for cls, entries in RAW["variants"].items():
            for e in entries:
                for k, v in (e.get("proof_access") or {}).items():
                    assert v.get("readable") in (pv.WORLD, pv.PRIVILEGED, pv.PROCESS), (cls, k)

    def test_an_undeclared_target_is_treated_as_readable(self):
        """Most app files are owned by the app; defaulting them to privileged
        would strip every usable proof target."""
        assert "package.json" in pv.preferred_proof("path-traversal", runtime="node")


# ── the runtimes that were declared and never detected ─────────────────────

@pytest.mark.unit
class TestRuntimeCoverage:
    @pytest.mark.parametrize("headers,expect", [
        ({"Server": "gunicorn/20.1.0"}, "python"),
        ({"Server": "Werkzeug/2.0.3 Python/3.9.2"}, "python"),
        ({"Set-Cookie": "csrftoken=abc; Path=/"}, "python"),
        ({"X-Powered-By": "Express"}, "node"),
        ({"Set-Cookie": "connect.sid=s%3Aabc"}, "node"),
        ({"Server": "Puma 5.6.4"}, "ruby"),
        ({"X-Runtime": "0.034512"}, "ruby"),
    ])
    def test_each_runtime_is_detected(self, headers, expect):
        assert pv.detect(headers=headers)["runtime"] == expect

    def test_every_declared_runtime_can_actually_be_detected(self):
        """A runtime in the vocabulary with no rule is a value nothing can
        ever produce — python and node were exactly that."""
        detectable = {r.get("runtime") for r in RAW["detection"] if r.get("runtime")}
        missing = sorted(set(RAW["runtimes"]) - detectable)
        assert not missing, "runtimes declared but undetectable: %s" % missing

    def test_every_detectable_runtime_has_payload_variants(self):
        """Detecting a runtime and then having nothing to send at it buys
        nothing."""
        with_variants = set()
        for entries in RAW["variants"].values():
            for e in entries:
                if e.get("runtime"):
                    with_variants.add(e["runtime"])
        detectable = {r.get("runtime") for r in RAW["detection"] if r.get("runtime")}
        missing = sorted(detectable - with_variants)
        assert not missing, "runtimes detected with no variants: %s" % missing

    def test_python_has_no_php_filter_wrapper(self):
        pays = pv.payloads_for("path-traversal", os="linux", runtime="python")
        assert not any("php://" in p for p in pays)
        assert any("settings.py" in p for p in pays)


# ── output analysis: read what came back ───────────────────────────────────

@pytest.mark.unit
class TestOutputAnalysis:
    @pytest.mark.parametrize("body,expect", [
        ("Traceback (most recent call last):\n  File \"/usr/lib/python3/a.py\"", "python"),
        ("Error: Cannot find module 'x'\n    at Object.<anonymous> (/srv/a.js:3)", "node"),
        ("java.lang.NullPointerException\n\tat org.apache.catalina.Foo(Foo.java:42)", "java"),
        ("Fatal error: Call to undefined function x() in /var/www/a.php on line 7", "php"),
        ("app/controllers/x.rb:12:in `show'  ActionController::RoutingError", "ruby"),
        ("System.NullReferenceException at Microsoft.AspNetCore.Mvc", "dotnet"),
    ])
    def test_a_stack_trace_names_the_runtime(self, body, expect):
        """A Server header can be rewritten by a proxy; a stack trace cannot.
        And an error page is exactly what a half-working exploit produces."""
        assert pv.detect(headers={"Server": "nginx"}, body=body)["runtime"] == expect

    def test_an_explicit_header_still_wins_over_the_body(self):
        d = pv.detect(headers={"X-Powered-By": "PHP/8.1"},
                      body="Traceback (most recent call last):")
        assert d["runtime"] == "php"

    def test_detection_reports_whether_it_had_anything_to_read(self):
        """"nothing matched" and "there was nothing to look at" both yield
        os=None and send an operator to different fixes."""
        assert pv.detect()["basis"] == "no_material"
        assert pv.detect(headers={"Server": "nginx"})["basis"] == "no_match"
        assert pv.detect(headers={"Server": "Microsoft-IIS/10"})["basis"] == "matched"

    def test_it_records_how_much_it_examined(self):
        d = pv.detect(headers={"Server": "nginx"}, body="x" * 50, paths=["/a", "/b"])
        assert d["examined"] == {"headers": 1, "body_chars": 50, "paths": 2}


# ── the projection that replaced the flat table ────────────────────────────

@pytest.mark.unit
class TestSignatureProjection:
    def test_it_covers_the_old_flat_table(self):
        """`_FILE_READ_SIGNATURES` is now a projection; nothing it proved may
        be lost."""
        old = None
        for n in ast.walk(TREE):
            if isinstance(n, ast.Assign) and any(
                    getattr(t, "id", "") == "_FILE_READ_SIGNATURES_FALLBACK" for t in n.targets):
                old = ast.literal_eval(n.value)
        assert old, "the fallback literal is gone"
        projected = pv.file_read_signatures()
        missing = sorted(k for k in old if not any(
            k.split("/")[-1] in p for p in projected))
        assert not missing, "signatures lost in the projection: %s" % missing

    def test_the_reader_falls_back_to_the_literal(self):
        fn = _func("_file_read_signatures")
        assert fn is not None
        src = ast.unparse(fn)
        assert "_FILE_READ_SIGNATURES_FALLBACK" in src, (
            "no fallback — an unreadable table would silently disable every "
            "file-read proof")


# ── wiring ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestWiring:
    def test_the_gather_manifest_detects_the_shape(self):
        src = ast.unparse(_func("_gather_manifest"))
        assert "_pv_detect" in src
        assert "target_shape" in src

    def test_the_shape_is_a_fact_not_a_gate_item(self):
        """An undetermined OS must never be able to BLOCK a build."""
        fn = _func("_gather_manifest")
        gate_items = {c.args[0].value for c in ast.walk(fn)
                      if isinstance(c, ast.Call)
                      and getattr(c.func, "id", "") == "add"
                      and c.args and isinstance(c.args[0], ast.Constant)}
        assert "target_os" not in gate_items, (
            "the shape is a manifest ITEM, so an undetermined OS can block a "
            "build — it must be a fact")
        assert "target_shape" not in gate_items

    def test_it_reuses_the_probe_rather_than_making_a_request(self):
        src = ast.unparse(_func("_gather_manifest"))
        i = src.index("_pv_detect")
        assert "r0" in src[max(0, i - 400):i + 400], (
            "detection should read the root probe's own response")

    def test_the_manifest_text_states_an_unknown_shape_out_loud(self):
        src = ast.unparse(_func("_gather_manifest_text"))
        assert "target shape" in src
        assert "UNKNOWN" in src, (
            "silence reads as linux to every downstream reader")

    def test_synth_reads_the_shape_back_instead_of_re_probing(self):
        src = ast.unparse(_func("_synthesize_cve_poc"))
        assert "_target_shape_from_guidance" in src
        assert "_proof_expectation_block" in src

    def test_the_parser_treats_unknown_as_none(self):
        fn = _func("_target_shape_from_guidance")
        assert fn is not None
        ns = {}
        exec(compile(ast.Module([fn], []), "<api>", "exec"), ns)
        f = ns["_target_shape_from_guidance"]
        assert f("  target shape: os=windows runtime=dotnet  (via x)") == ("windows", "dotnet")
        assert f("  target shape: os=UNKNOWN runtime=UNKNOWN — no banner") == (None, None)
        assert f("no such line") == (None, None)
        assert f(None) == (None, None)
