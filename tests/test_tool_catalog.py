"""Recommendation validator: reject what cannot run, allow what can.

The gate exists because LLM-generated recommendations are not constrained to real
tool names. Measured on a live run: 2 of 8 SMB suggestions were unrunnable —
`smb Vuln-MS17-010` (malformed) and `smb-enum-links` (no such nmap script).

The tests below lock in the FAILURE BIAS as much as the detection: this gate can
block scans, so anything it cannot confidently disprove must pass.
"""
import importlib.util
import os

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "tool_catalog",
    os.path.join(os.path.dirname(__file__), "..", "scan_recommender", "tool_catalog.py"),
)
tc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tc)


@pytest.fixture(autouse=True)
def catalog(monkeypatch):
    """A small, known catalog so tests do not depend on installed scanners."""
    fake = {
        "nmap_scripts": {"smb-enum-shares", "smb-vuln-ms17-010", "snmp-info", "snmp-brute"},
        "msf_modules": {"auxiliary/admin/smb/samba_symlink_traversal"},
        "nuclei_templates": {"cves/2017/CVE-2017-7494"},
        "nuclei_tags": {"snmp", "network", "misconfig"},
    }
    monkeypatch.setattr(tc, "load_catalogs", lambda *a, **k: fake)
    return fake


class TestRejects:
    def test_malformed_identifier(self):
        """The live defect: capital V and a space instead of a hyphen."""
        ok, reason = tc.validate_recommendation(
            {"scanner": "nmap", "script": "smb Vuln-MS17-010"})
        assert not ok and "not a valid identifier" in reason

    def test_plausible_but_nonexistent_script(self):
        """The subtler live defect — well-formed, reads correctly, does not exist."""
        ok, reason = tc.validate_recommendation(
            {"scanner": "nmap", "script": "smb-enum-links"})
        assert not ok and "does not exist" in reason

    def test_nonexistent_msf_module(self):
        ok, _ = tc.validate_recommendation(
            {"scanner": "metasploit", "script": "exploit/unix/misc/not_real"})
        assert not ok

    def test_glob_matching_nothing(self):
        ok, _ = tc.validate_recommendation({"scanner": "nmap", "script": "nosuch-*"})
        assert not ok


class TestAllows:
    def test_real_script(self):
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "smb-enum-shares"})[0]

    def test_real_msf_module(self):
        assert tc.validate_recommendation(
            {"scanner": "metasploit",
             "script": "auxiliary/admin/smb/samba_symlink_traversal"})[0]

    def test_glob_that_matches(self):
        """`--script=snmp-*` is a legitimate invocation, not a guess."""
        assert tc.validate_recommendation({"scanner": "nmap", "script": "snmp-*"})[0]

    def test_full_command_from_a_rule(self):
        """tool_kb rules carry whole commands; only --script= names are checkable."""
        assert tc.validate_recommendation(
            {"scanner": "nmap",
             "script": "nmap -sU -sV -p {port} --script=snmp-* {target}"})[0]

    def test_command_naming_no_script(self):
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "nmap -sV -p 445 {target}"})[0]

    def test_nuclei_tag_expression(self):
        assert tc.validate_recommendation(
            {"scanner": "nuclei", "template": "snmp,network"})[0]

    def test_scanner_without_a_catalog(self):
        """snmpwalk/hydra/gobuster have no closed vocabulary — must not be blocked."""
        assert tc.validate_recommendation(
            {"scanner": "snmpwalk", "script": "snmpwalk -v2c -c public {target}"})[0]

    def test_bare_recommendation(self):
        assert tc.validate_recommendation({"scanner": "hydra", "script": None})[0]


class TestFailureBias:
    def test_empty_catalog_allows_everything(self, monkeypatch):
        """Cannot verify != invalid. A missing catalog must not block all scans."""
        monkeypatch.setattr(tc, "load_catalogs", lambda *a, **k: {})
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "totally-made-up"})[0]

    def test_missing_single_catalog_allows_that_tool(self, monkeypatch):
        monkeypatch.setattr(tc, "load_catalogs",
                            lambda *a, **k: {"nmap_scripts": set(), "msf_modules": {"x"}})
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "anything-at-all"})[0]


class TestFilter:
    def test_splits_and_annotates(self):
        recs = [
            {"scanner": "nmap", "script": "smb-enum-shares"},
            {"scanner": "nmap", "script": "smb Vuln-MS17-010"},
            {"scanner": "nmap", "script": "smb-enum-links"},
        ]
        ok, bad = tc.filter_recommendations(recs)
        assert len(ok) == 1 and len(bad) == 2
        assert all("_rejection" in b for b in bad)


class TestFlagsOnlyValues:
    """A scanner flag is not a script name.

    Observed from qwen3.8: `-sV` returned as an nmap *script*. It passed the
    original gate because the leading dash made it look like a command line,
    and a command line names no script to check. But `--script=-sV` is not
    runnable — the value is junk, not a command.
    """

    def test_bare_flag_rejected(self):
        ok, reason = tc.validate_recommendation({"scanner": "nmap", "script": "-sV"})
        assert not ok, reason

    def test_multiple_flags_rejected(self):
        ok, _ = tc.validate_recommendation({"scanner": "nmap", "script": "-sV -sC"})
        assert not ok

    def test_real_command_still_passes(self):
        """Has a non-flag word, so it is a command, not a stray flag."""
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "nmap -sV -p {port} {target}"})[0]

    def test_command_with_script_still_validated(self):
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "nmap -sV --script=snmp-info {target}"})[0]


class TestProseAndWrongField:
    """Junk found by measuring a 3-round benchmark, not by imagination.

    qwen3.8 produced all three of these while ostensibly passing validation.
    """

    def test_prose_in_the_script_field(self):
        prose = ("Send IRC command prefixed with 'AB' to test for UnrealIRCd "
                 "system-command backdoor; verify server response for "
                 "unauthorized command execution")
        ok, reason = tc.validate_recommendation({"scanner": "nmap", "script": prose})
        assert not ok, reason

    def test_flag_in_the_action_field(self):
        """Only `script` was checked for nmap, so `-sV` in `action` slipped past."""
        ok, _ = tc.validate_recommendation({"scanner": "nmap", "action": "-sV"})
        assert not ok

    def test_flags_with_a_port_number(self):
        ok, _ = tc.validate_recommendation({"scanner": "nmap", "script": "-sV -p 6667"})
        assert not ok

    def test_short_real_command_still_passes(self):
        assert tc.validate_recommendation(
            {"scanner": "nmap", "script": "nmap -sV -p {port} {target}"})[0]

    def test_msf_path_not_mistaken_for_prose(self):
        assert tc.validate_recommendation(
            {"scanner": "metasploit",
             "action": "auxiliary/admin/smb/samba_symlink_traversal"})[0]


class TestMsfSingularPlural:
    """msf module DIRECTORIES are plural; its invocation syntax is singular.

    The catalog is built by walking the source tree, so it holds
    `exploits/unix/misc/distcc_exec` while every human, playbook and model writes
    `exploit/unix/misc/distcc_exec`. Without folding, the validator rejected
    EVERY real exploit module — a false positive, the worst failure mode for a
    gate that blocks work.

    Earlier tests missed this because `auxiliary` and `post` are spelled the same
    in both forms.
    """

    @pytest.fixture(autouse=True)
    def tree_catalog(self, monkeypatch):
        """Catalog in source-tree form, exactly as the refresh script emits it."""
        monkeypatch.setattr(tc, "load_catalogs", lambda *a, **k: {
            "msf_modules": {
                "exploits/unix/misc/distcc_exec",
                "exploits/unix/ftp/vsftpd_234_backdoor",
                "auxiliary/admin/smb/samba_symlink_traversal",
                "payloads/cmd/unix/reverse",
            },
        })

    def test_singular_exploit_path_accepted(self):
        ok, reason = tc.validate_recommendation(
            {"scanner": "metasploit", "script": "exploit/unix/misc/distcc_exec"})
        assert ok, reason

    def test_the_rule_named_module_accepted(self):
        ok, reason = tc.validate_recommendation(
            {"scanner": "metasploit", "script": "exploit/unix/ftp/vsftpd_234_backdoor"})
        assert ok, reason

    def test_payload_singular_accepted(self):
        assert tc.validate_recommendation(
            {"scanner": "metasploit", "script": "payload/cmd/unix/reverse"})[0]

    def test_auxiliary_unaffected(self):
        assert tc.validate_recommendation(
            {"scanner": "metasploit",
             "script": "auxiliary/admin/smb/samba_symlink_traversal"})[0]

    def test_nonexistent_still_rejected(self):
        """Folding must not turn the gate into a rubber stamp."""
        ok, _ = tc.validate_recommendation(
            {"scanner": "metasploit", "script": "exploit/unix/misc/not_a_module"})
        assert not ok
