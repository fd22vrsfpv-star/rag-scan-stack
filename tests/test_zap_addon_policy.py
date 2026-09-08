"""ZAP add-ons this stack deliberately does not install.

Run on demand:

    pytest tests/test_zap_addon_policy.py -v

WHY THIS EXISTS
---------------
`wappalyzer` ("Technology Detection") is the single cause of ZAP's memory
exhaustion here, and the evidence is unusually clean: 327
`Passive Scan rule ... took N seconds` warnings against demo.testfire.net, EVERY
ONE naming the same rule — "Tech Detection Passive Scanner" — at 40 to 110
seconds per message across 30 passive threads, including 110s on an 8.8 KB JPEG.
ZAP then grew to 11.98 GiB and died mid-scan.

Three things that did NOT fix it, recorded so they are not retried:

* Raising the heap 3g -> 8g and the container limit 6g -> 12g. ZAP filled the
  new ceiling and died at the same point. The growth is unbounded, not large.
* `pscan.disableScanners`. The add-on registers the scanner directly as a raw
  `PassiveScanner`, so it has no rule id and never appears in
  `pscan/view/scanners` — 70 rules listed, none matching "tech". The API even
  returns `{"Result":"OK"}` for an id it has never heard of.
* Pausing passive scanning for the active scan. Real, but partial: the rule
  dominates the SPIDER phase, which that pause deliberately leaves enabled.

The line is easy to re-add — it looks like a capability, and its cost is not
visible from the line itself. This guard is the reason the comment above it
survives.

Static — no ZAP needed, runs in CI.

Sabotage check: put `wappalyzer` back in zap/addons.txt -> RED.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ADDONS = os.path.join(REPO, "zap", "addons.txt")

#: id -> why it is excluded. An entry here must never appear in addons.txt.
EXCLUDED_ADDONS = {
    "wappalyzer": (
        "Technology Detection — its passive rule took 40-110s per message and "
        "drove ZAP to 11.98 GiB. Coverage is unaffected: WSTG INFO-08/09 are "
        "credited from whatweb/httpx evidence, not from this rule."
    ),
}


def _declared_addons():
    if not os.path.exists(ADDONS):
        pytest.skip("zap/addons.txt not present")
    out = []
    for line in open(ADDONS, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.split()[0])
    return out


def test_addons_file_is_parseable_and_not_empty():
    """Otherwise every assertion below passes for the wrong reason."""
    addons = _declared_addons()
    assert len(addons) >= 5, (
        f"only {len(addons)} add-on(s) parsed from addons.txt — the format "
        "changed and the exclusion check below is now vacuous"
    )
    for a in addons:
        assert re.fullmatch(r"[A-Za-z0-9_-]+", a), f"unexpected add-on token {a!r}"


@pytest.mark.parametrize("addon_id", sorted(EXCLUDED_ADDONS))
def test_excluded_addon_is_not_installed_at_build(addon_id):
    assert addon_id not in _declared_addons(), (
        f"zap/addons.txt installs {addon_id!r}, which this stack excludes on "
        f"purpose: {EXCLUDED_ADDONS[addon_id]}"
    )


def test_the_exclusion_reason_is_written_where_someone_would_re_add_it():
    """A bare deletion invites a well-meaning re-add.

    The reasoning has to live in the file being edited, not only in git history
    or a PR nobody will find.
    """
    body = open(ADDONS, encoding="utf-8").read()
    for addon_id in EXCLUDED_ADDONS:
        assert addon_id in body, (
            f"{addon_id} is absent from addons.txt with no comment explaining "
            "why — the next person adds it back and re-derives the failure from "
            "a dead scan"
        )
    assert "Tech Detection Passive Scanner" in body, (
        "the specific rule name is not recorded, so a reader cannot match the "
        "comment to what they see in zap.log"
    )
