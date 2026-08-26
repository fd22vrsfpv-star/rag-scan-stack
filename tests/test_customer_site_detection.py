"""Customer-hosted-site detection match functions.

Run on demand:

    pytest tests/test_customer_site_detection.py -v

WHY THIS EXISTS
---------------
We host customers' live sites on our shared domains (e.g. *-live.convio.net).
Scanning them is out of authorization. `check_customer_hosted_cert` /
`check_customer_hosted_cname` (app/rag-api/rule_engine.py) flag them from recon
data by comparing registrable domains. Pins the high-precision behaviour:

  * a host whose TLS cert CN/SAN is a DIFFERENT registrable domain is flagged,
    and our own wildcard cert (*.blackbaud.com on x.blackbaud.com) is NOT;
  * an IP host is never flagged (fail closed — no registrable domain);
  * a CNAME crossing registrable domains flags, same-domain does not.

Runs the REAL functions inside the rag-api container; skips if unreachable.
"""
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(REPO, "app", "rag-api", "rule_engine.py")


def _run(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return f"__ERR__ {out.stderr.strip()[-800:]}"
    return out.stdout


@pytest.fixture(scope="module")
def container():
    if _run("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


@pytest.mark.unit
def test_functions_registered():
    src = open(MODULE).read()
    assert "def check_customer_hosted_cert" in src
    assert "def check_customer_hosted_cname" in src
    assert '"check_customer_hosted_cert": check_customer_hosted_cert' in src
    assert '"check_customer_hosted_cname": check_customer_hosted_cname' in src


def test_cert_and_cname_signals(container):
    out = _run(r"""
import rule_engine as R
# 1. cert for a DIFFERENT registrable domain -> customer site
r1 = {'target':'hopeli-live.convio.net',
      'data':{'subject_cn':'connect.hopeoflifeintl.org',
              'subject_an':['connect.hopeoflifeintl.org']}}
a = R.check_customer_hosted_cert(r1, {})
# 2. our own wildcard cert -> NOT a customer site
r2 = {'target':'kb.blackbaud.com',
      'data':{'subject_cn':'*.blackbaud.com','subject_an':['*.blackbaud.com','blackbaud.com']}}
b = R.check_customer_hosted_cert(r2, {})
# 3. IP host -> never flagged
r3 = {'target':'74.123.1.1','data':{'subject_cn':'x.customer.org'}}
c = R.check_customer_hosted_cert(r3, {})
# 4. CNAME crossing registrable domains -> customer alias
r4 = {'target':'x.convio.net','data':{'record':['y.customer.org']}}
d = R.check_customer_hosted_cname(r4, {})
# 5. CNAME within our domain -> not flagged
r5 = {'target':'x.convio.net','data':{'record':['y-live.convio.net']}}
e = R.check_customer_hosted_cname(r5, {})
print(repr([a, r1.get('owner_domain'), r1.get('signal'), b, c,
            d, r4.get('owner_domain'), e]))
""")
    assert out and not out.startswith("__ERR__"), out
    val = eval(out.strip().splitlines()[-1])
    a, owner, signal, b, c, d, cname_owner, e = val
    assert a is True and owner == "hopeoflifeintl.org" and signal == "tls_cert_mismatch"
    assert b is False       # our wildcard cert
    assert c is False       # IP host
    assert d is True and cname_owner == "customer.org"
    assert e is False       # same-domain cname


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
