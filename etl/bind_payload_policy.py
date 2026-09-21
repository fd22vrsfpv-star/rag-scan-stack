"""Bind payloads are third-party risk: prefer a callback, and never auto-approve.

WHY THIS EXISTS
---------------
A REVERSE (callback) payload makes the target dial out to an address we control.
Only we can receive it.

A BIND payload does the opposite: it opens a LISTENING PORT ON THE TARGET and
waits. That port is, for its lifetime, an unauthenticated command shell on
someone else's host. Anyone who can reach it gets it — another tenant, another
tester, the target's own users, whoever scans that range next. We do not control
who connects, we cannot tell after the fact who did, and the exposure outlives
our session if the process is not cleaned up.

That is a risk taken on the client's behalf, not ours, so a human decides it
every time. Hence two rules, applied the same way everywhere:

  1. `auto` prefers a callback. Bind is the fallback, used when a reverse payload
     genuinely cannot work (no reachable callback host) — not the default.
  2. A bind payload is NEVER auto-approved. A rule may approve a reverse exploit
     unattended; the same exploit resolving to bind must wait for an operator.

This mirrors etl/dos_overrides.py: one module shared by the approval sweep
(rag-api) and the execution gate (exploit-runner), so the policy means the same
thing in both places rather than being re-implemented and drifting.

NOTE this is about the PAYLOAD's connect direction, not about whether the
exploit is dangerous. A bind payload on a trivial exploit still opens the port.
"""
from typing import Optional

# `reviewed_by` written by the rule sweep. Anything else (operator:<name>, a bare
# operator id) is a human decision. See api.py _sweep_exploit_approval_rules
# ("rule:{rid}") vs the release/status endpoints ("operator:{x_operator}").
_RULE_PREFIX = "rule:"

REFUSAL = (
    "bind payload requires manual approval: it opens an unauthenticated "
    "listening shell on the target that anyone who can reach the port may use. "
    "Approve this exploit as an operator, or configure a callback host "
    "(msf.payload_config.callback_host) so a reverse payload can be used."
)


def is_bind_payload(payload: Optional[str] = None, style: Optional[str] = None) -> bool:
    """True if this payload/style opens a listener on the TARGET.

    Either signal is enough: the style as resolved by _build_exploit_options, or
    the payload module name itself (a custom payload may be passed with no style).
    """
    if str(style or "").strip().lower() == "bind":
        return True
    return "bind" in str(payload or "").strip().lower()


def approval_is_manual(reviewed_by: Optional[str]) -> bool:
    """True if a HUMAN approved this, rather than an approval rule.

    Fail closed: an unknown/empty reviewer is not treated as a human decision.
    """
    rb = str(reviewed_by or "").strip()
    if not rb:
        return False
    return not rb.lower().startswith(_RULE_PREFIX)


def bind_is_likely(cfg) -> bool:
    """Would this payload config resolve to a bind payload?

    Used by the approval sweep, which decides BEFORE the payload is chosen. It
    mirrors _build_exploit_options: an explicit bind style is bind; `auto` is
    bind only when no callback host is configured, because a reverse payload with
    nowhere to call back is downgraded to bind at execution time.

    `cfg` may be an MsfPayloadConfig or a plain dict; unknown shapes are treated
    as "possibly bind" so the sweep holds rather than approves.
    """
    def _get(name, default=""):
        if cfg is None:
            return default
        if isinstance(cfg, dict):
            return cfg.get(name, default)
        return getattr(cfg, name, default)

    style = str(_get("connect_style", "auto") or "auto").strip().lower()
    if style == "bind":
        return True
    if is_bind_payload(payload=_get("payload", "")):
        return True
    if style == "reverse":
        return False
    # auto: reverse is only viable with a reachable callback address
    return not str(_get("callback_host", "") or "").strip()
