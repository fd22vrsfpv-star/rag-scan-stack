"""Every custom-built service must bake a BUILD_VERSION stamp into its image.

WHY THIS EXISTS
---------------
PR #322 taught `rag-api` to distinguish the version its image was BUILT at
(`IMAGE_BUILD_VERSION`, baked at build time) from the version its container was
CREATED with (`BUILD_VERSION`, the docker-compose env). A container that was not
recreated after a version bump keeps the OLD env value while running current (or
stale) code; comparing the two is the only way that staleness is visible. That
mechanism only works if the stamp is actually baked, so this guard extends it to
EVERY service that builds from one of our own Dockerfiles.

For each service in docker-compose.yml with a `build:` block, we require BOTH:
  (a) its Dockerfile contains  ENV IMAGE_BUILD_VERSION=$BUILD_VERSION  , and
  (b) its compose `build.args` declares  BUILD_VERSION
...UNLESS the service is listed in STAMP_EXEMPT (permanent, third-party-base
images with no first-party code to stamp) or STAMP_DEBT (temporary, must shrink).

This RATCHETS: a newly added built service that lacks the stamp and is not
declared here fails BY NAME. Shrink the debt list; do not grow it.

Pure-file check: parses YAML + reads Dockerfiles. No DB, no containers, no node.
Skips cleanly when PyYAML or the compose file is absent.

Sabotage check: delete the `ENV IMAGE_BUILD_VERSION=$BUILD_VERSION` line from any
one stamped Dockerfile (e.g. app/embedder/Dockerfile) -> this test names it RED.
"""
import os

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML not installed")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
COMPOSE = os.path.join(REPO, "docker-compose.yml")

# The literal the reference implementation (app/rag-api/Dockerfile) bakes.
STAMP_LINE = "ENV IMAGE_BUILD_VERSION=$BUILD_VERSION"

# ── Permanent exemptions ────────────────────────────────────────────────────
# Services that BUILD but wrap a third-party base image and copy no first-party
# application code — the running artifact's version is the upstream tool's, not
# our BUILD_VERSION, so an IMAGE_BUILD_VERSION stamp would be meaningless.
STAMP_EXEMPT = {
    "zap": "third-party image (FROM ghcr.io/zaproxy/zaproxy:stable); only ZAP "
           "add-ons + a config script are copied, no first-party app code — the "
           "artifact version is ZAP's release.",
    "kong": "third-party API-gateway image (FROM kong:3.6); adds only CLI "
            "utilities, no first-party app code.",
    "sliver-server": "third-party Sliver C2 server binary downloaded from the "
                     "BishopFox release; only entrypoint.sh is copied — the "
                     "artifact version is Sliver's.",
    "host-helper": "optional/privileged host-networked profile, excluded from "
                   "clean-build rehearsals (CLAUDE.md installer isolation); not "
                   "part of the standard rebuilt stack.",
}

# ── Temporary debt ──────────────────────────────────────────────────────────
# Built services that SHOULD carry the stamp but do not yet. Each needs a reason.
# This ratchets: shrink it, never grow it without a stated reason.
STAMP_DEBT: dict[str, str] = {}


def _load_compose():
    if not os.path.exists(COMPOSE):
        pytest.skip("docker-compose.yml not present")
    with open(COMPOSE, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "services" not in data:
        pytest.skip("docker-compose.yml has no services block")
    return data


def _dockerfile_path(context, dockerfile):
    """Resolve the Dockerfile path the way `docker build` does: `dockerfile` is
    relative to `context`, `context` is relative to the compose file's dir."""
    ctx = os.path.normpath(os.path.join(REPO, context or "."))
    return os.path.normpath(os.path.join(ctx, dockerfile or "Dockerfile"))


def _build_services(compose):
    """Yield (name, dockerfile_path, has_build_version_arg) for build services."""
    for name, svc in compose["services"].items():
        if not isinstance(svc, dict) or "build" not in svc:
            continue
        build = svc["build"]
        if isinstance(build, str):
            context, dockerfile, args = build, "Dockerfile", None
        elif isinstance(build, dict):
            context = build.get("context", ".")
            dockerfile = build.get("dockerfile", "Dockerfile")
            args = build.get("args")
        else:
            continue
        if isinstance(args, dict):
            has_arg = "BUILD_VERSION" in args
        elif isinstance(args, list):
            has_arg = any(str(a).split("=", 1)[0].strip() == "BUILD_VERSION" for a in args)
        else:
            has_arg = False
        yield name, _dockerfile_path(context, dockerfile), has_arg


def test_stamp_lists_are_disjoint_and_named():
    """A service cannot be both exempt and debt, and every entry names a service
    that actually has a build block (a stale entry is itself a rot)."""
    overlap = set(STAMP_EXEMPT) & set(STAMP_DEBT)
    assert not overlap, f"services in both STAMP_EXEMPT and STAMP_DEBT: {sorted(overlap)}"
    compose = _load_compose()
    built = {n for n, _, _ in _build_services(compose)}
    stale = (set(STAMP_EXEMPT) | set(STAMP_DEBT)) - built
    assert not stale, (
        f"STAMP_EXEMPT/STAMP_DEBT name services with no build block "
        f"(delete them): {sorted(stale)}"
    )


def test_every_built_service_bakes_the_version_stamp():
    compose = _load_compose()
    services = list(_build_services(compose))
    assert services, "no build services found — parser or compose file is wrong"

    missing_env = []   # stamped-expectation services whose Dockerfile lacks the ENV
    missing_arg = []   # stamped-expectation services whose compose lacks build.arg
    undeclared = []    # services failing the rule and not in exempt/debt

    for name, dockerfile, has_arg in services:
        if name in STAMP_EXEMPT or name in STAMP_DEBT:
            continue
        if not os.path.exists(dockerfile):
            pytest.skip(f"Dockerfile for {name} not found at {dockerfile}")
        with open(dockerfile, encoding="utf-8") as fh:
            body = fh.read()
        has_env = STAMP_LINE in body
        if has_env and has_arg:
            continue
        undeclared.append(name)
        if not has_env:
            missing_env.append(f"{name} ({os.path.relpath(dockerfile, REPO)})")
        if not has_arg:
            missing_arg.append(name)

    msg = []
    if missing_env:
        msg.append(
            "Dockerfiles missing `%s`:\n  %s" % (STAMP_LINE, "\n  ".join(missing_env))
        )
    if missing_arg:
        msg.append(
            "compose build.args missing BUILD_VERSION:\n  %s" % "\n  ".join(missing_arg)
        )
    if undeclared:
        msg.append(
            "Add the stamp (see app/rag-api/Dockerfile) or declare these in "
            "STAMP_DEBT/STAMP_EXEMPT with a reason: %s" % sorted(set(undeclared))
        )
    assert not undeclared, "\n\n".join(msg)


def test_reference_service_is_stamped():
    """rag-api is the reference implementation — if IT is not detected as
    stamped, the detection logic is broken and every green result is vacuous."""
    compose = _load_compose()
    for name, dockerfile, has_arg in _build_services(compose):
        if name != "rag-api":
            continue
        with open(dockerfile, encoding="utf-8") as fh:
            body = fh.read()
        assert STAMP_LINE in body, "rag-api Dockerfile lost its IMAGE_BUILD_VERSION stamp"
        assert has_arg, "rag-api compose build.args lost BUILD_VERSION"
        return
    pytest.fail("rag-api build service not found — detection logic is broken")
