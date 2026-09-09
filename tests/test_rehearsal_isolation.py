"""A fresh-install rehearsal must not be able to reach the live stack.

Phases 6-10 of the installer were documented as "not rehearsable" because
`docker compose up` could not run beside a live stack. The reason mattered more
than the symptom: `container_name` and published ports are global to the daemon
and to the host, so a second stack does not merely fail to start — every
`docker exec rag-postgres` in the installer addresses the FIRST stack, and every
`curl localhost:8000/health` reports the FIRST stack's health as the new
install's result. A rehearsal that applies its schema to the production database
is worse than no rehearsal at all.

Three things now make it safe, and each is pinned here:

  1. docker-compose.rehearsal.yml unsets every `container_name`, resets every
     published port, replaces the external `agents_net` with a project-local
     one, and drops the docker.sock mounts.
  2. scripts/lib/compose-target.sh resolves containers by (compose project,
     compose service), so the installer can only talk to the stack it started.
  3. scripts/setup.sh and scripts/post-install-check.sh use those helpers
     instead of literal names and ports.

Every check is static: it reads the compose files and the shell scripts. No
docker, no running stack, no imports of project code — so it works on a bare
checkout and in CI.

    pytest tests/test_rehearsal_isolation.py -q
"""

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip(
    "yaml", reason="pyyaml not installed — cannot parse the compose files"
)

REPO = Path(__file__).resolve().parents[1]
BASE_FILE = REPO / "docker-compose.yml"
REHEARSAL_FILE = REPO / "docker-compose.rehearsal.yml"
LIB_FILE = REPO / "scripts" / "lib" / "compose-target.sh"
SETUP_FILE = REPO / "scripts" / "setup.sh"
CHECK_FILE = REPO / "scripts" / "post-install-check.sh"
DRIVER_FILE = REPO / "scripts" / "rehearse-install.sh"


# ── Loading ────────────────────────────────────────────────────────────────
# The rehearsal file uses compose's merge tags (`!reset`, `!override`), which
# safe_load rejects as unknown. Keep the tag NAME on the loaded value: several
# checks below assert not just the value but that the right tag produced it —
# `ports: []` and `ports: !reset []` mean completely different things to
# compose (append nothing vs. remove everything).
class _TagPreservingLoader(yaml.SafeLoader):
    pass


class Tagged:
    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"{self.tag} {self.value!r}"


def _tagged(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return Tagged(f"!{tag_suffix}", value)


_TagPreservingLoader.add_multi_constructor("!", _tagged)


def _load(path):
    if not path.exists():
        pytest.fail(f"{path.relative_to(REPO)} is missing")
    with path.open() as handle:
        return yaml.load(handle, Loader=_TagPreservingLoader)


@pytest.fixture(scope="module")
def base():
    return _load(BASE_FILE)["services"]


@pytest.fixture(scope="module")
def rehearsal():
    return _load(REHEARSAL_FILE)


def _volumes(cfg):
    """Volume entries as strings. Long-form (dict) mounts are stringified so a
    sock mount cannot hide behind the other syntax."""
    out = []
    for entry in cfg.get("volumes") or []:
        out.append(entry if isinstance(entry, str) else str(entry))
    return out


def _mounts_sock(cfg):
    return any("/var/run/docker.sock" in v for v in _volumes(cfg))


# ── 1. Names and ports ─────────────────────────────────────────────────────
def test_every_container_name_is_unset(base, rehearsal):
    """A surviving container_name means the rehearsal stack cannot start —
    and that the installer's exec calls would land on the live stack.

    This is the ratchet: add a service with a container_name and this test
    names it until docker-compose.rehearsal.yml resets it too.
    """
    over = rehearsal["services"]
    missing = []
    for name, cfg in base.items():
        if not (cfg or {}).get("container_name"):
            continue
        entry = over.get(name) or {}
        reset = entry.get("container_name")
        if not isinstance(reset, Tagged) or reset.tag != "!reset":
            missing.append(name)
    assert not missing, (
        "these services set container_name but are not reset in "
        "docker-compose.rehearsal.yml, so a rehearsal would collide with the "
        "live stack (add `container_name: !reset null`):\n  "
        + "\n  ".join(sorted(missing))
    )


def test_every_published_port_is_reset(base, rehearsal):
    """A surviving published port means `up` fails on "address already in
    use" — or worse, a health check silently probes the live stack."""
    over = rehearsal["services"]
    missing = []
    for name, cfg in base.items():
        if not (cfg or {}).get("ports"):
            continue
        entry = over.get(name) or {}
        reset = entry.get("ports")
        if not isinstance(reset, Tagged) or reset.tag != "!reset":
            missing.append(name)
    assert not missing, (
        "these services publish host ports but are not reset in "
        "docker-compose.rehearsal.yml (add `ports: !reset []`):\n  "
        + "\n  ".join(sorted(missing))
    )


def test_rehearsal_declares_no_service_the_base_file_lacks(base, rehearsal):
    """A typo'd service name in the override is silently inert: compose merges
    it in as a NEW service with no image, and the service it was meant to
    isolate keeps its container_name."""
    unknown = sorted(set(rehearsal["services"]) - set(base))
    assert not unknown, (
        "docker-compose.rehearsal.yml overrides services that do not exist in "
        "docker-compose.yml (a rename or a typo — the override does nothing):\n  "
        + "\n  ".join(unknown)
    )


# ── 2. The shared network ──────────────────────────────────────────────────
def test_agents_net_is_project_local(rehearsal):
    """`agents_net` is `external: true` in the base file, so both stacks would
    join the SAME bridge and the rehearsal's containers would claim the
    `rag-postgres` and `embedder` aliases beside the live ones."""
    nets = rehearsal.get("networks") or {}
    agents = nets.get("agents_net")
    assert agents is not None, (
        "docker-compose.rehearsal.yml does not override agents_net; the base "
        "file declares it `external: true`, so a rehearsal would attach to the "
        "LIVE network"
    )
    assert isinstance(agents, Tagged) and agents.tag == "!override", (
        "agents_net must be overridden with `!override` — a plain mapping is "
        "MERGED with the base one, which keeps `external: true`"
    )
    assert not agents.value.get("external"), "the overridden agents_net is still external"


# ── 3. The docker socket ───────────────────────────────────────────────────
def test_docker_sock_mounts_are_dropped(base, rehearsal):
    """A rehearsal container with the socket can exec into the LIVE stack.

    These services enumerate containers by NAME, and in a rehearsal those
    names belong to the live stack: container-logs would stream the live
    containers' logs into the rehearsal database, and node-manager acts on
    them directly. Renaming the rehearsal's own containers does not help —
    only removing the socket does.
    """
    over = rehearsal["services"]
    offenders = []
    for name, cfg in base.items():
        if not _mounts_sock(cfg or {}):
            continue
        entry = over.get(name) or {}
        vols = entry.get("volumes")
        if not isinstance(vols, Tagged) or vols.tag != "!override":
            offenders.append(f"{name}: no `volumes: !override` (a plain list is APPENDED, "
                             f"so the socket mount survives)")
        elif any("/var/run/docker.sock" in str(v) for v in vols.value):
            offenders.append(f"{name}: the override still mounts the socket")
    assert not offenders, "docker.sock reaches the live stack:\n  " + "\n  ".join(offenders)


def test_sock_overrides_keep_every_other_mount(base, rehearsal):
    """`!override` REPLACES the list, so dropping the socket means retyping the
    rest — and a mount lost that way (certs, db-config.json, ./etl) breaks the
    rehearsal in a way that looks like a code defect, not a compose one."""
    over = rehearsal["services"]
    lost = []
    for name, cfg in base.items():
        if not _mounts_sock(cfg or {}):
            continue
        entry = over.get(name) or {}
        vols = entry.get("volumes")
        if not isinstance(vols, Tagged):
            continue  # reported by the test above
        kept = {str(v) for v in vols.value}
        for want in _volumes(cfg or {}):
            if "/var/run/docker.sock" in want:
                continue
            if want not in kept:
                lost.append(f"{name}: {want}")
    assert not lost, (
        "the rehearsal override drops mounts that are not the docker socket:\n  "
        + "\n  ".join(lost)
    )


# ── 4. The installer's addressing ──────────────────────────────────────────
# Literal container names and literal host ports are the defect this whole
# change exists to remove, so they are forbidden in the two scripts that run
# against a freshly started stack.
#
# Each allowance is a genuinely host-scoped call, not debt:
HOST_SCOPED_PORTS = {
    # Ollama runs natively on the HOST in the supported topology (the container
    # is behind the `gpu` profile). Phase 1 and Phase 8 check the host daemon,
    # which is correct: a rehearsal shares the host's ollama and should.
    "11434",
}
# `docker exec "$VAR"` is fine — the variable holds an id resolved through
# ct_cid. Only a BARE LITERAL name is a cross-project hazard.
LITERAL_EXEC = re.compile(r"\bdocker\s+exec\b(?:\s+-[^\s]+(?:\s+[^\s]+)?)*\s+([a-zA-Z][\w.-]*)")
CURL_LOCALHOST = re.compile(r"curl[^\n#]*?(?:localhost|127\.0\.0\.1):(\d+)")


def _code_lines(path):
    """Source with comment-only lines and trailing comments removed: a defect
    named in a comment must not satisfy — or trip — a guard. The toolchain
    guard added with the last rehearsal PASSED its first sabotage precisely
    because it matched the word inside its own explanatory comment.
    """
    out = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append((raw.split("#", 1)[0]) if " #" in raw else raw)
    return out


@pytest.mark.parametrize("script", [SETUP_FILE, CHECK_FILE], ids=lambda p: p.name)
def test_installer_does_not_exec_literal_container_names(script):
    hits = []
    for line in _code_lines(script):
        for match in LITERAL_EXEC.finditer(line):
            hits.append(f"{script.name}: docker exec {match.group(1)} -> {line.strip()[:90]}")
    assert not hits, (
        "these call sites address a container by its GLOBAL name, so under a "
        "second compose project they reach the live stack. Use ct_exec "
        "(scripts/lib/compose-target.sh), which resolves by project+service:\n  "
        + "\n  ".join(hits)
    )


@pytest.mark.parametrize("script", [SETUP_FILE, CHECK_FILE], ids=lambda p: p.name)
def test_installer_does_not_probe_literal_host_ports(script):
    hits = []
    for line in _code_lines(script):
        for match in CURL_LOCALHOST.finditer(line):
            if match.group(1) in HOST_SCOPED_PORTS:
                continue
            hits.append(f"{script.name}:{match.group(1)} -> {line.strip()[:90]}")
    assert not hits, (
        "these probes use a published HOST port, which belongs to whichever "
        "stack claimed it first — a rehearsal would report the live stack's "
        "health as its own. Use ct_curl / ct_http_code / ct_hostport:\n  "
        + "\n  ".join(hits)
    )


# A `.` or `source` statement, not a mention. The first version of this guard
# asserted the PATH appeared anywhere in the file and passed its sabotage,
# because both scripts explain the mechanism in a comment that names the file —
# the identical mistake the toolchain guard made in the previous rehearsal.
SOURCES_LIB = re.compile(r"^\s*(?:\.|source)\s+\S*compose-target\.sh", re.M)


@pytest.mark.parametrize("script", [SETUP_FILE, CHECK_FILE], ids=lambda p: p.name)
def test_installer_sources_the_helper(script):
    code = "\n".join(_code_lines(script))
    assert SOURCES_LIB.search(code), (
        f"{script.name} has no `. .../compose-target.sh` statement, so every "
        "ct_* helper it calls would be an unbound command at runtime — which "
        "`bash -n` passes and a healthy container never reveals"
    )


def test_helper_defines_what_the_scripts_call():
    """A missing helper is a runtime `command not found` that `bash -n` passes
    and a container health check never sees — the same class of defect as the
    f-string placeholder that made every recommendations query raise NameError.
    """
    lib = LIB_FILE.read_text()
    defined = set(re.findall(r"^(ct_[a-z_]+)\(\)", lib, re.M))
    called = set()
    for script in (SETUP_FILE, CHECK_FILE):
        called |= set(re.findall(r"\b(ct_[a-z_]+)\b", script.read_text()))
    missing = sorted(called - defined)
    assert not missing, (
        "the installer calls helpers that scripts/lib/compose-target.sh does "
        "not define:\n  " + "\n  ".join(missing)
    )


# ── 5. The driver ──────────────────────────────────────────────────────────
def test_driver_never_enables_the_optional_profile():
    """`host-helper` lives behind the `optional` profile and is
    `privileged: true`, `network_mode: host`, and mounts /etc/systemd/system.
    Two stacks writing host systemd units is not a rehearsal, it is an outage.
    """
    text = "\n".join(_code_lines(DRIVER_FILE))
    assert "--profile optional" not in text, (
        "scripts/rehearse-install.sh enables the `optional` profile, which "
        "starts host-helper (privileged, host network, writes host systemd units)"
    )


def test_driver_layers_the_isolation_override():
    text = DRIVER_FILE.read_text()
    assert "--rehearsal" in text, (
        "the driver does not pass --rehearsal to setup.sh, so the install would "
        "use the base compose file and collide with the live stack"
    )
    assert "COMPOSE_PROJECT_NAME" in text, (
        "the driver does not set COMPOSE_PROJECT_NAME, so compose would reuse "
        "the live project and RECREATE its containers"
    )


def test_setup_refuses_rehearsal_without_the_override_file():
    """If --rehearsal silently degraded to the base compose file, the install
    would claim the live stack's container names — the exact outcome the flag
    exists to prevent. It must fail closed."""
    text = SETUP_FILE.read_text()
    block = re.search(
        r'if \[ "\$REHEARSAL" = true \];.*?\nfi', text, re.S
    )
    assert block, "setup.sh has no --rehearsal handling block"
    assert "exit 1" in block.group(0), (
        "setup.sh does not exit when --rehearsal is passed but "
        "docker-compose.rehearsal.yml is missing"
    )
