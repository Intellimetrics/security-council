"""Orchestrator-owned kernel fence for code-executing arms (M-V4a, R6).

The fix lane runs untrusted code by design (vendor agent edits files AND runs
the project's test suite). Per the R6 safety review, the security boundary is
NOT the vendor's own sandbox (which differs by CLI/flags and whose in-process
edit tools may bypass it) but a bubblewrap (`bwrap`) sandbox the orchestrator
wraps the whole vendor process in:

- read-only bind of system dirs (`/usr`, `/bin`, `/lib*`, `/etc` ...),
- read-write bind of ONLY the scratch work copy,
- a tmpfs `HOME` (the real `~/.ssh`, `~/.aws`, `~/.claude`, `~/.codex` are
  unreachable — closes vendor-config persistence, MV4-11),
- `--unshare-all` (no network for tool subprocesses), `--die-with-parent`
  (a timed-out agent's grandchildren die with it — MV4-13), `--new-session`.

Because the fence is orchestrator-owned it is **deterministic and certifiable
with no vendor spend**: `certify()` runs a canary INSIDE the exact fence config
and refuses to mint a `FenceCertificate` unless the canary provably cannot
write outside the work copy, read `$HOME`, or reach the network. The fix arm
requires a live certificate to run (fail-closed) — no config key can forge one.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

FENCE_TTL_SECONDS = 3600
_RO_SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")
# B1 relaxed posture: neutral in-namespace roots for the vendor runtime, so a
# bound binary never makes the real HOME path exist (the HOME_VISIBLE breach).
_VENDOR_BIN = "/opt/sc-vendor/bin"
_VENDOR_NODE = "/opt/sc-node"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def resolve_runtime(command: str) -> "RuntimePlan | None":
    """How to make `command` runnable at a NEUTRAL path inside the fence.

    Two shapes, both verified live 2026-09-01 launching under bwrap with the
    real HOME absent:
    - a self-contained ELF (this host's `claude`): bind the single file at
      `/opt/sc-vendor/bin/<command>` (its `ldd` closure is `/lib*`, already
      fence-bound).
    - a Node script (`#!/usr/bin/env node`, this host's `codex`): bind the whole
      Node version root at `/opt/sc-node` — it carries the `node` interpreter,
      the `bin/<command>` shim and the global `node_modules` package tree.

    Returns None (arm refuses) if the command cannot be resolved to either shape,
    so an unrecognised runtime is an honest `available()` failure, never a
    silent unfenced run.
    """
    p = shutil.which(command)
    if not p:
        return None
    real = Path(p).resolve()
    if _is_elf(real):
        sandbox = f"{_VENDOR_BIN}/{command}"
        return RuntimePlan(
            command=command, binds=((str(real), sandbox),), path_dirs=(_VENDOR_BIN,),
            provenance={"command": command, "kind": "elf", "host_path": str(real),
                        "sha256": _sha256_file(real)})
    # a script — find its interpreter; support the Node shape we ship
    try:
        first = real.read_bytes()[:256].split(b"\n", 1)[0]
    except OSError:
        return None
    if b"node" not in first:
        return None
    node = shutil.which("node")
    if not node:
        return None
    node_real = Path(node).resolve()
    node_root = node_real.parent.parent          # <version>/bin/node -> <version>
    # the command's shim must live inside the node root, or binding the root
    # would not expose it (a locally-installed script would need its own bind)
    if not str(real).startswith(str(node_root).rstrip("/") + "/"):
        return None
    return RuntimePlan(
        command=command, binds=((str(node_root), _VENDOR_NODE),),
        path_dirs=(f"{_VENDOR_NODE}/bin",),
        provenance={"command": command, "kind": "node", "host_path": str(real),
                    "node_root": str(node_root), "node_sha256": _sha256_file(node_real)})


@dataclass(frozen=True)
class RuntimePlan:
    """How to expose one vendor command inside the fence at a neutral path.

    `binds` are `(host, sandbox)` ro-bind pairs for `bwrap_argv(runtime_binds=)`;
    `path_dirs` go on the fenced `PATH`; `provenance` (kind + host path + hashes)
    is recorded in the manifest so a run says exactly which runtime it launched.
    """
    command: str
    binds: tuple[tuple[str, str], ...]
    path_dirs: tuple[str, ...]
    provenance: dict = field(default_factory=dict)


def reachable_in_fence(cmd: str) -> tuple[bool, str]:
    """Whether `cmd` resolves to a path the STRICT (no-network) fence binds.

    R10 (verified live): the strict fence binds only `_RO_SYSTEM_DIRS`, but the
    vendor CLIs live outside them — `codex` under `~/.nvm/versions/node/*/bin`,
    `claude`/`agy` under `~/.local/bin` — so a fenced run of one produced
    `bwrap: execvp codex: No such file or directory` minutes in. Checking up
    front turns that into an honest `available()` refusal. The RELAXED posture
    (B1) instead binds the runtime at a neutral path via `resolve_runtime`;
    that path does not consult this function.
    """
    p = shutil.which(cmd)
    if not p:
        return False, f"{cmd} not on PATH"
    real = str(Path(p).resolve())
    if any(real == d or real.startswith(d.rstrip("/") + "/") for d in _RO_SYSTEM_DIRS):
        return True, f"fence binds {real}"
    return False, (f"{cmd} resolves to {real}, which the fence does not bind "
                   f"(binds only {', '.join(_RO_SYSTEM_DIRS)}) — it would be "
                   f"invisible inside the namespace")


def bwrap_available() -> tuple[bool, str]:
    p = shutil.which("bwrap")
    if not p:
        return False, "bwrap (bubblewrap) not on PATH — the fix lane needs it"
    try:
        r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=15)
        return (r.returncode == 0), (r.stdout or r.stderr).strip()[:60]
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"bwrap --version failed: {e}"


def bwrap_argv(*, work_dir: Path, home: Path, allow_network: bool = False,
               runtime_binds: tuple[tuple[str, str], ...] = (),
               writable_binds: tuple[tuple[str, str], ...] = ()) -> list[str]:
    """The bwrap wrapper argv (prefix a command after `--`). Writable: only
    `work_dir` and a tmpfs `home`. Everything else ro or absent.

    `runtime_binds` (B1, relaxed posture): each `(host_path, sandbox_path)`
    ro-binds a vendor runtime file/tree at a NEUTRAL in-namespace path
    (`sandbox_path`, e.g. `/opt/sc-vendor/...`), never at its real location.
    Binding a vendor binary in place under `~/.local`/`~/.nvm` would make the
    real `$HOME` path exist inside the namespace, which the canary's
    `HOME_VISIBLE` probe correctly treats as a breach (verified live 2026-09-01:
    in-place bind ⇒ breach, neutral bind ⇒ home absent). The pairs are part of
    the hashed fence shape, so a vendor version bump re-certifies.
    """
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup-try", "--proc", "/proc", "--dev", "/dev"]
    if not allow_network:
        argv += ["--unshare-net"]
    for d in _RO_SYSTEM_DIRS:
        if Path(d).exists():
            argv += ["--ro-bind", d, d]
    if allow_network:
        # B1 (live-found 2026-09-01): with the net shared but `/etc/resolv.conf`
        # a symlink into `/run` (systemd-resolved: -> stub-resolv.conf), the
        # target is absent in the fence and DNS fails ("failed to lookup address
        # information"). Bind the real resolver file at ITS OWN resolved path so
        # the `/etc/resolv.conf` symlink (brought by the /etc ro-bind) resolves —
        # bwrap cannot mount over the dangling symlink itself. The stub
        # nameserver 127.0.0.53 is reachable because the net namespace is shared.
        try:
            real_resolv = os.path.realpath("/etc/resolv.conf")
            if real_resolv != "/etc/resolv.conf" and Path(real_resolv).is_file():
                argv += ["--ro-bind", real_resolv, real_resolv]
            elif Path("/etc/resolv.conf").is_file():   # not a symlink: bind in place
                argv += ["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]
        except OSError:
            pass
    for host_path, sandbox_path in runtime_binds:
        argv += ["--ro-bind", str(host_path), str(sandbox_path)]
    argv += ["--tmpfs", "/tmp",
             "--bind", str(work_dir), str(work_dir),
             "--tmpfs", str(home),
             "--setenv", "HOME", str(home)]
    # writable binds (B1): an orchestrator-prepared, ephemeral dir mounted rw at
    # a neutral path — the vendor's config HOME carrying at most a COPIED
    # credential. It is under the orchestrator's scratch root, never the real
    # home or the original tree, so it does not widen the escape surface the
    # canary certifies (write-outside-work stays blocked). Mounted AFTER the
    # tmpfs home so a nested target (e.g. under HOME) lands on the tmpfs.
    for host_path, sandbox_path in writable_binds:
        argv += ["--bind", str(host_path), str(sandbox_path)]
    argv += ["--chdir", str(work_dir)]
    return argv


@dataclass(frozen=True)
class FenceCertificate:
    """Proof a fence config passed its canary. Only `certify()` mints one; the
    fix arm refuses to run without a live (unexpired) certificate whose config
    hash matches the fence it is about to use."""
    config_hash: str
    bwrap_version: str
    host: str
    minted_at: float
    canary: dict = field(default_factory=dict)

    def live(self, *, now: float | None = None) -> bool:
        return (now or time.time()) - self.minted_at <= FENCE_TTL_SECONDS


def _config_hash(argv_template: list[str], *, ephemeral: tuple[str, ...] = ()) -> str:
    """Hash the fence SHAPE — flags and bind structure — not the ephemeral paths.

    R11 recorded two defects here: the ephemeral filter was `startswith("/tmp/")`,
    so it was TMPDIR-dependent, and it stripped any path arg, so different bind
    scopes could hash identically. The caller now names exactly which values are
    ephemeral (its work dir and home); everything else — including every bind
    target — is part of the shape.
    """
    eph = set(ephemeral)
    shape = [a for a in argv_template if a not in eph]
    return hashlib.sha256("\x00".join(shape).encode()).hexdigest()[:16]


def config_hash_for(*, work_dir: Path, home: Path, allow_network: bool = False,
                    runtime_binds: tuple[tuple[str, str], ...] = (),
                    writable_binds: tuple[tuple[str, str], ...] = ()) -> str:
    """The hash a run's fence WILL have — compare it to the certificate's."""
    argv = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network,
                      runtime_binds=runtime_binds, writable_binds=writable_binds)
    # the writable bind's HOST path is ephemeral (a per-run scratch dir); its
    # SANDBOX path is the certified shape, so strip only the host side.
    eph = (str(work_dir), str(home), *(str(h) for h, _ in writable_binds))
    return _config_hash(argv, ephemeral=eph)


def verify_certificate(cert: "FenceCertificate | None", *, work_dir: Path, home: Path,
                       allow_network: bool = False,
                       runtime_binds: tuple[tuple[str, str], ...] = (),
                       writable_binds: tuple[tuple[str, str], ...] = (),
                       now: float | None = None) -> str | None:
    """None if `cert` covers exactly this fence; otherwise why it does not.

    R11: `fix.py` checked only `cert is None` — `cert.live()` and
    `cert.config_hash` were never consulted, contradicting the guarantee in the
    dataclass docstring. This is the check that makes the certificate mean
    something.
    """
    if cert is None:
        return "no certificate"
    if not cert.live(now=now):
        return "certificate expired"
    want = config_hash_for(work_dir=work_dir, home=home, allow_network=allow_network,
                           runtime_binds=runtime_binds, writable_binds=writable_binds)
    if cert.config_hash != want:
        return f"certificate is for a different fence (hash {cert.config_hash} != {want})"
    return None


def run_in_fence(cmd: list[str], *, work_dir: Path, home: Path, timeout: int = 3600,
                 allow_network: bool = False,
                 runtime_binds: tuple[tuple[str, str], ...] = (),
                 writable_binds: tuple[tuple[str, str], ...] = (), env: dict | None = None):
    from . import proc
    argv = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network,
                      runtime_binds=runtime_binds, writable_binds=writable_binds) + ["--", *cmd]
    return proc.run_command(argv, timeout=timeout, cwd=str(work_dir), env=env,
                            success_exit_codes=tuple(range(0, 256)))


def certify(*, work_dir: Path, original: Path, home: Path | None = None,
            allow_network: bool = False,
            runtime_binds: tuple[tuple[str, str], ...] = (),
            writable_binds: tuple[tuple[str, str], ...] = (),
            now: float | None = None) -> tuple[FenceCertificate | None, dict]:
    """Run the canary inside THE fence config the run will use; mint a
    certificate only if every escape is provably blocked AND every positive
    control fired. Returns (cert|None, canary_report).

    R11 recorded that the canary was built with the DEFAULT posture and its own
    home, so it never tested what the run would do — `home` and `allow_network`
    are now the run's own. It also recorded that the probes had no positive
    control: reading `~/.ssh/id_rsa` and `getent hosts` both fail benignly on a
    host lacking either, so the canary could "pass" without proving anything.
    Each escape probe is now paired with a control that must SUCCEED.
    """
    ok_bw, ver = bwrap_available()
    own_home = home is None
    home = home or (work_dir.parent / "sc-fence-home")
    argv_template = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network,
                               runtime_binds=runtime_binds, writable_binds=writable_binds)
    report: dict = {"bwrap": ver, "bwrap_ok": ok_bw, "allow_network": allow_network,
                    # B1: state the network posture the certificate attests. An
                    # open network is a DECLARED relaxation, not a passed check —
                    # record it as waived so the report never reads like the
                    # unshared canary passed a network-isolation probe.
                    "network": "open:waived_by_posture" if allow_network else "unshared",
                    "runtime_binds": [list(b) for b in runtime_binds],
                    "writable_binds": [list(b) for b in writable_binds]}
    if not ok_bw:
        report["refused"] = "bwrap unavailable"
        return None, report

    # R20-FENCE-01: a UNIQUE canary name, never the fixed `.sc-canary`. The old
    # name could collide with a real file already in the target — which this
    # "read-only" probe then DELETED (and mis-flagged as a breach). A random
    # per-call name cannot pre-exist, so a hit is unambiguously our probe and we
    # only ever unlink what we created.
    canary_target = original / f".sc-canary-{secrets.token_hex(8)}"
    real_home = str(Path.home())
    # R20-FENCE-02: the probe interpolated user-controlled paths (the target,
    # the real home) into a `sh -c` string UNQUOTED — a path with a space or a
    # shell metacharacter could make the WROTE_ORIGINAL / HOME_VISIBLE escape
    # probes test the wrong thing (or nothing) while the positive controls still
    # printed, minting a certificate that never proved the escapes were blocked.
    # Paths are now POSITIONAL args ($1 work dir, $2 canary target, $3 real home)
    # and every use is quoted, so no path content can reshape the script.
    # B1: when the network is declared open, DNS must actually resolve inside
    # the fence, or the vendor agent hangs reconnecting (live-found). Prove the
    # resolver is wired with a POSITIVE control that needs no external call —
    # resolv.conf present with a nameserver — so a broken relaxed fence refuses
    # to certify instead of hanging at run time.
    dns_probe = ('( grep -q "^nameserver" /etc/resolv.conf 2>/dev/null && echo DNS_OK ); '
                 if allow_network else "")
    probe = (
        # positive controls — these MUST print, or the probe did not really run
        '( [ -d /usr ] && echo USR_OK ); '
        '( touch "$1"/.sc-work-write 2>/dev/null && echo WORK_WRITE_OK ); '
        + dns_probe +
        # escapes — these must NOT print
        '( touch "$2" 2>/dev/null && echo WROTE_ORIGINAL ); '
        # the real home must not merely be unreadable, it must not EXIST in the namespace
        '( [ -e "$3" ] && echo HOME_VISIBLE ); '
        # with the network unshared only `lo` exists; any other interface is a breach
        "( awk -F: 'NR>2{print $1}' /proc/net/dev 2>/dev/null | tr -d ' ' "
        "| grep -qv '^lo$' && echo NET_VISIBLE ); "
        "echo CANARY_DONE")
    probe_argv = ["/bin/sh", "-c", probe, "sc-canary",
                  str(work_dir), str(canary_target), real_home]
    # best-effort: a strict-posture home is a real host tmp dir; a relaxed
    # posture may pass a neutral in-namespace path (e.g. /sc-home) the tmpfs
    # mount creates on its own, which is not writable on the host.
    try:
        home.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    try:
        r = run_in_fence(probe_argv, work_dir=work_dir, home=home,
                         allow_network=allow_network, runtime_binds=runtime_binds,
                         writable_binds=writable_binds, timeout=60)
    finally:
        if own_home:
            shutil.rmtree(home, ignore_errors=True)
        (work_dir / ".sc-work-write").unlink(missing_ok=True)
    out = (r.stdout or "") + (r.stderr or "")
    # HOME_VISIBLE stays a breach in EVERY posture: it is what makes an in-place
    # runtime bind refuse to certify (B1). NET_VISIBLE is a breach only when the
    # network was supposed to be unshared; under the declared open posture it is
    # expected and recorded as waived above, never a breach.
    breaches = [tag for tag in ("WROTE_ORIGINAL", "HOME_VISIBLE") if tag in out]
    if not allow_network and "NET_VISIBLE" in out:
        breaches.append("NET_VISIBLE")
    expect_controls = ["USR_OK", "WORK_WRITE_OK"] + (["DNS_OK"] if allow_network else [])
    controls_missing = [tag for tag in expect_controls if tag not in out]
    if canary_target.exists():
        # the unique per-call name (R20-FENCE-01) cannot be a pre-existing user
        # file, so its presence means the fenced probe really wrote outside the
        # work copy — a confirmed breach; remove only this marker we created.
        canary_target.unlink(missing_ok=True)
        breaches.append("WROTE_ORIGINAL_CONFIRMED")
    report.update({"ran": not r.timed_out, "breaches": breaches,
                   "controls_missing": controls_missing,
                   "canary_done": "CANARY_DONE" in out})
    if breaches or controls_missing or r.timed_out or "CANARY_DONE" not in out:
        report["refused"] = (f"fence canary failed: breaches={breaches} "
                             f"controls_missing={controls_missing}"
                             if (breaches or controls_missing) else "did not complete")
        return None, report
    cert = FenceCertificate(
        # SAME ephemeral set as config_hash_for, or a run's later hash would not
        # match its own certificate: the writable bind's per-run host path is
        # ephemeral (its neutral SANDBOX path is the certified shape).
        config_hash=_config_hash(argv_template, ephemeral=(
            str(work_dir), str(home), *(str(h) for h, _ in writable_binds))),
        bwrap_version=ver, host=os.uname().nodename if hasattr(os, "uname") else "?",
        minted_at=now or time.time(), canary=dict(report))
    return cert, report


# --------------------------------------------------------------------------- #
# env allowlist (M3): a fix/agent process gets only these + vendor auth vars
# --------------------------------------------------------------------------- #

_BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "TMPDIR")
# vendor auth the CLI legitimately needs; everything else (CI/cloud tokens) dropped
_VENDOR_ENV_PREFIXES = ("ANTHROPIC_", "CLAUDE_", "OPENAI_", "CODEX_")
_VENDOR_ENV_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY")
# never pass these, even if a broad rule would (defense in depth)
_ENV_DENY_SUBSTR = ("TOKEN", "SECRET", "AWS", "GITHUB", "GH_", "GITLAB", "NPM",
                    "KUBECONFIG", "DOCKER", "SSH_AUTH_SOCK", "SYSTEM_ACCESSTOKEN")


def allowlisted_env(*, home: str, extra_keys: tuple[str, ...] = ()) -> dict:
    """A minimal environment for a fenced agent: base locale/PATH + vendor auth,
    HOME pointed at the ephemeral dir, NESTED markers. CI/cloud tokens dropped."""
    src = os.environ
    allowed: dict[str, str] = {}
    for k in (*_BASE_ENV_KEYS, *_VENDOR_ENV_KEYS, *extra_keys):
        if k in src:
            allowed[k] = src[k]
    for k, v in src.items():
        if k.startswith(_VENDOR_ENV_PREFIXES):
            allowed[k] = v
    # R11: DENY WINS over the prefix allow. The old comprehension exempted
    # anything matching a vendor prefix, and every _VENDOR_ENV_KEYS entry also
    # matches a prefix — so _ENV_DENY_SUBSTR, labelled "never pass these, even
    # if a broad rule would", could not remove a single key. A var such as
    # CODEX_GITHUB_TOKEN or ANTHROPIC_AWS_SECRET rode straight in on its prefix.
    # Only the explicitly enumerated vendor keys and the caller's extra_keys are
    # exempt; none of those contain a denied substring.
    exempt = frozenset((*_BASE_ENV_KEYS, *_VENDOR_ENV_KEYS, *extra_keys))
    out = {k: v for k, v in allowed.items()
           if k in exempt or not any(d in k.upper() for d in _ENV_DENY_SUBSTR)}
    out["HOME"] = home
    out["SECURITY_COUNCIL_NESTED"] = "1"
    out["LLM_COUNCIL_NESTED"] = "1"
    return out
