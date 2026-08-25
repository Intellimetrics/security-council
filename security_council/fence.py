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
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

FENCE_TTL_SECONDS = 3600
_RO_SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")


def reachable_in_fence(cmd: str) -> tuple[bool, str]:
    """Whether `cmd` resolves to a path the fence actually binds.

    R10 (verified live): the fence binds only `_RO_SYSTEM_DIRS`, but the vendor
    CLIs live outside them — `codex` under `~/.nvm/versions/node/*/bin`,
    `claude` and `agy` under `~/.local/bin`. A fenced run of one produced
    `bwrap: execvp codex: No such file or directory` several minutes into the
    lane. Checking up front turns that into an honest `available()` refusal.
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


def bwrap_argv(*, work_dir: Path, home: Path, allow_network: bool = False) -> list[str]:
    """The bwrap wrapper argv (prefix a command after `--`). Writable: only
    `work_dir` and a tmpfs `home`. Everything else ro or absent."""
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup-try", "--proc", "/proc", "--dev", "/dev"]
    if not allow_network:
        argv += ["--unshare-net"]
    for d in _RO_SYSTEM_DIRS:
        if Path(d).exists():
            argv += ["--ro-bind", d, d]
    argv += ["--tmpfs", "/tmp",
             "--bind", str(work_dir), str(work_dir),
             "--tmpfs", str(home),
             "--setenv", "HOME", str(home),
             "--chdir", str(work_dir)]
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


def config_hash_for(*, work_dir: Path, home: Path, allow_network: bool = False) -> str:
    """The hash a run's fence WILL have — compare it to the certificate's."""
    argv = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network)
    return _config_hash(argv, ephemeral=(str(work_dir), str(home)))


def verify_certificate(cert: "FenceCertificate | None", *, work_dir: Path, home: Path,
                       allow_network: bool = False, now: float | None = None) -> str | None:
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
    want = config_hash_for(work_dir=work_dir, home=home, allow_network=allow_network)
    if cert.config_hash != want:
        return f"certificate is for a different fence (hash {cert.config_hash} != {want})"
    return None


def run_in_fence(cmd: list[str], *, work_dir: Path, home: Path, timeout: int = 3600,
                 allow_network: bool = False, env: dict | None = None):
    from . import proc
    argv = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network) + ["--", *cmd]
    return proc.run_command(argv, timeout=timeout, cwd=str(work_dir), env=env,
                            success_exit_codes=tuple(range(0, 256)))


def certify(*, work_dir: Path, original: Path, home: Path | None = None,
            allow_network: bool = False,
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
    argv_template = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network)
    report: dict = {"bwrap": ver, "bwrap_ok": ok_bw, "allow_network": allow_network}
    if not ok_bw:
        report["refused"] = "bwrap unavailable"
        return None, report

    canary_target = original / ".sc-canary"
    real_home = str(Path.home())
    probe = (
        # positive controls — these MUST print, or the probe did not really run
        "( [ -d /usr ] && echo USR_OK ); "
        f"( touch {str(work_dir)!s}/.sc-work-write 2>/dev/null && echo WORK_WRITE_OK ); "
        # escapes — these must NOT print
        f"( touch {canary_target!s} 2>/dev/null && echo WROTE_ORIGINAL ); "
        # the real home must not merely be unreadable, it must not EXIST in the namespace
        f"( [ -e {real_home!s} ] && echo HOME_VISIBLE ); "
        # with the network unshared only `lo` exists; any other interface is a breach
        "( awk -F: 'NR>2{print $1}' /proc/net/dev 2>/dev/null | tr -d ' ' "
        "| grep -qv '^lo$' && echo NET_VISIBLE ); "
        "echo CANARY_DONE")
    home.mkdir(parents=True, exist_ok=True)
    try:
        r = run_in_fence(["/bin/sh", "-c", probe], work_dir=work_dir, home=home,
                         allow_network=allow_network, timeout=60)
    finally:
        if own_home:
            shutil.rmtree(home, ignore_errors=True)
        (work_dir / ".sc-work-write").unlink(missing_ok=True)
    out = (r.stdout or "") + (r.stderr or "")
    breaches = [tag for tag in ("WROTE_ORIGINAL", "HOME_VISIBLE") if tag in out]
    if not allow_network and "NET_VISIBLE" in out:
        breaches.append("NET_VISIBLE")
    controls_missing = [tag for tag in ("USR_OK", "WORK_WRITE_OK") if tag not in out]
    if canary_target.exists():
        canary_target.unlink(missing_ok=True)      # never leave the marker behind
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
        config_hash=_config_hash(argv_template, ephemeral=(str(work_dir), str(home))),
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
