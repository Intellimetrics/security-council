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


def _config_hash(argv_template: list[str]) -> str:
    # hash the fence shape (flags + bind structure), not the ephemeral paths
    shape = [a for a in argv_template if not a.startswith("/tmp/") and "sc-ws" not in a]
    return hashlib.sha256("\x00".join(shape).encode()).hexdigest()[:16]


def run_in_fence(cmd: list[str], *, work_dir: Path, home: Path, timeout: int = 3600,
                 allow_network: bool = False, env: dict | None = None):
    from . import proc
    argv = bwrap_argv(work_dir=work_dir, home=home, allow_network=allow_network) + ["--", *cmd]
    return proc.run_command(argv, timeout=timeout, cwd=str(work_dir), env=env,
                            success_exit_codes=tuple(range(0, 256)))


def certify(*, work_dir: Path, original: Path, now: float | None = None) -> tuple[FenceCertificate | None, dict]:
    """Run the canary inside the real fence config; mint a certificate only if
    every escape is provably blocked. Returns (cert|None, canary_report)."""
    ok_bw, ver = bwrap_available()
    home = work_dir.parent / "sc-fence-home"
    argv_template = bwrap_argv(work_dir=work_dir, home=home)
    report: dict = {"bwrap": ver, "bwrap_ok": ok_bw}
    if not ok_bw:
        report["refused"] = "bwrap unavailable"
        return None, report

    canary_target = original / ".sc-canary"
    # a single probe: try to (1) write outside the work copy, (2) read $HOME real
    # files, (3) reach the network. All must fail.
    probe = (f"(touch {canary_target!s} 2>/dev/null && echo WROTE_ORIGINAL); "
             f"(cat {str(Path.home() / '.ssh' / 'id_rsa')!s} 2>/dev/null && echo READ_HOME); "
             "(getent hosts example.com 2>/dev/null && echo RESOLVED_NET); "
             "echo CANARY_DONE")
    home.mkdir(parents=True, exist_ok=True)
    try:
        r = run_in_fence(["/bin/sh", "-c", probe], work_dir=work_dir, home=home, timeout=60)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    out = (r.stdout or "") + (r.stderr or "")
    breaches = [tag for tag in ("WROTE_ORIGINAL", "READ_HOME", "RESOLVED_NET") if tag in out]
    escaped_canary = canary_target.exists()
    if escaped_canary:
        canary_target.unlink(missing_ok=True)      # never leave the marker behind
        breaches.append("WROTE_ORIGINAL_CONFIRMED")
    report.update({"ran": not r.timed_out, "breaches": breaches, "canary_done": "CANARY_DONE" in out})
    if breaches or r.timed_out or "CANARY_DONE" not in out:
        report["refused"] = f"fence canary failed: {breaches or 'did not complete'}"
        return None, report
    cert = FenceCertificate(config_hash=_config_hash(argv_template), bwrap_version=ver,
                            host=os.uname().nodename if hasattr(os, "uname") else "?",
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
    out: dict[str, str] = {}
    for k in (*_BASE_ENV_KEYS, *_VENDOR_ENV_KEYS, *extra_keys):
        if k in src:
            out[k] = src[k]
    for k, v in src.items():
        if k.startswith(_VENDOR_ENV_PREFIXES) and not any(d in k.upper() for d in ("SECRET",)):
            out[k] = v
    # positive allowlist wins, but scrub anything that slipped in by prefix
    out = {k: v for k, v in out.items()
           if k in (*_BASE_ENV_KEYS, *extra_keys)
           or k.startswith(_VENDOR_ENV_PREFIXES)
           or not any(d in k.upper() for d in _ENV_DENY_SUBSTR)}
    out["HOME"] = home
    out["SECURITY_COUNCIL_NESTED"] = "1"
    out["LLM_COUNCIL_NESTED"] = "1"
    return out
