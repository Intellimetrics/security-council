"""Minimal subprocess runner with timeout and success-exit-code handling.

Deterministic scanners exit nonzero *on findings* (semgrep/gitleaks/osv exit 1),
so `success_exit_codes` decides ok — not `returncode == 0`. This was confirmed by
the M0 S6 spike and is the whole reason the runner exists.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass
class ProcResult:
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool


def run_command(cmd: list[str], *, timeout: int = 1800,
                success_exit_codes: tuple[int, ...] = (0,),
                cwd: str | None = None, env: dict | None = None) -> ProcResult:
    start = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, env=env, check=False)
    except subprocess.TimeoutExpired as e:
        return ProcResult(False, None, e.stdout or "", (e.stderr or "") + "\n[timed out]",
                          time.monotonic() - start, True)
    except FileNotFoundError as e:
        return ProcResult(False, None, "", f"[not found] {e}", time.monotonic() - start, False)
    elapsed = time.monotonic() - start
    return ProcResult(p.returncode in success_exit_codes, p.returncode, p.stdout, p.stderr,
                      elapsed, False)
