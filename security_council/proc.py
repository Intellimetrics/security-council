"""Minimal subprocess runner with timeout and success-exit-code handling.

Deterministic scanners exit nonzero *on findings* (semgrep/gitleaks/osv exit 1),
so `success_exit_codes` decides ok — not `returncode == 0`. This was confirmed by
the M0 S6 spike and is the whole reason the runner exists.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
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
                cwd: str | None = None, env: dict | None = None,
                kill_process_group: bool = False, stdin=None) -> ProcResult:
    # `stdin` defaults to inherit; pass subprocess.DEVNULL for a child that
    # would otherwise BLOCK reading stdin (B1 live-found: `codex exec` reads
    # stdin for an appended block even with a prompt arg, hanging on no EOF).
    # start_new_session isolates the child in its own session/process group.
    # ``subprocess.run(timeout=...)`` kills only the direct child and then waits
    # for captured pipes to close.  A validator such as llm-council owns native
    # CLI children; if one survives with stdout/stderr open, that wait is
    # unbounded.  Own Popen directly so the timeout terminates the exact group.
    start = time.monotonic()
    if not kill_process_group:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               cwd=cwd, env=env, check=False, stdin=stdin,
                               start_new_session=hasattr(os, "setsid"))
        except subprocess.TimeoutExpired as e:
            return ProcResult(False, None, e.stdout or "", (e.stderr or "") + "\n[timed out]",
                              time.monotonic() - start, True)
        except FileNotFoundError as e:
            return ProcResult(False, None, "", f"[not found] {e}",
                              time.monotonic() - start, False)
        return ProcResult(p.returncode in success_exit_codes, p.returncode, p.stdout, p.stderr,
                          time.monotonic() - start, False)

    with (tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as out_file,
          tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as err_file):
        try:
            p = subprocess.Popen(cmd, stdout=out_file, stderr=err_file, text=True,
                                 cwd=cwd, env=env, stdin=stdin,
                                 start_new_session=hasattr(os, "setsid"))
        except FileNotFoundError as e:
            return ProcResult(False, None, "", f"[not found] {e}",
                              time.monotonic() - start, False)
        timed_out = False
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                if hasattr(os, "killpg"):
                    os.killpg(p.pid, signal.SIGKILL)
                else:
                    p.kill()
            except OSError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        out_file.seek(0)
        err_file.seek(0)
        stdout, stderr = out_file.read(), err_file.read()
        if timed_out:
            return ProcResult(False, None, stdout, stderr + "\n[timed out]",
                              time.monotonic() - start, True)
    elapsed = time.monotonic() - start
    return ProcResult(p.returncode in success_exit_codes, p.returncode, stdout, stderr,
                      elapsed, False)
