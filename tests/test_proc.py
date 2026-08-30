"""Subprocess timeout behavior, including descendant processes."""

import os
import sys
import time

import pytest

from security_council import proc


@pytest.mark.skipif(not hasattr(os, "fork"), reason="process-group regression is POSIX-specific")
def test_timeout_kills_descendants_holding_capture_pipes():
    code = (
        "import subprocess,time; "
        "subprocess.Popen(['sleep','60']); "
        "time.sleep(60)"
    )
    started = time.monotonic()

    result = proc.run_command(
        [sys.executable, "-c", code], timeout=0.1, kill_process_group=True)

    assert result.timed_out and not result.ok
    assert "[timed out]" in result.stderr
    assert time.monotonic() - started < 3
