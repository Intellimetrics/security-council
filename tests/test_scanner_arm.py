"""R12 — a scanner that scanned NOTHING must never look clean.

The dangerous path: semgrep/gitleaks/osv all treat exit 1 as success ("findings
found"), so a run that exited inside `success_exit_codes` but wrote no SARIF
returned `ok=True, findings=[]` — a silent clean result, which is the exact
failure mode this project exists to prevent.

The opposite mistake matters too: osv-scanner writes no SARIF and exits
non-zero on a repo with no dependency manifests. That is not-applicable, not a
failure, and treating it as one made every dependency-free repo scan
"degraded" (exit 3) instead of clean.
"""

from __future__ import annotations

import json

from security_council.arms import scanner as sc
from security_council.arms.scanner import ScannerArm


class _R:
    def __init__(self, ok=True, exit_code=0, stdout="", stderr=""):
        self.ok, self.exit_code = ok, exit_code
        self.stdout, self.stderr = stdout, stderr
        self.elapsed_seconds = 0.1
        self.timed_out = False


def _run(monkeypatch, tmp_path, name, result, *, write_sarif=None):
    monkeypatch.setattr(sc.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(ScannerArm, "_version", lambda self, d: "1.0")

    def fake(cmd, **kw):
        if write_sarif is not None:
            raw = tmp_path / "raw" / name
            raw.mkdir(parents=True, exist_ok=True)
            (raw / sc.SCANNER_SPECS[name].sarif_name).write_text(json.dumps(write_sarif))
        return result

    monkeypatch.setattr(sc.proc, "run_command", fake)
    return ScannerArm(name).run(tmp_path, tmp_path, run_id="r", collected_at="t")


def test_success_exit_but_no_report_is_a_failure_not_a_clean_scan(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, "semgrep", _R(ok=True, exit_code=1))
    assert res.ok is False                       # was True, with findings=[]
    assert res.findings == []
    assert res.coverage["coverage_unverified"] is True
    assert "NOT clean" in res.error and "wrote no semgrep.sarif" in res.error


def test_osv_with_no_package_sources_is_not_applicable_not_failed(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, "osv-scanner",
               _R(ok=False, exit_code=128, stderr="No package sources found, --help for usage"))
    assert res.ok is True                        # a dependency-free repo is not a broken scan
    assert res.error == ""
    assert res.coverage["not_applicable"] is True
    assert res.findings == []


def test_a_real_empty_report_is_still_a_clean_scan(monkeypatch, tmp_path):
    """semgrep and gitleaks DO write an empty SARIF when they find nothing —
    verified live — so an empty report must stay a clean pass."""
    empty = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}},
                                           "results": []}]}
    res = _run(monkeypatch, tmp_path, "semgrep", _R(ok=True, exit_code=0), write_sarif=empty)
    assert res.ok is True and res.findings == []
    assert not res.coverage.get("coverage_unverified")
    assert res.error == ""
