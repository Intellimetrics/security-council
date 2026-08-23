"""M-V4a fix arm: fail-closed on an uncertified fence; produces a validated
`.patch` artifact (never applied); refuses in-place; secrets patch export-excluded."""
import hashlib

import pytest

from security_council.arms import fix as fixmod
from security_council.arms.fix import FixArm
from security_council.orchestrator import run_scan
from tests.test_entitlements import _cfg
from tests.test_orchestrator import FakeArm, _finding as orch_finding


def _finding_row(cwe="CWE-89", fam="injection", uri="app/x.py"):
    return {"id": "f" + hashlib.sha256(uri.encode()).hexdigest()[:12],
            "taxonomy": {"cwe": [cwe], "cwe_family": fam},
            "locations": [{"uri": uri, "start_line": 1}]}


def _seed_target(tmp_path):
    t = tmp_path / "repo"
    (t / "app").mkdir(parents=True)
    (t / "app" / "x.py").write_text("q = 'SELECT ' + name\n")
    return t


def test_unknown_fix_job_rejected():
    with pytest.raises(ValueError, match="unknown fix job"):
        FixArm(job="nope", finding=_finding_row())


def test_fix_fails_closed_without_fence(tmp_path, monkeypatch):
    monkeypatch.setattr(fixmod._fence, "certify",
                        lambda **kw: (None, {"refused": "bwrap unavailable", "bwrap": "x"}))
    arm = FixArm(job="suggest-patches", finding=_finding_row())
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "fence_unverified" in res.error and res.artifacts == []


def _fake_cert(monkeypatch):
    from security_council import fence
    cert = fence.FenceCertificate(config_hash="h", bwrap_version="bwrap 0.11.0", host="t",
                                  minted_at=9e18)
    monkeypatch.setattr(fixmod._fence, "certify",
                        lambda **kw: (cert, {"bwrap": "bwrap 0.11.0", "breaches": [],
                                             "canary_done": True}))


def test_fix_produces_validated_patch_artifact(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    target = _seed_target(tmp_path)

    def fake_run(cmd, **kw):
        # emulate the fenced vendor editing the work copy (cwd)
        from pathlib import Path
        wt = Path(kw["cwd"]) / "app" / "x.py"
        wt.write_text("q = db.execute('SELECT ...', [name])\n")
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="suggest-patches", finding=_finding_row())
    res = arm.run(target, tmp_path / "out", run_id="r1", collected_at="2026-08-23T00:00:00Z")
    assert res.ok and len(res.artifacts) == 1
    a = res.artifacts[0]
    assert a["kind"] == "fix" and a["format"] == "patch" and a["export_excluded"] is False
    # the .patch was written under raw/, and the REAL target is untouched
    patch = (tmp_path / "out" / "raw" / a["path"].split("raw/", 1)[1]).read_text()
    assert "db.execute" in patch and "SELECT" in patch
    assert (target / "app" / "x.py").read_text() == "q = 'SELECT ' + name\n"   # never applied


def test_secrets_fix_patch_is_export_excluded_and_redacted(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "settings.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLEKEY99'\n")

    def fake_run(cmd, **kw):
        from pathlib import Path
        (Path(kw["cwd"]) / "app" / "settings.py").write_text("KEY = os.environ['KEY']\n")
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="suggest-patches", finding=_finding_row("CWE-798", "secrets", "app/settings.py"))
    res = arm.run(target, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok
    a = res.artifacts[0]
    assert a["export_excluded"] is True and a["patch"]["secret_in_patch"] is True
    patch = (tmp_path / "out" / "raw" / a["path"].split("raw/", 1)[1]).read_text()
    assert "AKIAIOSFODNN7EXAMPLEKEY99" not in patch


def test_no_change_degrades_not_crashes(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)

    def fake_run(cmd, **kw):
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()   # edits nothing
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)
    arm = FixArm(job="fix-finding", finding=_finding_row())
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and "no_patch" in res.error and res.artifacts == []


def test_orchestrator_refuses_inplace_with_fix(tmp_path):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="a")])]
    with pytest.raises(ValueError, match="requires isolation"):
        run_scan(_seed_target(tmp_path), arms, _cfg(), out_dir=tmp_path / "out",
                 isolate=False, fix_spec={"jobs": ["suggest-patches"], "finding_ids": None})


def test_orchestrator_fix_only_open_findings(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    monkeypatch.setattr(fixmod.proc, "run_command",
                        lambda cmd, **kw: type("R", (), {"ok": True, "exit_code": 0, "stdout": "",
                                                         "stderr": "", "elapsed_seconds": 1.0,
                                                         "timed_out": False})())
    # a refuted finding must be skipped by the fix phase
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="z")])]
    run = run_scan(_seed_target(tmp_path), arms, _cfg(), out_dir=tmp_path / "out",
                   fix_spec={"jobs": ["suggest-patches"], "finding_ids": ["nonexistent"]})
    # no finding matched the id filter → no fix artifacts, no crash
    assert [a for a in run.manifest["artifacts"] if a.get("kind") == "fix"] == []
