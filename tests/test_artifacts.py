"""M-V3 artifact lane: analysis workflows attach as artifacts, never as
findings; dual-use ones are export-excluded; provenance is stamped; the runner
drives the vendor `$skill` contract (fake-proc)."""

import pytest

from security_council import artifacts as art
from security_council.arms.artifact_runner import ArtifactRunnerArm
from security_council.arms.registry import build_analysis_arm
from security_council.orchestrator import run_scan
from tests.test_entitlements import _cfg
from tests.test_orchestrator import FakeArm, _finding as orch_finding


# --------------------------------------------------------------------------- #
# artifact model
# --------------------------------------------------------------------------- #


def test_make_artifact_dual_use_defaults_to_export_excluded():
    a = art.make_artifact(job=art.ANALYSIS_JOBS["writeup"], path="raw/codex-analysis_writeup/w.md",
                          producer="codex-analysis:writeup", run_id="r1", created_at="t")
    assert a.dual_use is True and a.export_excluded is True and a.kind == "writeup"
    tm = art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"],
                           path="raw/x/tm.md", producer="p", run_id="r1", created_at="t")
    assert tm.dual_use is False and tm.export_excluded is False


def test_artifact_path_must_be_under_raw():
    with pytest.raises(ValueError, match="under raw/"):
        art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"], path="/etc/passwd",
                          producer="p", run_id="r", created_at="t")


def test_export_eligible_holds_back_dual_use():
    rows = [
        art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"], path="raw/a/tm.md",
                          producer="p", run_id="r", created_at="t").to_dict(),
        art.make_artifact(job=art.ANALYSIS_JOBS["attack-path"], path="raw/a/ap.md",
                          producer="p", run_id="r", created_at="t").to_dict(),
    ]
    elig = art.export_eligible(rows)
    assert [a["kind"] for a in elig] == ["threat-model"]


def test_artifact_id_stable_and_prefixed():
    kw = dict(kind="threat-model", producer="p", path="raw/a/tm.md", run_id="r1")
    assert art.artifact_id(**kw) == art.artifact_id(**kw) and art.artifact_id(**kw).startswith("A")


# --------------------------------------------------------------------------- #
# runner (fake-proc)
# --------------------------------------------------------------------------- #


class _P:
    def __init__(self, rc=0, ok=True, timed_out=False):
        self.exit_code, self.ok, self.timed_out = rc, ok, timed_out
        self.stdout = self.stderr = ""
        self.elapsed_seconds = 1.0


def test_runner_builds_skill_prompt_and_returns_artifact(monkeypatch, tmp_path):
    from security_council.arms import artifact_runner as ar
    (tmp_path / "app").mkdir()
    captured = {}

    def fake(cmd, **kw):
        captured["cmd"] = cmd
        # emulate the plugin writing its markdown into the run's raw dir
        raw = tmp_path / "out" / "raw" / "codex-analysis_threat-model"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "threat-model.md").write_text("# Threat model\n")
        return _P()
    monkeypatch.setattr(ar.proc, "run_command", fake)
    arm = ArtifactRunnerArm(job="threat-model", family="codex")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r1", collected_at="2026-08-23T00:00:00Z")
    assert res.ok and res.findings == [] and len(res.artifacts) == 1
    a = res.artifacts[0]
    assert a["kind"] == "threat-model" and a["path"].startswith("raw/codex-analysis_threat-model/")
    assert a["export_excluded"] is False
    # R10: the command must follow CODEX's real contract. `-p` on codex is
    # `--profile`, not the prompt — passing it there is why the lane could
    # never run. The prompt is the trailing positional arg of `codex exec`.
    cmd = captured["cmd"]
    assert cmd[:3] == ["codex", "exec", "--ignore-user-config"]
    assert "-p" not in cmd
    assert "--output-format" not in cmd          # a Claude Code flag
    assert "$threat-model" in cmd[-1]


def test_codex_analysis_lane_refuses_because_the_skill_is_unreachable():
    """R10: these skills are internal phases of `codex-security scan`, not a
    public surface. Refusing beats emitting an artifact stamped with
    vendor-skill provenance we cannot support."""
    arm = ArtifactRunnerArm(job="threat-model", family="codex")
    ok, why = arm.available()
    assert ok is False
    assert "not independently invocable" in why


def test_runner_failure_when_no_artifact(monkeypatch, tmp_path):
    from security_council.arms import artifact_runner as ar
    monkeypatch.setattr(ar.proc, "run_command", lambda cmd, **kw: _P())
    arm = ArtifactRunnerArm(job="writeup", family="codex")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "no artifact produced" in res.error


def test_runner_stamps_tier_posture(monkeypatch, tmp_path):
    from security_council.arms import artifact_runner as ar

    def fake(cmd, **kw):
        raw = tmp_path / "out" / "raw" / "codex-analysis_attack-path"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "ap.md").write_text("# AP\n")
        return _P()
    monkeypatch.setattr(ar.proc, "run_command", fake)
    arm = ArtifactRunnerArm(job="attack-path", family="codex", model="daybreak-blue-latest")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    a = res.artifacts[0]
    assert a["dual_use"] is True and a["export_excluded"] is True
    assert a["entitlement"] == "daybreak-blue" and a["safeguard_posture"] == "relaxed"


def test_registry_builds_analysis_arm():
    arm = build_analysis_arm("threat-model")
    assert isinstance(arm, ArtifactRunnerArm) and arm.spec.key == "threat-model"


def test_unknown_job_rejected():
    with pytest.raises(ValueError, match="unknown analysis job"):
        ArtifactRunnerArm(job="nope")


# --------------------------------------------------------------------------- #
# orchestrator integration + summary
# --------------------------------------------------------------------------- #


class FakeAnalysisArm:
    kind = "artifact"
    supports_diff = False

    def __init__(self, job, dual_use, ok=True):
        self.name = f"codex-analysis:{job}"
        self.family = "codex"
        self.model = None
        self._job, self._dual, self._ok = job, dual_use, ok

    def available(self):
        return True, "fake"

    def run(self, target, out_dir, *, run_id, collected_at):
        from security_council.arms.base import ArmResult
        if not self._ok:
            return ArmResult(self.name, self.kind, self.family, False, 1, "boom", [])
        a = art.make_artifact(job=art.ANALYSIS_JOBS[self._job],
                              path=f"raw/x/{self._job}.md", producer=self.name,
                              run_id=run_id, created_at=collected_at)
        return ArmResult(self.name, self.kind, self.family, True, 0, "", [],
                         artifacts=[a.to_dict()])


def test_orchestrator_attaches_artifacts_not_findings(tmp_path):
    scan = FakeArm("semgrep", "scanner", "semgrep",
                   [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="a")])
    tm = FakeAnalysisArm("threat-model", dual_use=False)
    ap = FakeAnalysisArm("attack-path", dual_use=True)
    run = run_scan(tmp_path, [scan], _cfg(), out_dir=tmp_path / "out", analysis_arms=[tm, ap])
    arts = run.manifest["artifacts"]
    assert {a["kind"] for a in arts} == {"threat-model", "attack-path"}
    # artifacts never became findings
    assert len(run.findings) == 1 and run.findings[0].taxonomy.cwe_family == "injection"
    # summary lists them, dual-use flagged
    md = (run.out_dir / "summary.md").read_text()
    assert "## Analysis artifacts" in md and "dual-use" in md
    # export-eligibility holds back the dual-use one
    assert [a["kind"] for a in art.export_eligible(arts)] == ["threat-model"]


def test_failed_analysis_is_degradation_not_gate_flip(tmp_path):
    scan = FakeArm("semgrep", "scanner", "semgrep",
                   [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="b")])
    bad = FakeAnalysisArm("threat-model", dual_use=False, ok=False)
    run = run_scan(tmp_path, [scan], _cfg(), out_dir=tmp_path / "out", analysis_arms=[bad])
    kinds = [d["kind"] for d in run.manifest["degradations"]]
    assert "analysis_failed" in kinds
    assert run.exit_code == 1        # gated by the real finding, not degraded to 3 by analysis


def test_analysis_arm_not_a_coverage_source(tmp_path):
    # an analysis arm reporting no findings must not skew corroboration/coverage
    scan = FakeArm("semgrep", "scanner", "semgrep",
                   [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="c")])
    tm = FakeAnalysisArm("threat-model", dual_use=False)
    run = run_scan(tmp_path, [scan], _cfg(), out_dir=tmp_path / "out", analysis_arms=[tm])
    f = run.findings[0]
    assert "codex-analysis:threat-model" not in f.corroboration.eligible_sources
