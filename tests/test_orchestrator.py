"""Orchestrator tests with injected fake arms (no docker)."""
import hashlib

from security_council import model as m
from security_council.arms.base import ArmResult
from security_council.config import DEFAULT_CONFIG
from security_council.orchestrator import run_scan


def _sha(s): return hashlib.sha256(s.encode()).hexdigest()


def _finding(*, family="injection", sev="high", source_id, kind, vendor, rc="shared"):
    fps = m.Fingerprints(
        path_cwe_sink=f"pathCweSink/v1:{_sha(rc + 'p')[:32]}",
        context_hash=f"contextHash/v1:{_sha(rc + 'c')[:32]}",
        root_cause=f"rootCause/v1:{_sha(rc)[:32]}")
    prov = m.ProvenanceEntry(source_id=source_id, source_kind=kind, family=vendor,
                             prompt_sha256=_sha("p") if kind == "agent_cli" else "",
                             collected_at="t", model_id="mdl" if kind == "agent_cli" else None,
                             tool_version="1" if kind == "scanner" else None)
    corr = m.Corroboration(agent_sources=[source_id] if kind == "agent_cli" else [],
                           deterministic_sources=[source_id] if kind == "scanner" else [], count=1)
    return m.Finding(
        id=m.finding_id(fps), schema_version=1, cluster_id=None, rule=m.RuleRef(id="r", source=source_id),
        taxonomy=m.Taxonomy(cwe=["CWE-89"], cwe_family=family),
        severity=m.SeverityBlock(label=sev, sarif_level=m.SEVERITY_TO_SARIF_LEVEL[sev],
                                 security_severity=m.SEVERITY_TO_SECURITY_SEVERITY[sev]),
        locations=[m.CodeLocation(uri="app/x.py", start_line=1, end_line=1, role="primary",
                                  snippet_sha256=_sha("s"))],
        fingerprints=fps, provenance=[prov], corroboration=corr,
        disposition=m.Disposition(state="new", lifecycle="open",
                                  decided_by=m.DecidedBy(kind="auto", decided_at="t")),
        title="t", description="d")


class FakeArm:
    def __init__(self, name, kind, family, findings, ok=True, error="", coverage=None):
        self.name, self.kind, self.family = name, kind, family
        self._f, self._ok, self._e = findings, ok, error
        self._cov = coverage or {}

    def available(self):
        return True, "fake"

    def run(self, target, out_dir, *, run_id, collected_at):
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=self._ok,
                         exit_code=0 if self._ok else 1, error=self._e, findings=self._f,
                         tool_version="fake", coverage={"raw_results": len(self._f),
                                                        "normalized": len(self._f),
                                                        **self._cov})


def _run(arms, tmp_path, **policy):
    cfg = {**DEFAULT_CONFIG}
    cfg["policy"] = {**DEFAULT_CONFIG["policy"], **policy}
    return run_scan(tmp_path, arms, cfg, out_dir=tmp_path / "out")


def test_two_arms_cluster_and_gate_high(tmp_path):
    arms = [
        FakeArm("semgrep", "scanner", "semgrep",
                [_finding(source_id="semgrep", kind="scanner", vendor="semgrep")]),
        FakeArm("house", "agent_cli", "claude",
                [_finding(source_id="house", kind="agent_cli", vendor="claude")]),
    ]
    run = _run(arms, tmp_path)
    assert len(run.findings) == 1                          # same root_cause -> merged
    merged = run.findings[0]
    m.assert_invariants(merged)
    assert merged.corroboration.count == 2                 # two distinct sources
    assert run.exit_code == 1                              # high finding gates
    for f in ("merged.sarif", "raw.sarif", "findings.json", "manifest.json", "summary.md"):
        assert (run.out_dir / f).is_file()
    assert run.manifest["counts"]["total"] == 1


def test_low_only_is_clean_exit_0(tmp_path):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [_finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")])]
    run = _run(arms, tmp_path)
    assert run.exit_code == 0


def test_failed_arm_is_degraded_exit_3(tmp_path):
    arms = [
        FakeArm("semgrep", "scanner", "semgrep",
                [_finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")]),
        FakeArm("gitleaks", "scanner", "gitleaks", [], ok=False, error="boom"),
    ]
    run = _run(arms, tmp_path, min_arms_ok=1)
    assert run.exit_code == 3
    assert any(d["kind"] == "arm_failed" for d in run.degradations)


def test_insufficient_arms_exit_3(tmp_path):
    arms = [FakeArm("gitleaks", "scanner", "gitleaks", [], ok=False, error="boom")]
    run = _run(arms, tmp_path, min_arms_ok=1)
    assert run.exit_code == 3
    # zero successful arms trips the structural floor before the min_arms count
    assert any(d["kind"] == "no_arms_succeeded" for d in run.degradations)


def test_no_arms_succeeded_cannot_pass_even_with_min_arms_zero(tmp_path):
    """R12: with `min_arms_ok: 0` and nothing succeeding, every later branch was
    skipped and _exit_code returned 0 — a scan where NOTHING ran said clean."""
    arms = [FakeArm("gitleaks", "scanner", "gitleaks", [], ok=False, error="boom")]
    run = _run(arms, tmp_path, min_arms_ok=0)
    assert run.exit_code == 3
    assert any(d["kind"] == "no_arms_succeeded" for d in run.degradations)


def test_arm_crash_is_isolated(tmp_path):
    class Crasher:
        name, kind, family = "crash", "scanner", "x"
        def available(self): return True, ""
        def run(self, *a, **k): raise RuntimeError("kaboom")
    run = _run([Crasher()], tmp_path, min_arms_ok=1)
    assert run.exit_code == 3
    assert any("crashed" in (d.get("detail") or "") for d in run.degradations)


def test_coverage_unverified_arm_does_not_count_as_coverage(tmp_path):
    """R12 structural rule: the gate used to read `r.ok` alone, so every arm had
    to remember to set ok=False alongside `coverage_unverified` — and two of the
    three did not. Deciding it in ONE place stops the next arm forgetting.

    An arm that lies (ok=True while unverified) must still not produce a pass.
    """
    arm = FakeArm("claude", "agent_cli", "claude", [], ok=True,
                  coverage={"coverage_unverified": True})
    run = _run([arm], tmp_path, min_arms_ok=1)
    assert run.exit_code == 3
    assert any(d["kind"] == "coverage_unverified" for d in run.degradations)


def test_unverified_arm_is_not_an_eligible_source(tmp_path):
    """R12 round 4: `ran=r.ok` bypassed `_counts_as_coverage`, so an arm that
    verified nothing stayed ELIGIBLE — and, reporting nothing, counted as
    *silent*, applying `coverage_decline` (up to -1.05 log-odds) against a real
    finding from another arm. An arm that scanned nothing gets no vote."""
    real = _finding(source_id="semgrep", kind="scanner", vendor="semgrep")
    arms = [
        FakeArm("semgrep", "scanner", "semgrep", [real]),
        FakeArm("claude", "agent_cli", "claude", [], ok=True,
                coverage={"coverage_unverified": True}),
    ]
    run = _run(arms, tmp_path, min_arms_ok=1)
    f = run.findings[0]
    assert "claude" not in (f.corroboration.eligible_sources or [])
    assert run.exit_code == 1          # the real finding still gates
