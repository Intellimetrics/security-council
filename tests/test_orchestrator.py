"""Orchestrator tests with injected fake arms (no docker)."""
import hashlib
import json

from security_council import model as m
from security_council.arms.base import ArmResult
from security_council.config import DEFAULT_CONFIG
from security_council.decisions import DecisionStore
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
    # These tests exercise gating/coverage with UNSIGNED stored decisions. Pin
    # the signature level so the suite does not flip when `auto` sunsets to
    # `enforce` (signing.WARN_SUNSET); tests/test_signing.py covers `auto`
    # and `enforce` explicitly, on both sides of that date.
    cfg["decisions"] = {**DEFAULT_CONFIG["decisions"], "require_signatures": "warn"}
    return run_scan(tmp_path, arms, cfg, out_dir=tmp_path / "out")


def _allow_unsigned(target):
    """Write the target config the CLI/MCP write paths read, so an unsigned
    `suppress` / `outcome mark` / `baseline set` is recorded (not refused)."""
    (target / ".security-council.yaml").write_text(
        "decisions:\n  require_signatures: warn\n")


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


def test_partial_coverage_never_exits_clean(tmp_path):
    """R12 round 4's open item: a PARTIAL scan whose findings were all below the
    gate threshold used to exit 0 — a clean bill from a run that examined less
    than it claimed. Incomplete coverage is degraded, never clean."""
    low = _finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")
    arms = [FakeArm("semgrep", "scanner", "semgrep", [low],
                    coverage={"completion": "partial"})]
    run = _run(arms, tmp_path, min_arms_ok=1)
    assert run.exit_code == 3                       # was 0
    assert any(d["kind"] == "partial_coverage" for d in run.degradations)


def test_partial_arm_is_not_silent_on_families_it_declined(tmp_path):
    """A partial arm must not be counted as declining a finding in a category it
    never looked at — that silence would push p down toward suppression."""
    real = _finding(source_id="semgrep", kind="scanner", vendor="semgrep", family="crypto")
    arms = [
        FakeArm("semgrep", "scanner", "semgrep", [real]),
        FakeArm("claude", "agent_cli", "claude", [],
                coverage={"completion": "partial", "declined_categories": ["crypto"]}),
    ]
    run = _run(arms, tmp_path, min_arms_ok=1)
    f = run.findings[0]
    assert "claude" not in (f.corroboration.declined_sources or [])
    assert "claude" not in (f.corroboration.eligible_sources or [])


def test_degraded_run_does_not_auto_suppress(tmp_path):
    """G10 (R12): a run that did not verify its coverage may not write a durable
    excuse. A partial run has fewer eligible corroborators, so p is LOWER and
    suppression more likely — exactly when it is least justified."""
    low = _finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")
    arms = [FakeArm("semgrep", "scanner", "semgrep", [low],
                    coverage={"completion": "partial"})]
    run = _run(arms, tmp_path, min_arms_ok=1, auto_suppress=True,
               accept_suppression_risk=True, shadow_runs=0)
    assert any(d["kind"] == "auto_suppress_withheld" for d in run.degradations)
    assert all(f.disposition.lifecycle == "open" for f in run.findings)


def test_a_degraded_run_does_not_consume_a_shadow_run(tmp_path):
    """G10/G4 (R12 round 6): `armed` was computed from the RAW config, before
    the G10 copy, so a degraded run burned one of the five shadow runs it could
    never use. After five, the first properly-verified run would suppress for
    real with no shadow observation behind it."""
    low = _finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")
    arms = [FakeArm("semgrep", "scanner", "semgrep", [low],
                    coverage={"completion": "partial"})]
    run = _run(arms, tmp_path, min_arms_ok=1, auto_suppress=True,
               accept_suppression_risk=True)
    assert any(d["kind"] == "auto_suppress_withheld" for d in run.degradations)
    # assert on the state FILE, not `armed_runs_completed(cfg)` — that is keyed
    # on a policy fingerprint, so a mismatched cfg returns 0 and the test would
    # pass whether or not the counter was bumped
    # the run roots its store at <target>/.security-council (orchestrator.py)
    state = DecisionStore(tmp_path / ".security-council").state_path
    assert not state.is_file() or json.loads(state.read_text()).get("armed_runs", 0) == 0


def test_a_zero_arm_run_does_not_consume_a_shadow_run(tmp_path):
    """R12 round 7: `any()` over an EMPTY results list is False, so a run with no
    arms looked fully verified, kept its armed status, and burned a shadow run
    on a scan that examined nothing."""
    run = _run([], tmp_path, min_arms_ok=1, auto_suppress=True,
               accept_suppression_risk=True)
    assert run.exit_code == 3
    state = DecisionStore(tmp_path / ".security-council").state_path
    assert not state.is_file() or json.loads(state.read_text()).get("armed_runs", 0) == 0


def test_manifest_records_the_policy_that_actually_ran(tmp_path):
    """R12 round 7: the manifest logged the RAW config, claiming
    `auto_suppress: true` on a run where G10 had disabled it."""
    low = _finding(source_id="semgrep", kind="scanner", vendor="semgrep", sev="low")
    arms = [FakeArm("semgrep", "scanner", "semgrep", [low],
                    coverage={"completion": "partial"})]
    run = _run(arms, tmp_path, min_arms_ok=1, auto_suppress=True,
               accept_suppression_risk=True)
    assert run.manifest["policy"]["auto_suppress"] is False


def test_validate_without_a_backend_is_a_visible_degradation(tmp_path, monkeypatch):
    """0.2.0 release rehearsal, reproduced live from the wheel: `scan --validate`
    with no `llm-council` on PATH produced no degradation and a summary line
    claiming "1 cross-examined". Fail-safe was already true (needs_human, never
    demoted); this pins the visibility."""
    from security_council import proc
    from security_council.validate import council_client

    def not_found(cmd, **kw):
        return proc.ProcResult(False, None, "", "[not found] No such file: 'llm-council'", 0.0, False)
    monkeypatch.setattr(council_client.proc, "run_command", not_found)
    f = _finding(source_id="semgrep", kind="scanner", vendor="semgrep")
    cfg = {**DEFAULT_CONFIG, "policy": {**DEFAULT_CONFIG["policy"]},
           "decisions": {**DEFAULT_CONFIG["decisions"], "require_signatures": "warn"}}
    run = run_scan(tmp_path, [FakeArm("semgrep", "scanner", "semgrep", [f])], cfg,
                   out_dir=tmp_path / "out", validate=True, validate_max_findings=1)
    kinds = [d["kind"] for d in run.degradations]
    assert "validator_unavailable" in kinds
    detail = next(d["detail"] for d in run.degradations if d["kind"] == "validator_unavailable")
    assert "not found" in detail and "llm-council" in detail
    out = [x for x in run.findings if x.validation is not None]
    assert len(out) == 1 and out[0].validation.verdict == "needs_human"
    assert out[0].disposition.state != "refuted"                     # never demoted
    assert run.manifest["validation"] == {
        "requested": True,
        "eligible": 1,
        "max_findings": 1,
        "max_cost_usd_per_finding": 0.5,
        "timeout_seconds_per_finding": 600,
        "host_records": 0,
        "external_selected": 1,
        "external_convened": 0,
        "external_two_vendor_quorum": 0,
        "external_failed": 1,
        "not_selected": 0,
        "deterministic_skipped": 0,
        "no_validation_record": 0,
    }
    md = (tmp_path / "out" / "summary.md").read_text()
    assert "0 reviewed" in md and "1 not examined" in md
    assert "validator_unavailable" in md
    # R15b: the HTML dashboard used to read `validation is not None` and said
    # "validated 1 — cross-examined by the panel" while the markdown said 0
    html = (tmp_path / "out" / "summary.html").read_text()
    assert "1 not examined" in html
    assert 'data-metric="external-panel">0' in html  # counts convened panels only
