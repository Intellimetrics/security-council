"""decisions.py: per-root-cause decision store — reapply/expiry(G6)/drift(G8),
anti-poisoning history, armed-run shadow counter with policy-change reset,
baseline/delta, and the CLI + orchestrator wiring."""
import dataclasses
import json

from security_council import decisions as dec
from security_council import model as m
from security_council import policy
from security_council.arms.base import ArmResult
from security_council.cli import main as cli_main
from security_council.jsonio import to_dict
from security_council.orchestrator import _exit_code
from tests.test_orchestrator import FakeArm, _allow_unsigned, _finding as orch_finding, \
    _run as orch_run
from tests.test_validate import _finding

NOW = "2026-08-22T00:00:00Z"
LATER = "2026-08-25T00:00:00Z"


def _human(store, f, *, days=90, vex=None):
    return store.record_human_decision(
        root_cause=f.fingerprints.root_cause, context_hash=f.fingerprints.context_hash,
        finding_id=f.id, title=f.title, operator="clindell", justification="test fixture",
        now_iso=NOW, expires_days=days, vex_justification=vex)


# --------------------------------------------------------------------------- #
# store: reapply / expiry / drift / shadow records
# --------------------------------------------------------------------------- #


def test_human_decision_reapplies_with_full_attribution(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding(), vex="inline_mitigations_already_exist")
    f = _finding()                          # a fresh scan's finding, same root cause
    actions = store.apply_prior_decisions([f], now_iso=LATER)
    # R9: action rows carry per-suppression provenance so the report can list
    # every reapplied decision individually instead of an aggregate count
    assert len(actions) == 1
    a = actions[0]
    assert a["finding_id"] == f.id and a["action"] == "reapplied_suppressed"
    assert a["ref"] == f"decision:root_cause:{f.fingerprints.root_cause}"
    assert a["title"] == f.title and a["severity"] == f.severity.label
    assert a["operator"] == "clindell" and a["decided_at"] == NOW
    assert a["expires_at"] == "2026-11-20T00:00:00Z"
    assert a["expiry_clamped"] is False and a["high_assurance"] is False
    assert a["reapplied_count"] == 1
    d = f.disposition
    assert d.lifecycle == "suppressed" and d.decided_by.kind == "human"
    assert d.decided_by.operator == "clindell" and d.expires_at == "2026-11-20T00:00:00Z"
    assert d.vex_status == "not_affected"
    m.assert_invariants(f)                  # I6 human attribution complete


def test_expired_decision_reopens_G6(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding(), days=1)
    f = _finding()
    [a] = store.apply_prior_decisions([f], now_iso=LATER)     # 3 days later
    assert a["action"] == "reopened_expired"
    assert f.disposition.lifecycle == "reopened"
    assert "suppression_expired" in f.disposition.reopen_reason
    m.assert_invariants(f)
    rec = store.load(f.fingerprints.root_cause)
    assert rec["suppression"]["status"] == "expired"
    assert rec["history"][-1]["kind"] == "expire"
    # once expired, later scans are untouched (plain open, no re-reopen)
    f2 = _finding()
    assert store.apply_prior_decisions([f2], now_iso=LATER) == []
    assert f2.disposition.lifecycle == "open"


def test_context_drift_reopens_and_deactivates_G8(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding())
    f = _finding()
    drifted = dataclasses.replace(f.fingerprints,
                                  context_hash="contextHash/v1:" + "d" * 32)
    f.fingerprints = drifted
    [a] = store.apply_prior_decisions([f], now_iso=LATER)
    assert a["action"] == "reopened_drift"
    assert f.disposition.lifecycle == "reopened"
    assert "context_drift" in f.disposition.reopen_reason
    rec = store.load(f.fingerprints.root_cause)
    assert rec["suppression"]["status"] == "drifted"
    # a drifted decision never reactivates on its own — even if context returns
    f3 = _finding()
    assert store.apply_prior_decisions([f3], now_iso=LATER) == []
    assert f3.disposition.lifecycle == "open"


def test_shadow_records_never_apply(tmp_path):
    store = dec.DecisionStore(tmp_path)
    f = _finding()
    store.record_suppression(f, now_iso=NOW, shadow=True)
    rec = store.load(f.fingerprints.root_cause)
    assert "suppression" not in rec
    assert rec["history"][-1]["kind"] == "shadow_suppress"
    f2 = _finding()
    assert store.apply_prior_decisions([f2], now_iso=LATER) == []
    assert f2.disposition.lifecycle == "open"


def test_atomic_writes_leave_no_tmp(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding())
    files = list((tmp_path / "decisions" / "by-root-cause").iterdir())
    assert len(files) == 1 and files[0].suffix == ".json"
    json.loads(files[0].read_text())        # valid JSON on disk


# --------------------------------------------------------------------------- #
# anti-poisoning history
# --------------------------------------------------------------------------- #


def test_history_counts_only_human_outcome_marks(tmp_path):
    store = dec.DecisionStore(tmp_path)
    f = _finding()
    rc = f.fingerprints.root_cause
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive",
                       operator="clindell", now_iso=NOW)
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive",
                       operator="clindell", now_iso=LATER)
    # machine decisions in the same record must NOT count (anti-poisoning)
    fs = _finding()
    fs.disposition.lifecycle = "suppressed"
    fs.disposition.decided_by = m.DecidedBy(kind="human", decided_at=NOW, operator="x")
    fs.disposition.decision_ref = "decision:root_cause:" + rc
    fs.disposition.expires_at = LATER
    store.record_suppression(fs, now_iso=NOW)
    store.record_suppression(_finding(), now_iso=NOW, shadow=True)
    assert store.history_counts() == {rc: {"confirmed_tp": 0, "confirmed_fp": 2}}


def test_mark_outcome_rejects_unknown_verdict(tmp_path):
    store = dec.DecisionStore(tmp_path)
    try:
        store.mark_outcome(root_cause="rootCause/v1:" + "a" * 32, finding_id="x",
                           verdict="meh", operator="o", now_iso=NOW)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# --------------------------------------------------------------------------- #
# armed-run shadow counter (G4) — resets on policy change, unarmed runs free
# --------------------------------------------------------------------------- #


def test_shadow_counter_bumps_and_resets_on_policy_change(tmp_path):
    store = dec.DecisionStore(tmp_path)
    armed = {"policy": {"auto_suppress": True, "accept_suppression_risk": True}}
    assert store.armed_runs_completed(armed) == 0
    store.bump_armed_runs(armed, run_id="r1", now_iso=NOW)
    store.bump_armed_runs(armed, run_id="r2", now_iso=NOW)
    assert store.armed_runs_completed(armed) == 2
    # suppression-relevant change -> full shadow again
    changed = {"policy": {**armed["policy"], "suppress_below": 0.2}}
    assert store.armed_runs_completed(changed) == 0
    # gating-only change does NOT reset (fail_on_severity is not suppression-relevant)
    gating = {"policy": {**armed["policy"], "fail_on_severity": "low"}}
    assert store.armed_runs_completed(gating) == 2


# --------------------------------------------------------------------------- #
# baseline / delta
# --------------------------------------------------------------------------- #


def _bl_finding(rc, ctx="c", sev="high"):
    f = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=rc)
    if ctx != "c":
        f.fingerprints = dataclasses.replace(
            f.fingerprints, context_hash="contextHash/v1:" + (ctx * 32)[:32])
    return f


def test_baseline_annotation_tiers(tmp_path):
    store = dec.DecisionStore(tmp_path)
    old = [_bl_finding("a"), _bl_finding("b"), _bl_finding("gone")]
    store.set_baseline([to_dict(f) for f in old], run_id="r0", now_iso=NOW)
    unchanged = _bl_finding("a")
    updated = _bl_finding("b", ctx="e")            # same root cause, new context
    brand_new = _bl_finding("fresh")
    delta = dec.annotate_baseline([unchanged, updated, brand_new], store.load_baseline())
    assert unchanged.baseline_state == "unchanged"
    assert updated.baseline_state == "updated"
    assert brand_new.baseline_state == "new"
    assert (delta["new"], delta["unchanged"], delta["updated"], delta["absent"]) == (1, 1, 1, 1)
    assert delta["absent_findings"][0]["id"] == old[2].id
    assert delta["baseline_run"] == "r0"


def test_gate_baseline_new_mode():
    ok_arm = ArmResult(name="a", kind="scanner", family="x", ok=True, exit_code=0,
                       error="", findings=[])
    f_old, f_new = _bl_finding("a"), _bl_finding("fresh")
    f_old.baseline_state, f_new.baseline_state = "unchanged", "new"
    cfg_new = {"policy": {"gate_baseline": "new"}}
    assert _exit_code([f_old], [ok_arm], cfg_new)[0] == 0        # baselined: passes
    assert _exit_code([f_old, f_new], [ok_arm], cfg_new)[0] == 1  # new high: gates
    assert _exit_code([f_old], [ok_arm], {"policy": {}})[0] == 1  # default gates all
    f_none = _bl_finding("x")                                     # no baseline set
    assert _exit_code([f_none], [ok_arm], cfg_new)[0] == 1        # fail-safe: gates


# --------------------------------------------------------------------------- #
# policy guard for store-closed findings
# --------------------------------------------------------------------------- #


def test_policy_skips_store_suppressed_findings():
    f = _finding()
    f.disposition.lifecycle = "suppressed"
    f.disposition.decided_by = m.DecidedBy(kind="human", decided_at=NOW, operator="o")
    f.disposition.decision_ref = "decision:root_cause:" + f.fingerprints.root_cause
    f.disposition.expires_at = LATER
    [d] = policy.apply_policy([f], {}, now_iso=NOW)
    assert d.action == "none" and d.reasons == ["lifecycle_suppressed"]
    assert f.disposition.lifecycle == "suppressed"      # untouched


# --------------------------------------------------------------------------- #
# end-to-end: CLI + orchestrator across two scans
# --------------------------------------------------------------------------- #


def test_scan_suppress_rescan_flow(tmp_path):
    arm = lambda: [FakeArm("semgrep", "scanner", "semgrep",  # noqa: E731
                           [orch_finding(source_id="semgrep", kind="scanner",
                                         vendor="semgrep", rc="flow")])]
    run1 = orch_run(arm(), tmp_path)
    assert run1.exit_code == 1
    [row] = json.loads((run1.out_dir / "findings.json").read_text())

    _allow_unsigned(tmp_path)
    rc = cli_main(["suppress", row["id"], "--operator", "clindell",
                   "--justification", "mitigated upstream",
                   "--vex-justification", "inline_mitigations_already_exist",
                   "--run", str(run1.out_dir), "--target", str(tmp_path)])
    assert rc == 0

    run2 = orch_run(arm(), tmp_path)
    assert run2.exit_code == 0                                    # suppressed: off the gate
    [f2] = run2.findings
    assert f2.disposition.lifecycle == "suppressed"
    assert f2.disposition.decided_by.operator == "clindell"
    assert run2.manifest["prior_decisions"][0]["action"] == "reapplied_suppressed"
    sarif = json.loads((run2.out_dir / "merged.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["suppressions"][0]["status"] == "accepted"


def test_outcome_mark_cli_feeds_history_term(tmp_path):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner",
                                  vendor="semgrep", rc="hist")])]
    run1 = orch_run(arms, tmp_path)
    [row] = json.loads((run1.out_dir / "findings.json").read_text())
    _allow_unsigned(tmp_path)
    for _ in range(2):
        assert cli_main(["outcome", "mark", row["id"], "--verdict", "fp",
                         "--operator", "clindell", "--run", str(run1.out_dir),
                         "--target", str(tmp_path)]) == 0
    run2 = orch_run(arms, tmp_path)
    [pj] = json.loads((run2.out_dir / "policy.json").read_text())
    assert pj["score"]["terms"]["history"] == -1.0                # capped, from 2 FP marks


def test_baseline_cli_and_delta_in_manifest(tmp_path):
    def arms(extra=False):
        fs = [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="base")]
        if extra:
            novel = orch_finding(source_id="semgrep", kind="scanner",
                                 vendor="semgrep", rc="novel")
            # different file, else the CWE-gated overlap tier clusters them together
            novel.locations = [dataclasses.replace(novel.locations[0], uri="app/y.py")]
            fs.append(novel)
        return [FakeArm("semgrep", "scanner", "semgrep", fs)]
    run1 = orch_run(arms(), tmp_path)
    _allow_unsigned(tmp_path)
    assert cli_main(["baseline", "set", "--run", str(run1.out_dir),
                     "--target", str(tmp_path), "--operator", "clindell"]) == 0
    run2 = orch_run(arms(extra=True), tmp_path, gate_baseline="new")
    bd = run2.manifest["baseline_delta"]
    assert bd["unchanged"] == 1 and bd["new"] == 1 and bd["absent"] == 0
    assert run2.exit_code == 1                                     # the new high finding gates
    run3 = orch_run(arms(), tmp_path, gate_baseline="new")
    assert run3.manifest["baseline_delta"]["new"] == 0
    assert run3.exit_code == 0                                     # brownfield adoption works
    assert cli_main(["baseline", "show", "--target", str(tmp_path)]) == 0
