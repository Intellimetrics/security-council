"""The replay-based eval gate (R3 lane 1): zero wrongful suppression on ground truth.

Replays the recorded raw fixtures for every arm family through the real
normalize -> cluster -> coverage -> panel-verdict -> score -> policy pipeline and
gates on EXPECTED.yaml. These tests ARE the CI gate: any true positive ending
demoted or hidden fails the suite, in every posture up to fully-armed
auto-suppression with adversarial history.
"""
import json
import pathlib

from security_council import policy
from security_council.cli import main as cli_main
from security_council.eval import runner
from security_council.model import assert_invariants

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _armed(**over):
    return {"policy": {**policy.POLICY_DEFAULTS, "auto_suppress": True,
                       "accept_suppression_risk": True, **over}}


def test_gate_default_posture():
    run = runner.run_eval(FIXTURES)
    mt = run.report.metrics
    assert run.report.violations == []
    assert mt["recall"] == 1.0 and mt["missed"] == []                 # 7/7 detected
    assert mt["true_positive_suppression_rate"] == 0.0
    assert mt["crypto_suppression_rate"] == 0.0
    assert mt["decoys"] == {"FP-MD5-CACHE": "demoted/refuted"}        # demoted, not hidden
    assert run.report.disposition_actions == {"none": 21, "demote": 1}
    for f in run.findings:
        assert_invariants(f)


def test_gate_pins_corpus_shape():
    """Pin the replay corpus so silent fixture drift is visible."""
    run = runner.run_eval(FIXTURES)
    mt = run.report.metrics
    assert mt["findings_total"] == 22 and mt["tp_findings"] == 20
    assert mt["noise_findings"] == 1                     # codex-security debug-enabled
    # SQLi + command injection share one root-cause cluster, exactly as live
    assert run.report.matches["F-SQLI-REPORTS"] == run.report.matches["F-CMDI-REPORTS"]
    assert len(run.report.matches["F-DEP-URLLIB3"]) == 15   # osv advisory clusters


def test_gate_fully_armed_past_shadow():
    """Auto-suppression armed and past shadow: no TP may be touched, and the
    crypto decoy must stay demoted-not-hidden (G1 + crypto score floor)."""
    run = runner.run_eval(FIXTURES, config=_armed(), prior_runs=99)
    assert run.report.violations == []
    assert run.report.metrics["true_positive_suppression_rate"] == 0.0
    decoy = next(f for f in run.findings
                 if run.report.matches["FP-MD5-CACHE"] == [f.id])
    assert decoy.disposition.state == "refuted" and decoy.disposition.lifecycle == "open"
    [d] = [d for d in run.decisions if d.finding_id == decoy.id]
    assert d.action == "demote" and "G1_crypto_never_auto_suppressed" in d.guardrails_failed


def test_gate_adversarial_history():
    """R3 risk check: hostile confirmed-FP history on every root cause must not
    move a single validated TP (history can lower p, but only a refuted state
    can ever suppress — and the panel validated them)."""
    base = runner.run_eval(FIXTURES)
    history = {f.fingerprints.root_cause: {"confirmed_fp": 5} for f in base.findings}
    run = runner.run_eval(FIXTURES, config=_armed(suppress_below=0.99),
                          prior_runs=99, history=history)
    assert run.report.violations == []
    assert run.report.metrics["true_positive_suppression_rate"] == 0.0
    assert run.report.metrics["crypto_suppression_rate"] == 0.0


def test_gate_catches_wrongful_demotion():
    """Meta-test: the gate itself must detect the published failure mode. A
    panel that wrongly refutes the must_not_demote crypto TP -> violation."""
    verdicts = {"F-CRYPTO-MD5-PW": "false_positive", "FP-MD5-CACHE": "false_positive"}
    run = runner.run_eval(FIXTURES, verdicts=verdicts)
    assert any("F-CRYPTO-MD5-PW" in v and "must_not_demote" in v and "crypto" in v
               for v in run.report.violations), run.report.violations
    assert run.report.metrics["crypto_suppression_rate"] > 0.0


def test_gate_catches_open_decoy():
    """A decoy the panel wrongly confirms must violate its must_end_as."""
    verdicts = {"FP-MD5-CACHE": "true_positive"}
    run = runner.run_eval(FIXTURES, verdicts=verdicts)
    assert any("FP-MD5-CACHE" in v for v in run.report.violations), run.report.violations


def test_cli_eval_subcommand(capsys):
    assert cli_main(["eval", "--fixtures", str(FIXTURES)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["violations"] == [] and out["metrics"]["recall"] == 1.0
    assert cli_main(["eval", "--fixtures", str(FIXTURES / "nope")]) == 2
