"""R12 — the coverage model: what an arm actually examined.

Four council rounds on the 0.1.0 ship review all found the same shape of bug: a
scan that examined less than it claimed reported clean. The cause was that
coverage was a per-arm BOOLEAN. These tests pin the tri-state that replaced it,
and the three consumers that must not drift apart again: the gate, the
corroboration context, and the SARIF execution status.
"""

from __future__ import annotations

import json

from security_council.arms.base import ArmResult
from security_council.export import sarif as sarif_mod
from security_council.normalize import coverage as cov


def _r(ok=True, **coverage):
    return ArmResult(name="a", kind="scanner", family="f", ok=ok, exit_code=0,
                     error="", findings=[], coverage=coverage)


# --------------------------------------------------------------------------- #
# the verdict itself
# --------------------------------------------------------------------------- #


def test_verdict_none_for_anything_that_vouches_for_nothing():
    assert cov.coverage_verdict(_r(ok=False)) == cov.NONE
    assert cov.coverage_verdict(_r(coverage_unverified=True)) == cov.NONE


def test_verdict_partial_for_a_scan_that_covered_less_than_its_scope():
    assert cov.coverage_verdict(_r(partial_scan=True)) == cov.PARTIAL
    assert cov.coverage_verdict(_r(cost_stopped=True)) == cov.PARTIAL
    assert cov.coverage_verdict(_r(completion="partial")) == cov.PARTIAL
    assert cov.coverage_verdict(_r(completion="declined")) == cov.PARTIAL
    assert cov.coverage_verdict(_r(declined_categories=["crypto"])) == cov.PARTIAL


def test_verdict_verified_including_nothing_in_scope():
    assert cov.coverage_verdict(_r(completion="complete")) == cov.VERIFIED
    assert cov.coverage_verdict(_r()) == cov.VERIFIED
    # osv on a repo with no dependency manifests: nothing in scope is an honest
    # clean for that arm's categories, not a failure
    assert cov.coverage_verdict(_r(ok=True, not_applicable=True)) == cov.VERIFIED


def test_partial_is_masked_by_findings_no_longer_matters():
    """The dedicated arms compute `coverage_unverified` as
    `not findings and not verified`, so it is masked whenever findings exist.
    `completion` still carries the truth, and the verdict reads that."""
    assert cov.coverage_verdict(_r(completion="partial", coverage_unverified=False)) == cov.PARTIAL


# --------------------------------------------------------------------------- #
# consumer 1: corroboration — silence only means something from a live source
# --------------------------------------------------------------------------- #


def test_none_arm_gets_no_vote():
    sr = cov.source_run_for(_r(coverage_unverified=True))
    assert sr.ran is False


def test_partial_arm_votes_only_on_families_it_did_not_decline():
    sr = cov.source_run_for(_r(completion="partial", declined_categories=["crypto", "xss"]))
    assert sr.ran is True
    assert "crypto" not in sr.supported_families and "xss" not in sr.supported_families
    assert "injection" in sr.supported_families


def test_verified_arm_supports_everything():
    assert cov.source_run_for(_r(completion="complete")).supported_families is None


# --------------------------------------------------------------------------- #
# consumer 2: SARIF execution status
# --------------------------------------------------------------------------- #


def test_sarif_reports_execution_success_when_coverage_is_complete():
    doc = sarif_mod.to_sarif([], tool_version="1", run_id="r")
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_sarif_reports_a_degraded_run_as_unsuccessful():
    """Without this a consumer — GitHub code scanning included — cannot tell a
    partial scan from a clean one."""
    degr = [{"kind": "partial_coverage", "arm": "codex", "detail": "declined 3 categories"}]
    doc = sarif_mod.to_sarif([], tool_version="1", run_id="r", degradations=degr)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert "partial_coverage" in json.dumps(inv["toolExecutionNotifications"])


# --------------------------------------------------------------------------- #
# round 5: silence only counts from a source that covered the ground
# --------------------------------------------------------------------------- #


def test_a_partial_arm_may_not_decline():
    """A timed-out arm has no `declined_categories`, so `supported_families`
    cannot express its unknown scope. Without `may_decline` it stayed eligible
    on EVERY family and counted as silent — the same suppression pressure the
    tri-state was built to remove."""
    assert cov.source_run_for(_r(partial_scan=True)).may_decline is False
    assert cov.source_run_for(_r(completion="complete")).may_decline is True


def test_partial_arm_silence_is_neither_credit_nor_penalty():
    from security_council.model import Corroboration  # noqa: F401
    from tests.test_validate import _finding
    f = _finding()
    partial = cov.SourceRun("codex", "agent_cli", "codex", ran=True, may_decline=False)
    verified = cov.SourceRun("semgrep", "scanner", "semgrep", ran=True)
    corr = cov.compute(f, cov.RunContext(sources=[partial, verified]))
    assert "codex" not in corr.declined_sources     # silence proves nothing
    assert "codex" not in corr.eligible_sources     # and does not dilute the denominator


def test_not_applicable_cannot_rescue_an_unverified_arm():
    """Ordering: `coverage_unverified` is the stronger signal."""
    assert cov.coverage_verdict(_r(not_applicable=True, coverage_unverified=True)) == cov.NONE
