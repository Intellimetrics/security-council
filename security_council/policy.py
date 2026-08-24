"""Disposition policy: what a score is allowed to *do* (guardrails G1-G8).

The published risk this module exists to contain: agentic triage that wrongly
suppressed 22% of true vulnerabilities (>50% for crypto CWEs). Everything here
is fail-closed and auditable:

- **Auto-demote, never auto-close** (D7): a panel-refuted finding is demoted —
  it renders as SARIF ``suppressions[status=underReview]`` and drops out of the
  CI gate — but its lifecycle stays ``open`` and it stays in every report.
- **Auto-suppression is off by default** and doubly gated: it takes BOTH
  ``policy.auto_suppress: true`` AND ``policy.accept_suppression_risk: true``
  in config (the operator's explicit acknowledgement), and the first
  ``shadow_runs`` runs are shadow mode — the would-be decision is recorded but
  the finding stays open (G4).
- Guardrails, checked at decision time and again structurally by the model
  invariants (I6/I7/I11) via ``assert_invariants`` on every mutated finding:
  G1 crypto is never auto-suppressed (also a score floor).
  G2 a deterministically-corroborated finding cannot be LLM-refuted at all
     unless a defender with 100% verified citations showed the mitigating
     code; without that it escalates to ``needs_human`` instead of demoting.
  G3 every hidden disposition carries full attribution (model id, prompt hash,
     panel hash, decision_ref, expiry) — I6 makes the alternative unrepresentable.
  G4 shadow mode for the first ``shadow_runs`` runs.
  G5 decisions are scoped to one root cause (the decision_ref embeds the
     root-cause fingerprint) — never a rule, CWE, or glob.
  G6 suppressions expire (``suppression_expiry_days``, default 90) and reopen.
  G7 critical severity is never auto-suppressed.
  G8 context drift -> advisory-only + re-validate: enforced by construction for
     now — decisions are not yet persisted across runs, so every run re-scores
     from fresh evidence; the check becomes explicit when decisions.py lands.

Escalation to human review is the *safe* direction and needs no gate: an
unreliable panel opinion, a missing cross-file navigation, an uncovered
category, or an unsupported refutation of a deterministic finding all move the
state to ``needs_human``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .model import (
    CLOSED_LIFECYCLES,
    DecidedBy,
    Finding,
    assert_invariants,
    is_crypto_finding,
)
from .score import ScoreResult, _fully_verified_defender, attach, score_finding

POLICY_DEFAULTS = {
    "auto_suppress": False,
    "accept_suppression_risk": False,
    "shadow_runs": 5,
    "suppress_below": 0.10,
    "suppression_expiry_days": 90,
}

_RUN_DIR_RE = re.compile(r"^\d{8}_\d{6}$")


@dataclass
class PolicyDecision:
    finding_id: str
    action: str                   # none | demote | escalate_human | shadow_suppress | suppress
    p: float
    reasons: list[str] = field(default_factory=list)
    guardrails_failed: list[str] = field(default_factory=list)
    score: ScoreResult | None = None


def is_armed(config: dict) -> bool:
    """Auto-suppression takes BOTH flags (explicit operator acknowledgement)."""
    cfg = {**POLICY_DEFAULTS, **(config.get("policy") or {})}
    return bool(cfg["auto_suppress"]) and bool(cfg["accept_suppression_risk"])


def count_prior_runs(runs_root: Path, current_run_id: str) -> int:
    """Completed sibling runs, counted strictly by run-id shape so unrelated
    files in a custom --out parent can only *under*-count (which keeps shadow
    mode on longer — the fail-safe direction)."""
    try:
        return sum(1 for d in Path(runs_root).iterdir()
                   if d.is_dir() and d.name != current_run_id
                   and _RUN_DIR_RE.match(d.name) and (d / "manifest.json").is_file())
    except OSError:
        return 0


def _panel_sha256(f: Finding) -> str | None:
    if not f.validation or not f.validation.panel:
        return None
    key = json.dumps(sorted((op.role, op.participant, op.model_id or "", op.verdict)
                            for op in f.validation.panel))
    return hashlib.sha256(key.encode()).hexdigest()


def _stamp(f: Finding, now_iso: str) -> None:
    """Attribute the automatic decision that is about to be recorded."""
    panel = f.validation.panel if f.validation else []
    adj = next((op for op in panel if op.role == "adjudicator" and op.model_id), None)
    any_model = next((op for op in panel if op.model_id), None)
    src = adj or any_model
    f.disposition.decided_by = DecidedBy(
        kind="auto", decided_at=now_iso,
        model_id=src.model_id if src else None,
        prompt_sha256=panel[0].prompt_sha256 if panel else None,
        panel_sha256=_panel_sha256(f))


def _suppression_guardrails(f: Finding, cfg: dict) -> list[str]:
    failed = []
    if not cfg["auto_suppress"]:
        failed.append("auto_suppress_disabled")
    elif not cfg["accept_suppression_risk"]:
        failed.append("suppression_risk_not_acknowledged")
    if is_crypto_finding(f):
        failed.append("G1_crypto_never_auto_suppressed")
    if f.severity.label == "critical":
        failed.append("G7_critical_never_auto_suppressed")
    return failed


def _suppress(f: Finding, s: ScoreResult, cfg: dict, now_iso: str) -> None:
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    expires = now + timedelta(days=int(cfg["suppression_expiry_days"]))
    d = f.disposition
    d.lifecycle = "suppressed"
    d.decision_ref = f"decision:root_cause:{f.fingerprints.root_cause}"      # G5 scope
    d.expires_at = expires.isoformat().replace("+00:00", "Z")                # G6 expiry
    d.sarif_suppression = {
        "kind": "external", "status": "accepted",
        "justification": (f"security-council validator panel refuted this finding "
                          f"(p_true={s.p:.3f}); {d.decision_ref}"),
    }
    unreachable = bool(f.validation and f.validation.reachability
                       and f.validation.reachability.verdict == "unreachable")
    d.vex_status = "not_affected"
    d.vex_justification = ("vulnerable_code_not_in_execute_path" if unreachable
                           else "inline_mitigations_already_exist")


def apply_policy(findings: list[Finding], config: dict, *, now_iso: str,
                 prior_runs: int = 0, history: dict[str, dict] | None = None,
                 calibration=None) -> list[PolicyDecision]:
    """Score every finding and apply the disposition policy in place.

    `history` (future decisions.py lane) maps root_cause fingerprint -> outcome
    counts. `calibration` is an optional loaded fitted record (R7) forwarded to
    the scorer; it never touches the guardrails below. Every mutated finding
    passes assert_invariants — fail-closed."""
    cfg = {**POLICY_DEFAULTS, **(config.get("policy") or {})}
    shadow = prior_runs < int(cfg["shadow_runs"])                            # G4
    decisions: list[PolicyDecision] = []

    for f in findings:
        if f.disposition.lifecycle in CLOSED_LIFECYCLES:
            # closed by a stored/operator decision — policy never restamps it
            decisions.append(PolicyDecision(finding_id=f.id, action="none", p=0.0,
                                            reasons=[f"lifecycle_{f.disposition.lifecycle}"]))
            continue
        h = (history or {}).get(f.fingerprints.root_cause)
        s = score_finding(f, history=h, calibration=calibration)
        if f.validation is None:
            decisions.append(PolicyDecision(finding_id=f.id, action="none", p=s.p,
                                            reasons=["not_validated"], score=s))
            continue
        attach(f, s)
        state = f.disposition.state
        reasons = list(s.needs_human_reasons)

        # G2: an LLM panel alone cannot refute what a deterministic scanner saw.
        if state == "refuted" and f.corroboration.deterministic_sources \
                and not _fully_verified_defender(f.validation.panel):
            reasons.append("G2_deterministic_refutation_unsupported")

        if reasons and state != "needs_human":
            f.disposition.state = "needs_human"
            _stamp(f, now_iso)
            decisions.append(PolicyDecision(finding_id=f.id, action="escalate_human",
                                            p=s.p, reasons=reasons, score=s))
        elif state == "refuted":
            # demote: stays open, renders as suppressions[underReview], off the gate
            _stamp(f, now_iso)
            failed = _suppression_guardrails(f, cfg)
            if s.p > float(cfg["suppress_below"]):
                failed.append("p_above_suppress_threshold")
            action, reasons = "demote", ["panel_refuted_demoted_not_closed"]
            if not failed:
                if shadow:
                    f.disposition.shadow = True
                    action = "shadow_suppress"
                    reasons = [f"shadow_run_{prior_runs + 1}_of_{cfg['shadow_runs']}"]
                else:
                    _suppress(f, s, cfg, now_iso)
                    action = "suppress"
                    reasons = ["all_guardrails_passed"]
            decisions.append(PolicyDecision(finding_id=f.id, action=action, p=s.p,
                                            reasons=reasons, guardrails_failed=failed,
                                            score=s))
        else:
            decisions.append(PolicyDecision(finding_id=f.id, action="none", p=s.p,
                                            reasons=[f"state_{state}"], score=s))
        assert_invariants(f)
    return decisions


def decisions_summary(decisions: list[PolicyDecision]) -> dict:
    counts: dict[str, int] = {}
    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1
    return counts


def decisions_to_json(decisions: list[PolicyDecision]) -> list[dict]:
    out = []
    for d in decisions:
        row = {"finding_id": d.finding_id, "action": d.action, "p_true": d.p,
               "reasons": d.reasons, "guardrails_failed": d.guardrails_failed}
        if d.score is not None:
            row["score"] = {"log_odds": d.score.log_odds, "terms": d.score.terms,
                            "clamps": d.score.clamps, "calibration": d.score.calibration}
            if d.score.calibration_record:
                row["score"]["calibration_record"] = d.score.calibration_record
        out.append(row)
    return out
