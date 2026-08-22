"""Confidence scoring: log-odds p(true positive) per finding.

Design (plan §Scoring): a transparent additive log-odds model, NOT a black box.
Every term is a named constant below, every applied clamp is recorded in the
result, and the breakdown is persisted into ``validation.evidence_check["score"]``
so a suppression can always be audited back to its arithmetic.

Calibration honesty: ``calibration`` is ``"prior"`` until the weights are fitted
on ground truth (eval harness lane); the word "calibrated" must never appear in
reports unless ``calibration == "fitted"`` (with ECE reported). v1 is prior-only.

Clamps are the scoring shadow of the policy guardrails and are fail-safe in one
direction only — they can raise p or force human review, never lower p:
- crypto findings never score below 0.50 (and policy never auto-suppresses them);
- a deterministically-corroborated finding scores >= 0.60 unless a defender with
  100% verified citations showed the mitigating code;
- an unreliable panel opinion caps p at 0.50 *and* flags human review — an
  unreliable panel can never ground a suppression;
- no cross-file navigation or an uncovered category flags human review (the
  published failure mode: removing navigation dropped triage accuracy 96%->44%).

Floors apply before caps: a crypto finding judged by an unreliable panel lands
exactly at 0.50 + needs_human, which is the conservative corner.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .model import Finding, PanelOpinion, is_crypto_finding

# Log-odds prior for an uncorroborated, unvalidated candidate finding
# (sigmoid(-1.2) ~= 0.23 — roughly the base rate SAST literature reports).
PRIOR = -1.2

# Term weights (log-odds units).
W_FAMILY = 0.7            # per independent vendor family beyond the first
FAMILY_CAP = 1.4
W_DETERMINISTIC = 1.2     # any deterministic scanner corroborates
W_ADJUDICATOR = 1.5       # adjudicator true_positive (+) / false_positive (-)
W_REACHABILITY = {"external": 0.8, "internal": 0.3, "unreachable": -1.2, "unknown": 0.0}
W_CITATION = 0.3          # per verified citation: prosecutor (+) / defender (-)
CITATION_CAP = 0.9
W_SILENT = -0.35          # per eligible arm that stayed silent
SILENT_CAP = -1.05
W_HISTORY = 0.5           # per confirmed prior outcome for this root cause
HISTORY_CAP = 1.0

CRYPTO_FLOOR = 0.50
DETERMINISTIC_FLOOR = 0.60
UNRELIABLE_CAP = 0.50


@dataclass
class ScoreResult:
    p: float                      # p(true positive), post-clamp
    log_odds: float               # pre-clamp sum
    terms: dict[str, float]       # named contribution of every non-zero term
    clamps: list[str] = field(default_factory=list)
    needs_human_reasons: list[str] = field(default_factory=list)
    calibration: str = "prior"    # "fitted" only when weights come from ground truth


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _fully_verified_defender(panel: list[PanelOpinion]) -> bool:
    """A defender whose every citation resolved against the repo (>=1 citation)."""
    return any(op.role == "defender" and op.status == "ok" and op.citations
               and op.citation_pass_rate == 1.0 for op in panel)


def _term_adjudicator(panel: list[PanelOpinion]) -> float:
    for op in panel:
        if op.role == "adjudicator" and op.status == "ok":
            if op.verdict == "true_positive":
                return W_ADJUDICATOR * op.weight
            if op.verdict == "false_positive":
                return -W_ADJUDICATOR * op.weight
    return 0.0


def _term_evidence(panel: list[PanelOpinion]) -> float:
    up = sum(1 for op in panel if op.role == "prosecutor"
             for c in op.citations if c.verified is True)
    down = sum(1 for op in panel if op.role == "defender"
               for c in op.citations if c.verified is True)
    return min(up * W_CITATION, CITATION_CAP) - min(down * W_CITATION, CITATION_CAP)


def score_finding(f: Finding, *, history: dict | None = None) -> ScoreResult:
    """Score one finding. `history` is the (future) decision-store prior for this
    root cause: {"confirmed_tp": n, "confirmed_fp": n}; absent -> term is 0."""
    corr = f.corroboration
    terms: dict[str, float] = {}

    fams = max(0, corr.independent_family_count - 1)
    if fams:
        terms["corroboration"] = min(fams * W_FAMILY, FAMILY_CAP)
    if corr.deterministic_sources:
        terms["deterministic"] = W_DETERMINISTIC

    panel = f.validation.panel if f.validation else []
    if (adj := _term_adjudicator(panel)):
        terms["adjudicator"] = adj
    if f.validation and f.validation.reachability:
        r = W_REACHABILITY.get(f.validation.reachability.verdict, 0.0)
        if r:
            terms["reachability"] = r
    if (ev := _term_evidence(panel)):
        terms["evidence"] = ev

    reporting = set(corr.agent_sources) | set(corr.deterministic_sources)
    silent = [s for s in corr.eligible_sources if s not in reporting]
    if silent:
        terms["coverage_decline"] = max(len(silent) * W_SILENT, SILENT_CAP)

    if history:
        h = (int(history.get("confirmed_tp", 0)) - int(history.get("confirmed_fp", 0))) * W_HISTORY
        if h:
            terms["history"] = max(-HISTORY_CAP, min(h, HISTORY_CAP))

    log_odds = PRIOR + sum(terms.values())
    p = _sigmoid(log_odds)
    clamps: list[str] = []
    reasons: list[str] = []

    # floors first, caps second (see module docstring)
    if is_crypto_finding(f) and p < CRYPTO_FLOOR:
        p = CRYPTO_FLOOR
        clamps.append("crypto_floor")
    if corr.deterministic_sources and not _fully_verified_defender(panel) \
            and p < DETERMINISTIC_FLOOR:
        p = DETERMINISTIC_FLOOR
        clamps.append("deterministic_floor")
    if any(op.status == "unreliable" for op in panel):
        if p > UNRELIABLE_CAP:
            p = UNRELIABLE_CAP
            clamps.append("unreliable_cap")
        reasons.append("unreliable_panel_opinion")
    if f.validation and f.validation.no_cross_file_navigation:
        reasons.append("no_cross_file_navigation")
    if corr.uncovered:
        reasons.append("category_uncovered")

    return ScoreResult(p=round(p, 4), log_odds=round(log_odds, 4), terms=terms,
                       clamps=clamps, needs_human_reasons=reasons)


def attach(f: Finding, s: ScoreResult) -> None:
    """Persist the score onto the finding (only meaningful when validated):
    validation.confidence becomes p(true positive) and the full breakdown lands
    in evidence_check["score"] for audit. The raw panel vote fraction remains
    derivable from validation.panel."""
    if f.validation is None:
        return
    f.validation.confidence = round(s.p, 3)
    f.validation.calibration = s.calibration
    f.validation.evidence_check["score"] = {
        "log_odds": s.log_odds, "terms": dict(s.terms), "clamps": list(s.clamps),
        "needs_human_reasons": list(s.needs_human_reasons),
    }
