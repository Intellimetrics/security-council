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
- a deterministically-corroborated finding scores >= 0.60 unless a defender who
  actually refuted, with 100% verified citations, showed the mitigating code
  *in the finding's own code* (R10: "verified" proves a reference RESOLVES, not
  that a claim is SUPPORTED, so the citation must also be anchored);
- an unreliable panel opinion caps p at 0.50 *and* flags human review — an
  unreliable panel can never ground a suppression;
- an attempted refutation that cited nothing flags human review (the panel
  already refuses to count it; this makes the report say so);
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
    calibration_record: str | None = None   # record id whenever a fitted base was used


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


# A citation spanning more than this many lines is not pointing at anything in
# particular. llm-council's verify_ref bounds start_line but NOT end_line, so a
# whole-file span would otherwise "verify" and trivially intersect any anchor.
MAX_ANCHOR_SPAN_LINES = 80
# How far from the finding's own lines a citation may sit and still be about it
# (a mitigating guard clause usually sits just above the sink).
ANCHOR_WINDOW_LINES = 25


def _anchor_ranges(f: Finding) -> dict[str, list[tuple[int, int]]]:
    """The finding's own code: every location plus every data-flow step. A
    refutation has to point at one of these to be evidence *about this finding*."""
    out: dict[str, list[tuple[int, int]]] = {}
    for loc in [*f.locations, *(st.location for st in f.data_flow)]:
        out.setdefault(loc.uri, []).append((loc.start_line, loc.end_line))
    return out


def _is_anchored(c, anchors: dict[str, list[tuple[int, int]]]) -> bool:
    """True when a VERIFIED citation lands on the finding's own code."""
    if c.verified is not True:
        return False
    if (c.end_line - c.start_line) > MAX_ANCHOR_SPAN_LINES:
        return False
    return any(c.start_line <= end + ANCHOR_WINDOW_LINES
               and c.end_line >= start - ANCHOR_WINDOW_LINES
               for start, end in anchors.get(c.path, ()))


def _fully_verified_defender(panel: list[PanelOpinion], finding: Finding) -> bool:
    """A defender that actually refuted, whose every citation resolved, and at
    least one of whose citations lands on the finding's own code.

    R10 (2026-08-25): this used to ask only for `>= 1 citation` and
    `citation_pass_rate == 1.0`. Since `verified` proves a reference RESOLVES —
    llm-council checks path-resolves and `start_line <= line_count`, nothing
    more — a defender citing `README.md:1-1` was a "fully verified defender",
    which cleared G2 and let a semgrep-corroborated finding be refuted out of
    the CI gate (reproduced). The anchor is what ties evidence to the claim.
    The verdict check closes a second hole: the function gating refutation did
    not require the defender to be refuting.
    """
    anchors = _anchor_ranges(finding)
    return any(op.role == "defender" and op.status == "ok"
               and op.verdict == "false_positive"
               and op.citations and op.citation_pass_rate == 1.0
               and any(_is_anchored(c, anchors) for c in op.citations)
               for op in panel)


def _term_adjudicator(panel: list[PanelOpinion]) -> float:
    for op in panel:
        if op.role == "adjudicator" and op.status == "ok":
            if op.verdict == "true_positive":
                return W_ADJUDICATOR * op.weight
            if op.verdict == "false_positive":
                return -W_ADJUDICATOR * op.weight
    return 0.0


def _term_evidence(panel: list[PanelOpinion], finding: Finding) -> float:
    """Citations move p only when they are from an INDEPENDENT, `ok` opinion and
    ANCHORED to the finding's own code (R11): a verified reference to README.md
    line 1 is not evidence about a SQL sink in reports.py, and this term used to
    count it at full weight in either direction."""
    anchors = _anchor_ranges(finding)

    def _n(role: str) -> int:
        return sum(1 for op in panel
                   if op.role == role and op.independent and op.status == "ok"
                   for c in op.citations if _is_anchored(c, anchors))

    up, down = _n("prosecutor"), _n("defender")
    return min(up * W_CITATION, CITATION_CAP) - min(down * W_CITATION, CITATION_CAP)


def score_finding(f: Finding, *, history: dict | None = None,
                  calibration=None) -> ScoreResult:
    """Score one finding. `history` is the decision-store prior for this root
    cause: {"confirmed_tp": n, "confirmed_fp": n}; absent -> term is 0.

    `calibration` is an optional loaded `calibration.Calibration` record (R7):
    for an in-scope finding its fitted family logit REPLACES the hand-set base
    (PRIOR + W_DETERMINISTIC) as the ``fitted_base`` term; every other term and
    every clamp is untouched. The result is labeled ``fitted`` only when no
    other term contributes — a composed score honestly stays ``prior`` even
    though its base was measured (the breakdown records the record id)."""
    corr = f.corroboration
    terms: dict[str, float] = {}
    fitted = calibration.base_for(f) if calibration is not None else None

    fams = max(0, corr.independent_family_count - 1)
    if fams:
        terms["corroboration"] = min(fams * W_FAMILY, FAMILY_CAP)
    if corr.deterministic_sources:
        if fitted is not None:
            terms["fitted_base"] = round(fitted, 4)
        else:
            terms["deterministic"] = W_DETERMINISTIC

    panel = f.validation.panel if f.validation else []
    if (adj := _term_adjudicator(panel)):
        terms["adjudicator"] = adj
    if f.validation and f.validation.reachability:
        r = W_REACHABILITY.get(f.validation.reachability.verdict, 0.0)
        if r:
            terms["reachability"] = r
    if (ev := _term_evidence(panel, f)):
        terms["evidence"] = ev

    reporting = set(corr.agent_sources) | set(corr.deterministic_sources)
    silent = [s for s in corr.eligible_sources if s not in reporting]
    if silent:
        terms["coverage_decline"] = max(len(silent) * W_SILENT, SILENT_CAP)

    if history:
        h = (int(history.get("confirmed_tp", 0)) - int(history.get("confirmed_fp", 0))) * W_HISTORY
        if h:
            terms["history"] = max(-HISTORY_CAP, min(h, HISTORY_CAP))

    # fitted_base is an absolute measured intercept, not an offset from PRIOR
    log_odds = (0.0 if fitted is not None else PRIOR) + sum(terms.values())
    p = _sigmoid(log_odds)
    clamps: list[str] = []
    reasons: list[str] = []

    # floors first, caps second (see module docstring)
    if is_crypto_finding(f) and p < CRYPTO_FLOOR:
        p = CRYPTO_FLOOR
        clamps.append("crypto_floor")
    if corr.deterministic_sources and not _fully_verified_defender(panel, f) \
            and p < DETERMINISTIC_FLOOR:
        p = DETERMINISTIC_FLOOR
        clamps.append("deterministic_floor")
    if any(op.status == "unreliable" for op in panel):
        if p > UNRELIABLE_CAP:
            p = UNRELIABLE_CAP
            clamps.append("unreliable_cap")
        reasons.append("unreliable_panel_opinion")
    # R10: an attempt to refute WITHOUT evidence is the wrongful-suppression
    # shape. The panel already refuses to count it (see synthesize_validation),
    # but surface it so the report says why the finding stayed open.
    if any(op.status == "unevidenced" and op.verdict == "false_positive" for op in panel):
        reasons.append("unevidenced_refutation_attempt")
    if f.validation and f.validation.no_cross_file_navigation:
        reasons.append("no_cross_file_navigation")
    if corr.uncovered:
        reasons.append("category_uncovered")

    strict_scope = fitted is not None and set(terms) == {"fitted_base"}
    return ScoreResult(p=round(p, 4), log_odds=round(log_odds, 4), terms=terms,
                       clamps=clamps, needs_human_reasons=reasons,
                       calibration="fitted" if strict_scope else "prior",
                       calibration_record=(calibration.record_id
                                           if fitted is not None else None))


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
    if s.calibration_record:
        f.validation.evidence_check["score"]["calibration_record"] = s.calibration_record
