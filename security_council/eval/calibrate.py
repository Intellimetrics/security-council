"""Calibration fitting from a labeled corpus run — closed-form, honestly scoped.

The OWASP Benchmark corpus (import_owasp) exercises exactly one production
situation: a deterministic semgrep finding standing alone, per CWE family. So
this is NOT a 7-term regression — it fits per-family empirical log-odds
``P(true positive | semgrep detection, family)`` with Laplace smoothing and a
Wilson interval, on a deterministic stratified half-split with a held-out half.

Labeling unit is the CASE, not the cluster (Benchmark's own scorecard
convention): the corpus is generated, near-identical code, so context-tier
clustering merges true and false test files into mixed clusters — a per-cluster
label would be ambiguous there, while per-case detection is exact.

Honesty properties, council-reviewed (R7) and enforced here + by tests:
- families below ``min_n`` train detections never enter the table; unmapped
  categories (family None) are excluded and counted, never pooled into "other";
- every family entry carries per-category counts (a precision skew between
  pooled categories, e.g. sqli vs cmdi, stays visible) and a ``floor_binding``
  flag (the deployed 0.60 deterministic floor censors any lower fitted value);
- ECE/Brier are reported on the held-out half, both pre-clamp and post-clamp
  (the deployed floors only ever raise p; post-clamp is what users experience);
- the record states its caveats: fitted p is prevalence-conditional
  (Benchmark is ~50% real by construction), the corpus is templated so a random
  split leaks near-twins and the effective n is below the nominal n (CIs and
  ECE flatter accordingly), and scope is limited to the corpus language;
- nothing here touches score.py's clamps or the policy guardrails.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone

from ..model import Finding
from . import metrics

RECORD_SCHEMA = "security-council/calibration/v1"
DEFAULT_MIN_N = 30
DEFAULT_SMOOTHING = 1.0   # Laplace add-a on both outcomes
Z95 = 1.959963984540054


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    category: str
    family: str | None
    real: bool        # ground truth: true vulnerability vs safe decoy
    detected: bool    # a CWE-matched finding reported this case's file


def label_cases(expected: dict, findings: list[Finding]) -> tuple[list[CaseOutcome], dict]:
    """Label every ground-truth case via the SAME matcher the eval gate uses.
    Returns (outcomes, audit) — audit counts what was excluded and why:
    findings matching no case are Benchmark out-of-scope noise, never labeled."""
    matches, noise = metrics.match(expected, findings)
    out: list[CaseOutcome] = []
    for kind, real in (("findings", True), ("decoys", False)):
        for case in expected.get(kind) or []:
            out.append(CaseOutcome(case_id=case["id"], category=case.get("category", ""),
                                   family=case.get("family"), real=real,
                                   detected=bool(matches.get(case["id"]))))
    audit = {
        "findings_total": len(findings),
        "noise_findings_excluded": len(noise),
        "cases_unmapped_family": sum(1 for o in out if o.family is None),
        "categories_unmapped": sorted({o.category for o in out if o.family is None}),
    }
    return out, audit


def _wilson(tp: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    phat, z2 = tp / n, Z95 * Z95
    denom = 1 + z2 / n
    center = (phat + z2 / (2 * n)) / denom
    half = (Z95 * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))) / denom
    return (round(max(0.0, center - half), 4), round(min(1.0, center + half), 4))


def _logit(p: float) -> float:
    return math.log(p / (1 - p))


def _split(outcomes: list[CaseOutcome], seed: int) -> tuple[list[CaseOutcome], list[CaseOutcome]]:
    """Deterministic stratified half-split: within each (category, real) stratum
    so both halves see the same case mix. Caveat (recorded): Benchmark cases are
    templated near-duplicates, so twins leak across any random split."""
    strata: dict[tuple[str, bool], list[CaseOutcome]] = {}
    for o in outcomes:
        strata.setdefault((o.category, o.real), []).append(o)
    train: list[CaseOutcome] = []
    test: list[CaseOutcome] = []
    rng = random.Random(seed)
    for key in sorted(strata, key=str):
        rows = sorted(strata[key], key=lambda o: o.case_id)
        rng.shuffle(rows)
        half = len(rows) // 2
        train += rows[:half]
        test += rows[half:]
    return train, test


def _clamped(family: str, p: float) -> float:
    from .. import score
    p = max(p, score.DETERMINISTIC_FLOOR)          # deterministic singleton, no defender
    if family == "crypto":
        p = max(p, score.CRYPTO_FLOOR)
    return p


def _ece_brier(rows: list[CaseOutcome], table: dict[str, dict]) -> dict:
    """Held-out calibration error of the per-family constant predictor, pre- and
    post-clamp. R7 caveat baked into the numbers' presentation: for a
    one-feature four-bucket model the meaningful figures are the per-family
    held-out empirical precisions next to the fitted p, not the aggregate ECE."""
    per_family: dict[str, dict] = {}
    n_total = ece_pre = ece_post = brier_pre = brier_post = 0.0
    for fam, fit in table.items():
        rel = [o for o in rows if o.detected and o.family == fam]
        if not rel:
            continue
        emp = sum(1 for o in rel if o.real) / len(rel)
        p_pre, p_post = fit["p"], _clamped(fam, fit["p"])
        per_family[fam] = {"n_test": len(rel), "empirical": round(emp, 4),
                           "p": p_pre, "p_clamped": round(p_post, 4)}
        n_total += len(rel)
        ece_pre += len(rel) * abs(p_pre - emp)
        ece_post += len(rel) * abs(p_post - emp)
        for o in rel:
            y = 1.0 if o.real else 0.0
            brier_pre += (p_pre - y) ** 2
            brier_post += (p_post - y) ** 2
    if not n_total:
        return {"test_detections": 0, "per_family": {}}
    return {"test_detections": int(n_total),
            "ece_preclamp": round(ece_pre / n_total, 4),
            "ece_postclamp": round(ece_post / n_total, 4),
            "brier_preclamp": round(brier_pre / n_total, 4),
            "brier_postclamp": round(brier_post / n_total, 4),
            "per_family": per_family}


def fit(outcomes: list[CaseOutcome], *, corpus_meta: dict, scanner: dict,
        languages: list[str] | None = None, audit: dict | None = None,
        smoothing: float = DEFAULT_SMOOTHING, min_n: int = DEFAULT_MIN_N,
        seed: int = 0, created_at: str | None = None) -> dict:
    """Fit the per-family table on half the corpus, validate on the other half.

    Only NAMED families enter the table (family None — unmapped CWEs — is
    excluded: pooling them under "other" would blend unrelated categories)."""
    from .. import score
    families = {o.family for o in outcomes if o.family}
    train, test = _split(outcomes, seed)
    table: dict[str, dict] = {}
    excluded: dict[str, str] = {}
    for fam in sorted(families):
        rows = [o for o in train if o.family == fam and o.detected]
        det, tp = len(rows), sum(1 for o in rows if o.real)
        if det < min_n:
            excluded[fam] = f"train detections {det} < min_n {min_n}"
            continue
        p = (tp + smoothing) / (det + 2 * smoothing)
        per_cat: dict[str, dict] = {}
        for o in rows:
            c = per_cat.setdefault(o.category, {"detections": 0, "tp": 0})
            c["detections"] += 1
            c["tp"] += 1 if o.real else 0
        table[fam] = {"detections": det, "tp": tp, "p": round(p, 4),
                      "logit": round(_logit(p), 4), "wilson95": list(_wilson(tp, det)),
                      "floor_binding": p < score.DETERMINISTIC_FLOOR,
                      "per_category": per_cat}
    n_real = sum(1 for o in outcomes if o.real)
    stamp = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "record": RECORD_SCHEMA,
        "created_at": stamp,
        "corpus": dict(corpus_meta),
        "scanner": dict(scanner),
        "method": (f"per-family case-level empirical log-odds; Laplace a={smoothing}; "
                   f"min_n={min_n}; stratified half-split seed={seed}"),
        "scope": {"deterministic_singleton": True,
                  "source_families": [scanner.get("family", "semgrep")],
                  "languages": list(languages or ["java"]),
                  "prevalence": round(n_real / len(outcomes), 4) if outcomes else None},
        "families": table,
        "excluded_families": excluded,
        "labeling_audit": dict(audit or {}),
        "metrics": _ece_brier(test, table),
        "caveats": [
            "fitted p is prevalence-conditional: Benchmark is ~50% real by construction; "
            "P(TP | detection) shifts with a repo's true base rate",
            "corpus cases are templated near-duplicates: a random split leaks twins, so "
            "effective n is below nominal n and held-out ECE / Wilson CIs flatter the fit",
            "labels are per CASE (Benchmark scorecard convention), while production scores "
            "clusters; on generated code context-tier clustering mixes true/false files",
            "deployed floors are action-gates, not probability estimates: where "
            "floor_binding is true the deployed value is the floor, not the fitted p",
        ],
    }
