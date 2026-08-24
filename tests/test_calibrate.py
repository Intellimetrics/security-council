"""eval/calibrate.py: case labeling, per-family closed-form fit, honest record."""

import math

from security_council.eval import calibrate as cal
from security_council.eval import import_owasp as io_
from security_council.score import DETERMINISTIC_FLOOR


def mk_outcomes(fam, category, n_tp, n_fp, *, undetected_true=0, start=0):
    rows = [(True, True)] * n_tp + [(False, True)] * n_fp + [(True, False)] * undetected_true
    return [cal.CaseOutcome(f"T{start + i:05}", category, fam, real, det)
            for i, (real, det) in enumerate(rows)]


def test_label_cases_reuses_eval_matcher_and_audits_exclusions(tmp_path):
    from tests.test_import_owasp import write_benchmark
    from tests.test_cluster import mk
    cases, _ = io_.load_cases(write_benchmark(tmp_path))
    expected = io_.ground_truth(cases)
    hit = mk(path=f"{io_.TESTCODE_DIR}/BenchmarkTest00001.java", cwe="CWE-89",
             family="injection", source_id="semgrep", source_kind="scanner", vendor="semgrep")
    noise = mk(path="src/main/java/org/owasp/benchmark/helpers/Util.java", cwe="CWE-79",
               family="xss", source_id="semgrep", source_kind="scanner", vendor="semgrep")
    outcomes, audit = cal.label_cases(expected, [hit, noise])
    by_id = {o.case_id: o for o in outcomes}
    assert by_id["BenchmarkTest00001"].detected and by_id["BenchmarkTest00001"].real
    assert not by_id["BenchmarkTest00002"].detected      # decoy not reported
    assert audit["noise_findings_excluded"] == 1         # helper-file finding never labeled
    assert audit["cases_unmapped_family"] == 1           # the trustbound (CWE-501) case
    assert audit["categories_unmapped"] == ["trustbound"]


def test_wilson_and_split_are_sane_and_deterministic():
    lo, hi = cal._wilson(90, 100)
    assert 0.82 < lo < 0.90 < hi < 0.95
    assert cal._wilson(0, 0) == (0.0, 1.0)
    outcomes = mk_outcomes("injection", "sqli", 40, 20) + mk_outcomes("xss", "xss", 30, 10, start=100)
    a1, b1 = cal._split(outcomes, seed=0)
    a2, b2 = cal._split(outcomes, seed=0)
    assert [o.case_id for o in a1] == [o.case_id for o in a2]      # deterministic
    assert len(a1) + len(b1) == len(outcomes)
    sqli_train = sum(1 for o in a1 if o.category == "sqli")
    assert 25 <= sqli_train <= 35                                   # stratified ~half


def test_fit_produces_honest_record():
    # 60 sqli (48 tp) + 40 cmdi (12 tp) -> injection pooled; per-category kept.
    outcomes = (mk_outcomes("injection", "sqli", 48, 12)
                + mk_outcomes("injection", "cmdi", 12, 28, start=200)
                + mk_outcomes("crypto", "weakrand", 80, 0, start=400, undetected_true=5)
                + mk_outcomes("xss", "xss", 4, 2, start=600))       # below min_n
    rec = cal.fit(outcomes, corpus_meta={"corpus": "test", "version": "1.2"},
                  scanner={"arm": "semgrep", "family": "semgrep"},
                  min_n=30, seed=0, created_at="2026-08-24T00:00:00Z")
    assert rec["record"] == cal.RECORD_SCHEMA
    inj = rec["families"]["injection"]
    # split halves the strata; train counts are ~half of 100 injection detections
    assert 45 <= inj["detections"] <= 55
    assert set(inj["per_category"]) == {"sqli", "cmdi"}
    assert inj["per_category"]["sqli"]["detections"] + \
           inj["per_category"]["cmdi"]["detections"] == inj["detections"]
    p = (inj["tp"] + 1) / (inj["detections"] + 2)                   # Laplace a=1
    assert abs(inj["p"] - round(p, 4)) < 1e-9
    assert abs(inj["logit"] - round(math.log(p / (1 - p)), 4)) < 1e-9
    assert inj["floor_binding"] == (p < DETERMINISTIC_FLOOR)
    crypto = rec["families"]["crypto"]
    assert crypto["floor_binding"] is False and crypto["p"] > 0.9
    assert "xss" in rec["excluded_families"]                        # min_n guard
    assert "xss" not in rec["families"]
    assert rec["scope"]["languages"] == ["java"]
    assert rec["scope"]["deterministic_singleton"] is True
    exp_prev = sum(1 for o in outcomes if o.real) / len(outcomes)
    assert rec["scope"]["prevalence"] == round(exp_prev, 4)
    assert len(rec["caveats"]) >= 4 and any("prevalence" in c for c in rec["caveats"])


def test_fit_metrics_on_heldout_half():
    outcomes = mk_outcomes("injection", "sqli", 60, 40)
    rec = cal.fit(outcomes, corpus_meta={}, scanner={"family": "semgrep"},
                  min_n=10, seed=0, created_at="2026-08-24T00:00:00Z")
    m = rec["metrics"]
    assert m["test_detections"] == 50                               # held-out half
    pf = m["per_family"]["injection"]
    assert 0.4 < pf["empirical"] < 0.8
    # post-clamp p is floored at 0.60 for this population; ECE reflects both
    assert pf["p_clamped"] >= DETERMINISTIC_FLOOR
    assert m["ece_postclamp"] >= 0.0 and m["brier_preclamp"] > 0.0


def test_unmapped_families_never_fit():
    outcomes = mk_outcomes(None, "trustbound", 40, 10)
    rec = cal.fit(outcomes, corpus_meta={}, scanner={"family": "semgrep"},
                  min_n=10, seed=0, created_at="2026-08-24T00:00:00Z")
    assert rec["families"] == {} and rec["excluded_families"] == {}
