"""Ground-truth matching + metrics + the zero-tolerance suppression gate.

Matcher: a finding is a candidate for an expected case when the case's path is
among the finding's location URIs; exact-CWE candidates beat family-level ones
(the two crypto cases share path *and* family and must not cross-match). Decoys
carry no CWE and match on path alone. Multiple findings may match one case
(e.g. many osv advisory clusters over one requirements.txt case) and one merged
cluster may satisfy several cases (the SQLi+command-injection root-cause cluster).

Gate semantics (R3): at this corpus size (7 TPs) the published <=5%
true-positive-suppression target is not statistically resolvable — one wrongful
suppression is already 14% — so the gate is ZERO tolerance: any TP-matched
finding that ends demoted (state ``refuted``) or hidden (suppressed /
accepted_risk) is a violation. The crypto 0% gate is subsumed by that but the
rate is still reported separately. A missed detection is NOT a gate violation
(the gate measures wrongful suppression); recall is reported and pinned by the
test suite instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import HIDDEN_LIFECYCLES, Finding, canonical_cwe, is_crypto_finding


def is_demoted_or_hidden(f: Finding) -> bool:
    return f.disposition.state == "refuted" or f.disposition.lifecycle in HIDDEN_LIFECYCLES


def outcome_labels(f: Finding) -> set[str]:
    """Vocabulary shared with EXPECTED.yaml's `must_end_as` lists."""
    out: set[str] = set()
    if f.disposition.lifecycle in HIDDEN_LIFECYCLES:
        out |= {"suppressed", "refuted", "demoted"}
    if f.disposition.state == "refuted":
        out |= {"refuted", "demoted"}
    if f.disposition.state == "disputed":
        out.add("disputed")
    if f.disposition.state == "needs_human":
        out.add("needs_human")
    return out


def match(expected: dict, findings: list[Finding]) -> tuple[dict[str, list[Finding]], list[Finding]]:
    """-> ({case_id: matched findings}, noise findings matching no case)."""
    matches: dict[str, list[Finding]] = {}
    matched_ids: set[str] = set()
    for case in list(expected.get("findings") or []) + list(expected.get("decoys") or []):
        path, cwe, fam = case["path"], case.get("cwe"), case.get("family")
        cands = [f for f in findings if any(loc.uri == path for loc in f.locations)]
        if cwe:
            exact = [f for f in cands
                     if canonical_cwe(cwe) in {canonical_cwe(c) for c in f.taxonomy.cwe}]
            cands = exact or [f for f in cands if fam and f.taxonomy.cwe_family == fam]
        matches[case["id"]] = cands
        matched_ids |= {f.id for f in cands}
    noise = [f for f in findings if f.id not in matched_ids]
    return matches, noise


@dataclass
class EvalReport:
    metrics: dict
    violations: list[str]
    matches: dict[str, list[str]] = field(default_factory=dict)   # case id -> finding ids
    noise: list[str] = field(default_factory=list)
    disposition_actions: dict = field(default_factory=dict)


def compute(expected: dict, findings: list[Finding]) -> EvalReport:
    tps = list(expected.get("findings") or [])
    decoys = list(expected.get("decoys") or [])
    matches, noise = match(expected, findings)

    detected = [c for c in tps if matches[c["id"]]]
    missed = [c["id"] for c in tps if not matches[c["id"]]]
    tp_findings = {f.id: f for c in tps for f in matches[c["id"]]}
    decoy_findings = {f.id: f for c in decoys for f in matches[c["id"]]}

    suppressed_tp = [f for f in tp_findings.values() if is_demoted_or_hidden(f)]
    crypto_tp = [f for f in tp_findings.values() if is_crypto_finding(f)]
    suppressed_crypto = [f for f in crypto_tp if is_demoted_or_hidden(f)]

    violations: list[str] = []
    for c in tps:
        for f in matches[c["id"]]:
            if is_demoted_or_hidden(f):
                tag = "crypto " if is_crypto_finding(f) else ""
                tag += "must_not_demote " if c.get("must_not_demote") else ""
                violations.append(
                    f"TP {c['id']}: {tag}finding {f.id} ended "
                    f"state={f.disposition.state} lifecycle={f.disposition.lifecycle}")
    decoy_outcomes: dict[str, str] = {}
    for c in decoys:
        found = matches[c["id"]]
        if not found:
            decoy_outcomes[c["id"]] = "not_reported"
            continue
        allowed = set(c.get("must_end_as") or [])
        for f in found:
            labels = outcome_labels(f)
            decoy_outcomes[c["id"]] = "/".join(sorted(labels)) or "open"
            if allowed and not (labels & allowed):
                violations.append(
                    f"decoy {c['id']}: finding {f.id} ended "
                    f"state={f.disposition.state} lifecycle={f.disposition.lifecycle} "
                    f"(must end as one of {sorted(allowed)})")

    # unhandled false positives = decoy/noise findings still standing open
    unhandled_fp = [f for f in [*decoy_findings.values(), *noise]
                    if not is_demoted_or_hidden(f) and f.disposition.state != "disputed"]
    denom_val = len(tp_findings) + len(unhandled_fp)
    metrics = {
        "cases_total": len(tps),
        "cases_detected": len(detected),
        "recall": round(len(detected) / len(tps), 4) if tps else None,
        "missed": missed,
        "findings_total": len(findings),
        "tp_findings": len(tp_findings),
        "noise_findings": len(noise),
        "precision_raw": round(len(tp_findings) / len(findings), 4) if findings else None,
        "validated_precision": round(len(tp_findings) / denom_val, 4) if denom_val else None,
        "true_positive_suppression_rate":
            round(len(suppressed_tp) / len(tp_findings), 4) if tp_findings else 0.0,
        "crypto_suppression_rate":
            round(len(suppressed_crypto) / len(crypto_tp), 4) if crypto_tp else 0.0,
        "decoys": decoy_outcomes,
    }
    return EvalReport(metrics=metrics, violations=violations,
                      matches={cid: [f.id for f in fs] for cid, fs in matches.items()},
                      noise=[f.id for f in noise])
