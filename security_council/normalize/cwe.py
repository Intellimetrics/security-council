"""Five-layer CWE normalization: exact -> mapped -> rule-heuristic -> prose-heuristic -> none."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import _CWE_RE, CRYPTO_CWES, CWE_FAMILIES, canonical_cwe, family_for_cwe
from .cwe_table import CWE_BY_SOURCE_RULE, heuristic_cwe

Confidence = str  # "exact" | "mapped" | "heuristic" | "none"


@dataclass(frozen=True)
class CweAssignment:
    cwe: list[str]
    family: str
    confidence: Confidence
    source_category: str | None


def _family(cwes: list[str], category: str | None) -> str:
    if any(c in CRYPTO_CWES for c in cwes):   # crypto is sticky
        return "crypto"
    fam = family_for_cwe(cwes[0])
    if fam is not None:
        return fam
    if category in CWE_FAMILIES:
        return category
    return "other"


def normalize_cwe(*, source_id: str, rule_id: str | None, declared_cwe: list[str] | None,
                  category: str | None, title: str, description: str) -> CweAssignment:
    # 1 exact — a well-formed declared CWE
    if declared_cwe:
        clean = [canonical_cwe(c) for c in declared_cwe if _CWE_RE.match(canonical_cwe(c))]
        if clean:
            # I4 requires the primary CWE to agree with the canonical family.
            # Crypto is intentionally sticky, so a secondary crypto CWE must be
            # promoted ahead of a non-crypto primary rather than producing an
            # invalid finding that the ingress boundary silently drops.
            if any(c in CRYPTO_CWES for c in clean):
                clean = ([c for c in clean if c in CRYPTO_CWES]
                         + [c for c in clean if c not in CRYPTO_CWES])
            return CweAssignment(clean, _family(clean, category), "exact", category)
    # 2 mapped — curated (source, rule) table
    if rule_id and (source_id, rule_id) in CWE_BY_SOURCE_RULE:
        c = CWE_BY_SOURCE_RULE[(source_id, rule_id)]
        return CweAssignment([c], _family([c], category), "mapped", category)
    # 3 heuristic — rule id tokens
    if rule_id:
        h = heuristic_cwe(rule_id)
        if h:
            return CweAssignment([h], _family([h], category), "heuristic", category)
    # 4 heuristic — prose
    h = heuristic_cwe(f"{title} {description}")
    if h:
        return CweAssignment([h], _family([h], category), "heuristic", category)
    # 5 none — family from the producer's category if it names one
    fam = category if category in CWE_FAMILIES else "other"
    return CweAssignment(["CWE-noinfo"], fam, "none", category)
