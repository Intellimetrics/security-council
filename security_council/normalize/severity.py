"""Severity normalization to the 5-level scale + SARIF level."""

from __future__ import annotations

from ..model import (
    SEVERITY_TO_SARIF_LEVEL,
    SEVERITY_TO_SECURITY_SEVERITY,
    SeverityBlock,
)

# Per-source label vocabularies -> canonical severity.
SEVERITY_VOCAB: dict[str, dict[str, str]] = {
    "semgrep": {"ERROR": "high", "WARNING": "medium", "INFO": "low"},
    "gitleaks": {},           # no native levels; verified secrets default high
    "osv-scanner": {},
}
_GENERIC = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
            "low": "low", "info": "info", "informational": "info", "warning": "medium",
            "error": "high", "note": "low"}
_SECRET_FAMILIES = frozenset(("secrets",))


def _band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _from_label(source_id: str, raw: str | None, cwe_family: str) -> str:
    if raw:
        vocab = SEVERITY_VOCAB.get(source_id, {})
        if raw in vocab:
            return vocab[raw]
        if raw.lower() in _GENERIC:
            return _GENERIC[raw.lower()]
    if cwe_family in _SECRET_FAMILIES:
        return "high"
    return "medium"


def normalize_severity(*, source_id: str, raw_label: str | None = None,
                       numeric_severity: float | None = None, cwe_family: str = "other",
                       cvss_v3: str | None = None, cvss_v4: str | None = None,
                       epss: float | None = None, kev: bool = False) -> SeverityBlock:
    if numeric_severity is not None:
        label = _band(float(numeric_severity))
        sec = float(numeric_severity)
    else:
        label = _from_label(source_id, raw_label, cwe_family)
        sec = SEVERITY_TO_SECURITY_SEVERITY[label]
    return SeverityBlock(
        label=label, sarif_level=SEVERITY_TO_SARIF_LEVEL[label], security_severity=sec,
        cvss_v3=cvss_v3, cvss_v4=cvss_v4, epss=epss, kev=kev, source_label=raw_label,
    )
