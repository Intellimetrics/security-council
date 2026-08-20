"""Normalization entry points: producer output -> list[Finding]."""

from __future__ import annotations

from ..model import Finding
from .base import ParseContext, build_finding
from .sources import agent_envelope, sarif_generic

SARIF_ADAPTERS = {
    "semgrep": sarif_generic.semgrep,
    "gitleaks": sarif_generic.gitleaks,
    "osv-scanner": sarif_generic.osv,
}


def normalize_sarif(sarif: dict, adapter: str, ctx: ParseContext) -> list[Finding]:
    raws = SARIF_ADAPTERS[adapter](sarif)
    return [f for f in (build_finding(r, ctx) for r in raws) if f is not None]


def normalize_envelope(env: dict, ctx: ParseContext) -> tuple[list[Finding], dict]:
    raws, meta = agent_envelope.parse_envelope(env)
    findings = [f for f in (build_finding(r, ctx) for r in raws) if f is not None]
    return findings, meta
