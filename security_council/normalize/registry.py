"""Normalization entry points: producer output -> list[Finding]."""

from __future__ import annotations

from ..model import Finding
from .base import ParseContext, build_finding
from .sources import agent_envelope, claude_security, codex_security, sarif_generic

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


def normalize_claude_security(sarif: dict, ctx: ParseContext) -> tuple[list[Finding], dict]:
    """claude-security plugin SARIF (records + panel + stamp) -> findings, run meta."""
    raws, meta = claude_security.parse_sarif(sarif)
    findings = [f for f in (build_finding(r, ctx) for r in raws) if f is not None]
    return findings, meta


def normalize_codex_security(doc: dict, ctx: ParseContext, *, manifest: dict | None = None,
                             coverage: dict | None = None) -> tuple[list[Finding], dict]:
    """codex-security canonical findings.json (+ manifest/coverage) -> findings, bundle meta."""
    raws = codex_security.parse_findings(doc)
    findings = [f for f in (build_finding(r, ctx) for r in raws) if f is not None]
    return findings, codex_security.bundle_meta(doc, manifest, coverage)
