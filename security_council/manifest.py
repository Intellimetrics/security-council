"""Run manifest — what ran, on what, with what result."""

from __future__ import annotations

from collections import Counter

from . import __version__
from .model import Finding

SCHEMA_VERSION = 1


def build_manifest(*, run_id: str, target: str, arm_results: list, merged: list[Finding],
                   config: dict, started_at: str, finished_at: str, git: dict,
                   degradations: list[dict], reports: list[dict],
                   exit_code: int | None = None,
                   disposition_actions: dict | None = None) -> dict:
    by_sev = Counter(f.severity.label for f in merged)
    by_state = Counter(f.disposition.state for f in merged)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "tool": {"security_council": __version__},
        "target": {"root": target, **git},
        "arms": [{
            "name": r.name, "kind": r.kind, "family": r.family, "ok": r.ok,
            "exit_code": r.exit_code, "tool_version": r.tool_version,
            "elapsed_seconds": round(r.elapsed_seconds, 2),
            "raw_results": r.coverage.get("raw_results"), "normalized": r.coverage.get("normalized"),
            "completion": r.coverage.get("completion"),
            "cost_usd": r.coverage.get("cost_usd"),
            "cost_stopped": bool(r.coverage.get("cost_stopped")),
            "model_unattested": bool(r.coverage.get("model_unattested")),
            "coverage_unverified": bool(r.coverage.get("coverage_unverified")),
            "classifier_fallback": bool(r.coverage.get("classifier_fallback")),   # D8
            "error": r.error or None,
        } for r in arm_results],
        "counts": {"total": len(merged), "by_severity": dict(by_sev), "by_state": dict(by_state)},
        "policy": config.get("policy", {}),
        "disposition_actions": disposition_actions or {},
        "degradations": degradations,
        "exit_code": exit_code,
        "reports": reports,
    }
