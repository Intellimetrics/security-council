"""Run manifest — what ran, on what, with what result."""

from __future__ import annotations

from collections import Counter

from . import __version__
from .model import Finding
from .normalize import coverage as _coverage

SCHEMA_VERSION = 1


def build_manifest(*, run_id: str, target: str, arm_results: list, merged: list[Finding],
                   config: dict, started_at: str, finished_at: str, git: dict,
                   degradations: list[dict], reports: list[dict],
                   exit_code: int | None = None,
                   disposition_actions: dict | None = None,
                   baseline_delta: dict | None = None,
                   prior_decisions: list[dict] | None = None,
                   scan_scope: dict | None = None,
                   artifacts: list[dict] | None = None,
                   calibration: dict | None = None,
                   signature_policy: dict | None = None,
                   history_audit: list[dict] | None = None,
                   verify_fix: dict | None = None) -> dict:
    by_sev = Counter(f.severity.label for f in merged)
    by_state = Counter(f.disposition.state for f in merged)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "tool": {"security_council": __version__},
        "target": {"root": target, **git},
        # R12 round 21: who configured this scan. "repository" means the scanned
        # tree's own .security-council.yaml chose the arms and the gate.
        "config_source": config.get("_source") or {"kind": "defaults", "path": None},
        "scan_scope": scan_scope or {"kind": "full"},
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
            # R12: the tri-state answer to "what did this arm actually examine".
            # `ok` alone could not distinguish a complete scan from one that
            # covered half the tree, which is how four rounds of silent-clean
            # results happened.
            "coverage_verdict": _coverage.coverage_verdict(r),
            "declined_families": sorted(_coverage.declined_families(r)),
            "classifier_fallback": bool(r.coverage.get("classifier_fallback")),   # D8
            "error": r.error or None,
        } for r in arm_results],
        "counts": {"total": len(merged), "by_severity": dict(by_sev), "by_state": dict(by_state)},
        "policy": config.get("policy", {}),
        "calibration": calibration or {"status": "off"},
        "disposition_actions": disposition_actions or {},
        "baseline_delta": baseline_delta,
        "prior_decisions": prior_decisions or [],
        # R9 signing lane: the level that RAN (configured vs effective, and why),
        # the verifier found, and any outcome marks that did not verify.
        "signature_policy": signature_policy or {"configured": "off", "effective": "off"},
        "history_audit": history_audit or [],
        "artifacts": artifacts or [],
        # Deterministic verify-fix (R11 Q4): per-patch verdicts bound to the
        # patch sha + base commit. Machine evidence — a human still decides.
        "verify_fix": verify_fix,
        "degradations": degradations,
        "exit_code": exit_code,
        "reports": reports,
    }
