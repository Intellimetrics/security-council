"""Scan orchestration: isolate, fan out arms, normalize, cluster, score, report."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .arms.base import Arm, ArmResult
from .cluster import cluster_findings, merge_cluster
from .export import markdown, sarif
from .jsonio import dumps, to_dict
from .manifest import build_manifest
from .model import Finding
from .normalize import coverage
from .workspace import prepare_workspace

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class ScanRun:
    run_id: str
    out_dir: Path
    findings: list[Finding]
    arm_results: list[ArmResult]
    manifest: dict
    exit_code: int
    degradations: list[dict] = field(default_factory=list)


def _utc_stamp() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d_%H%M%S"), now.isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_run(arm: Arm, root: Path, out_dir: Path, run_id: str, collected_at: str) -> ArmResult:
    try:
        return arm.run(root, out_dir, run_id=run_id, collected_at=collected_at)
    except Exception as e:  # noqa: BLE001
        return ArmResult(name=arm.name, kind=arm.kind, family=arm.family, ok=False,
                         exit_code=None, error=f"arm crashed: {e}", findings=[])


def _exit_code(merged: list[Finding], results: list[ArmResult], config: dict) -> tuple[int, list[dict]]:
    policy = config.get("policy", {})
    threshold = _SEV_RANK.get(policy.get("fail_on_severity", "high"), 4)
    min_arms = int(policy.get("min_arms_ok", 1))
    # gate on real/unresolved findings at/above threshold; a validated false positive
    # (state "refuted") is demoted and does not fail the build.
    gating = [f for f in merged
              if f.disposition.lifecycle in ("open", "reopened")
              and f.disposition.state != "refuted"
              and not f.disposition.sarif_suppression
              and _SEV_RANK[f.severity.label] >= threshold]
    ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    degr = [{"kind": "arm_failed", "arm": r.name, "detail": r.error} for r in failed]
    if len(ok) < min_arms:
        degr.append({"kind": "insufficient_arms", "detail": f"{len(ok)} ok < min_arms_ok {min_arms}"})
        return 3, degr
    if gating:
        return 1, degr
    if failed:
        return 3, degr
    return 0, degr


def run_scan(target: str | Path, arms: list[Arm], config: dict, *, out_dir: Path | None = None,
             isolate: bool = True, validate: bool = False, validate_max_findings: int | None = None,
             validate_budget_usd: float = 0.5) -> ScanRun:
    target = Path(target).resolve()
    run_id, collected_at = _utc_stamp()
    outdir_root = Path(config.get("reports", {}).get("outdir", ".security-council/runs"))
    out_dir = Path(out_dir) if out_dir else (target / outdir_root / run_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    ws = prepare_workspace(target, mode="copy" if isolate else "inplace")
    try:
        maxc = int(config.get("defaults", {}).get("max_concurrency", 4))
        with ThreadPoolExecutor(max_workers=max(1, maxc)) as ex:
            results = list(ex.map(
                lambda a: _safe_run(a, ws.root, out_dir, run_id, collected_at), arms))

        mdv = int(config.get("defaults", {}).get("min_distinct_vendors", 2))
        all_findings = [f for r in results for f in r.findings]
        clusters = cluster_findings(all_findings, min_distinct_vendors=mdv)
        run_ctx = coverage.RunContext(
            sources=[coverage.SourceRun(r.name, r.kind, r.family, ran=r.ok) for r in results],
            min_distinct_vendors=mdv)
        merged = [coverage.apply(merge_cluster(c), run_ctx) for c in clusters]
        merged.sort(key=lambda f: (-_SEV_RANK[f.severity.label], f.taxonomy.cwe_family))

        if validate and merged:
            from .validate import panel as _vpanel
            _vpanel.validate_findings(merged, repo_root=ws.root, max_findings=validate_max_findings,
                                      max_cost_usd=validate_budget_usd)

        (out_dir / "merged.sarif").write_text(dumps(sarif.to_sarif(
            merged, tool_version=__version__, run_id=run_id)))
        by_source = {r.name: r.findings for r in results if r.findings}
        (out_dir / "raw.sarif").write_text(dumps(sarif.raw_sarif(by_source, tool_version=__version__)))
        (out_dir / "findings.json").write_text(dumps([to_dict(f) for f in merged]))

        exit_code, degradations = _exit_code(merged, results, config)
        _, finished_at = _utc_stamp()
        manifest = build_manifest(
            run_id=run_id, target=str(target), arm_results=results, merged=merged, config=config,
            started_at=collected_at, finished_at=finished_at, git=ws.git_info(),
            degradations=degradations, exit_code=exit_code,
            reports=[{"path": str(out_dir / n), "format": fmt} for n, fmt in
                     (("merged.sarif", "sarif"), ("raw.sarif", "sarif"), ("findings.json", "json"),
                      ("summary.md", "markdown"), ("manifest.json", "json"))])
        (out_dir / "summary.md").write_text(markdown.to_markdown(merged, manifest))
        (out_dir / "manifest.json").write_text(dumps(manifest))
    finally:
        ws.cleanup()

    return ScanRun(run_id=run_id, out_dir=out_dir, findings=merged, arm_results=results,
                   manifest=manifest, exit_code=exit_code, degradations=degradations)
