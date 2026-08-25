"""Scan orchestration: isolate, fan out arms, normalize, cluster, score, report."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, calibration as calibration_mod, decisions as decisions_mod, \
    entitlements as ent_mod, policy as policy_mod
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


def _counts_as_coverage(r: ArmResult) -> bool:
    """Whether an arm may be counted as "this was actually scanned".

    Delegates to the one coverage model (`normalize.coverage.coverage_verdict`)
    so the gate, the corroboration context and the manifest cannot drift apart —
    drift between exactly those three is what four review rounds kept finding.
    """
    return coverage.coverage_verdict(r) != coverage.NONE


def _unavailable(arm: Arm, detail: str) -> ArmResult:
    return ArmResult(name=arm.name, kind=arm.kind, family=arm.family, ok=False,
                     exit_code=None, error=f"arm unavailable: {detail}", findings=[])


def _safe_run(arm: Arm, root: Path, out_dir: Path, run_id: str, collected_at: str) -> ArmResult:
    # R12: `available()` used to be consulted ONLY by `doctor`, the MCP doctor
    # and the setup wizard — never on the scan path — so an arm that reported
    # itself unusable ran anyway. Observed live: the analysis lane ran 131s and
    # reported ok while `available()` returned False. An arm that refuses is now
    # a failed arm, which counts against `min_arms_ok` and degrades the run
    # rather than letting it look clean.
    try:
        ok, detail = arm.available()
    except Exception as e:  # noqa: BLE001
        return _unavailable(arm, f"availability check crashed: {e}")
    if not ok:
        return _unavailable(arm, detail)
    try:
        return arm.run(root, out_dir, run_id=run_id, collected_at=collected_at)
    except Exception as e:  # noqa: BLE001
        return ArmResult(name=arm.name, kind=arm.kind, family=arm.family, ok=False,
                         exit_code=None, error=f"arm crashed: {e}", findings=[])


def _shadow_runs_completed(store, config: dict, out_dir: Path, run_id: str) -> int:
    """Shadow-run count, cross-checked against evidence on disk (R9).

    The store's counter lives in `policy_state.json`, which an attacker who can
    write the store can simply set high to skip shadow mode and unlock
    auto-suppression. Taking the MINIMUM of the counter and the number of real
    sibling run directories means forging it now also requires fabricating that
    many complete run dirs. Both sources under-count in the fail-safe direction
    (shadow mode stays on longer), so the min never weakens G4."""
    counter = store.armed_runs_completed(config)
    observed = policy_mod.count_prior_runs(Path(out_dir).parent, run_id)
    return min(counter, observed)


def _exit_code(merged: list[Finding], results: list[ArmResult], config: dict) -> tuple[int, list[dict]]:
    policy = config.get("policy", {})
    threshold = _SEV_RANK.get(policy.get("fail_on_severity", "high"), 4)
    min_arms = int(policy.get("min_arms_ok", 1))
    # gate on real/unresolved findings at/above threshold; a validated false positive
    # (state "refuted") is demoted and does not fail the build.
    gate_baseline = policy.get("gate_baseline", "all")
    gating = [f for f in merged
              if f.disposition.lifecycle in ("open", "reopened")
              and f.disposition.state != "refuted"
              and not f.disposition.sarif_suppression
              and _SEV_RANK[f.severity.label] >= threshold
              # baseline mode "new": pre-existing (baselined) findings don't gate;
              # findings with no baseline_state (no baseline set) always gate.
              # R9/G9: the baseline file is unsigned operator state, so it can
              # never excuse a crypto or critical finding — mirroring G1/G7,
              # a forged baseline still cannot switch off those gates.
              and not (gate_baseline == "new"
                       and f.baseline_state in ("unchanged", "updated")
                       and not policy_mod.baseline_ineligible(f))]
    verdicts = {r.name: coverage.coverage_verdict(r) for r in results}
    ok = [r for r in results if verdicts[r.name] != coverage.NONE]
    failed = [r for r in results if not r.ok]
    unverified = [r for r in results if r.ok and verdicts[r.name] == coverage.NONE]
    partial = [r for r in results if verdicts[r.name] == coverage.PARTIAL]
    degr = [{"kind": "arm_failed", "arm": r.name, "detail": r.error} for r in failed]
    degr += [{"kind": "coverage_unverified", "arm": r.name,
              "detail": "arm verified nothing it can vouch for — "
                        "it does not count as coverage"}
             for r in unverified]
    degr += [{"kind": "partial_coverage", "arm": r.name,
              "detail": _partial_reason(r)} for r in partial]
    # R12: structural floor, independent of min_arms_ok. With `min_arms_ok: 0`
    # (or `--min-arms 0`) and no arm succeeding, every later branch was skipped
    # and this returned 0 — a scan where NOTHING ran reported the repo clean.
    if not ok:
        degr.append({"kind": "no_arms_succeeded",
                     "detail": "no arm produced a usable result; nothing was scanned"})
        return 3, degr
    if len(ok) < min_arms:
        degr.append({"kind": "insufficient_arms", "detail": f"{len(ok)} ok < min_arms_ok {min_arms}"})
        return 3, degr
    if gating:
        return 1, degr
    # R12 round 4: a PARTIAL scan whose findings were all below the threshold
    # used to exit 0 — "clean" from a run that examined less than it claimed.
    # Incomplete coverage is a degraded run, never a clean one.
    if failed or unverified or partial:
        return 3, degr
    return 0, degr


def _partial_reason(r: ArmResult) -> str:
    cov = r.coverage or {}
    if cov.get("ignore_files"):
        return (f"the repository's own ignore rules were in effect and reduced what was "
                f"scanned: {', '.join(cov['ignore_files'][:5])}")
    if cov.get("partial_scan"):
        return "timed out mid-scan; its report covers only what was flushed"
    if cov.get("cost_stopped"):
        return "stopped on the cost fuse before finishing"
    declined = cov.get("declined_categories") or []
    if declined:
        return f"declined {len(declined)} categories: {', '.join(sorted(declined)[:6])}"
    raw, norm = cov.get("raw_results"), cov.get("normalized")
    if isinstance(raw, int) and isinstance(norm, int) and norm < raw:
        return (f"reported {raw} results but only {norm} could be placed in the repo — "
                f"{raw - norm} dropped (unresolvable location, or a path outside the "
                f"scanned root); those findings are NOT in this report")
    return f"completion={cov.get('completion') or 'partial'} — scanned less than the full scope"


def _run_fix_jobs(target: Path, merged: list[Finding], fix_spec: dict, out_dir: Path,
                  store, *, run_id: str, collected_at: str) -> tuple[list[dict], list[dict]]:
    """Run fix jobs SERIALLY (each makes its own fenced fresh copy). Only open,
    non-refuted findings are fixable. If `verify`, run verify-fix on each produced
    patch and record it as machine evidence — NEVER changing the finding's state."""
    from .arms.fix import FixArm
    from .arms.verify_fix import VerifyFixArm
    from .jsonio import to_dict as _td
    jobs = list(fix_spec.get("jobs") or [])
    want_ids = set(fix_spec.get("finding_ids") or [])
    model = fix_spec.get("model")
    verify = bool(fix_spec.get("verify"))
    fixable = [f for f in merged
               if f.disposition.lifecycle in ("open", "reopened")
               and f.disposition.state != "refuted"
               and (not want_ids or f.id in want_ids)]
    artifacts: list[dict] = []
    degr: list[dict] = []
    for f in fixable:
        row = _td(f)
        for job in jobs:
            arm = FixArm(job=job, finding=row, model=model)
            res = _safe_run(arm, target, out_dir, run_id, collected_at)
            artifacts += res.artifacts
            if not res.ok:
                degr.append({"kind": "fix_failed", "arm": f"{arm.name}:{f.id[:8]}",
                             "detail": res.error})
                continue
            if not verify or not res.raw_path:
                continue
            meta = (res.artifacts[0].get("patch") or {}) if res.artifacts else {}
            varm = VerifyFixArm(finding=row, patch_path=res.raw_path,
                                patch_sha256=meta.get("sha256", ""),
                                base_commit=meta.get("base_commit"),
                                family=arm.family, fix_family=arm.family, model=model)
            vres = _safe_run(varm, target, out_dir, run_id, collected_at)
            artifacts += vres.artifacts
            if vres.artifacts:
                ev = vres.artifacts[0]
                store.record_verify_evidence(
                    root_cause=f.fingerprints.root_cause, finding_id=f.id,
                    verdict=ev.get("verdict", "unproven"), patch_sha256=ev.get("patch_sha256", ""),
                    base_commit=ev.get("base_commit"), producer=varm.name, now_iso=collected_at,
                    model=model, note=ev.get("note", ""))
            # a verify verdict is evidence only; f.disposition is deliberately untouched
    return artifacts, degr


def run_scan(target: str | Path, arms: list[Arm], config: dict, *, out_dir: Path | None = None,
             isolate: bool = True, validate: bool = False, validate_max_findings: int | None = None,
             validate_budget_usd: float = 0.5, diff=None, analysis_arms: list[Arm] | None = None,
             fix_spec: dict | None = None, vendor_validate: bool = False) -> ScanRun:
    target = Path(target).resolve()
    if fix_spec and not isolate:
        raise ValueError("the fix lane requires isolation (an in-place fix would edit the "
                         "real tree); --inplace is refused with fix jobs (R6/MV4-2).")
    run_id, collected_at = _utc_stamp()
    outdir_root = Path(config.get("reports", {}).get("outdir", ".security-council/runs"))
    out_dir = Path(out_dir) if out_dir else (target / outdir_root / run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_scope = diff.as_dict() if diff is not None else {"kind": "full"}
    partial = diff is not None

    analysis_arms = list(analysis_arms or [])
    # M-V2 entitlement preflight: refuse a gated tier that is Red or undeclared
    # BEFORE any arm runs (nothing is scanned, no cost incurred). Includes the
    # fix job's model so a gated fix tier is gated too.
    _pre_models = [getattr(a, "model", None) for a in [*arms, *analysis_arms]]
    if fix_spec and fix_spec.get("model"):
        _pre_models.append(fix_spec["model"])
    refusals = ent_mod.preflight(_pre_models, config)
    if refusals:
        code = 5 if any(r.kind == "red_refused" for r in refusals) else 4  # 5 preflight, 4 entitlement
        degr = [{"kind": r.kind, "arm": None, "detail": r.detail} for r in refusals]
        _, finished_at = _utc_stamp()
        manifest = build_manifest(
            run_id=run_id, target=str(target), arm_results=[], merged=[], config=config,
            started_at=collected_at, finished_at=finished_at, git={}, degradations=degr,
            exit_code=code, scan_scope=scan_scope,
            reports=[{"path": str(out_dir / n), "format": fmt}
                     for n, fmt in (("summary.md", "markdown"), ("manifest.json", "json"))])
        (out_dir / "summary.md").write_text(markdown.to_markdown([], manifest))
        (out_dir / "manifest.json").write_text(dumps(manifest))
        return ScanRun(run_id=run_id, out_dir=out_dir, findings=[], arm_results=[],
                       manifest=manifest, exit_code=code, degradations=degr)

    # M-V1 diff lane: a diff run must stay scope-coherent — run only diff-capable
    # arms, and record the rest as an informational (not failing) degradation, so
    # a full-tree scanner's findings never get corroborated against a diff-scoped
    # arm that never looked at the same code.
    pre_degr: list[dict] = []
    if diff is not None:
        run_arms = [a for a in arms if getattr(a, "supports_diff", False)]
        for a in arms:
            if not getattr(a, "supports_diff", False):
                pre_degr.append({"kind": "diff_skipped", "arm": a.name,
                                 "detail": f"{a.name} has no diff mode; skipped in diff scan "
                                           f"({diff.label()})"})
    else:
        run_arms = list(arms)

    ws = prepare_workspace(target, mode="copy" if isolate else "inplace")
    try:
        maxc = int(config.get("defaults", {}).get("max_concurrency", 4))
        with ThreadPoolExecutor(max_workers=max(1, maxc)) as ex:
            results = list(ex.map(
                lambda a: _safe_run(a, ws.root, out_dir, run_id, collected_at), run_arms))
            # analysis arms (M-V3) produce artifacts, not findings — run alongside,
            # but keep them out of coverage/clustering/gate accounting
            analysis_results = list(ex.map(
                lambda a: _safe_run(a, ws.root, out_dir, run_id, collected_at), analysis_arms))
        artifacts = [a for r in analysis_results for a in r.artifacts]
        for r in analysis_results:
            if not r.ok:
                pre_degr.append({"kind": "analysis_failed", "arm": r.name, "detail": r.error})

        mdv = int(config.get("defaults", {}).get("min_distinct_vendors", 2))
        all_findings = [f for r in results for f in r.findings]
        clusters = cluster_findings(all_findings, min_distinct_vendors=mdv)
        # R12 round 4: `ran=r.ok` bypassed `_counts_as_coverage`, so an arm that
        # verified nothing was still an ELIGIBLE source. Having reported nothing
        # it then counted as *silent*, which applies `coverage_decline` — up to
        # SILENT_CAP (-1.05) log-odds — and can push a real finding from another
        # arm toward auto-suppression. An arm that scanned nothing must not get
        # a vote on whether someone else's finding is real.
        run_ctx = coverage.RunContext(
            sources=[coverage.source_run_for(r) for r in results],
            min_distinct_vendors=mdv)
        merged = [coverage.apply(merge_cluster(c), run_ctx) for c in clusters]
        merged.sort(key=lambda f: (-_SEV_RANK[f.severity.label], f.taxonomy.cwe_family))

        # decision store: reapply stored suppressions (expiry/drift reopen instead)
        # BEFORE validation, so suppressed findings don't burn validator budget and
        # reopened ones get re-validated (G8)
        store = decisions_mod.DecisionStore(target / ".security-council")
        prior_decisions = store.apply_prior_decisions(merged, now_iso=collected_at)

        if validate and merged:
            from .validate import panel as _vpanel
            vrunner = (_vpanel.make_vendor_runner(ws.root) if vendor_validate else None)
            _vpanel.validate_findings(merged, repo_root=ws.root, max_findings=validate_max_findings,
                                      max_cost_usd=validate_budget_usd, vendor_runner=vrunner)

        # score + disposition policy (mutates dispositions; must precede exports/gate)
        _, decided_at = _utc_stamp()
        # G10 (R12): a run that did not verify its full coverage may not create a
        # durable excuse. Auto-suppression on partial evidence is doubly wrong —
        # a partial run has fewer eligible corroborating sources, so p is lower
        # and suppression is MORE likely, and the record then outlives the run
        # that could not justify it. Human decisions are unaffected.
        #
        # This has to be decided BEFORE `armed`, because `armed` also drives the
        # shadow counter: computing it from the raw config let a degraded run
        # burn one of the five shadow runs it was never able to use, so after
        # five such runs the first properly-verified one would suppress for real
        # with no shadow observation behind it — G4 defeated by degradation.
        cfg_for_policy = config
        # `not results` matters: `any()` over an empty list is False, so a run
        # with NO arms at all would have looked fully verified here and kept its
        # armed status, burning a shadow run on a scan that examined nothing.
        if not results or any(coverage.coverage_verdict(r) != coverage.VERIFIED
                              for r in results):
            cfg_for_policy = {**config,
                              "policy": {**config.get("policy", {}), "auto_suppress": False}}
            if (config.get("policy") or {}).get("auto_suppress"):
                pre_degr.append({"kind": "auto_suppress_withheld",
                                 "detail": "coverage was not fully verified this run; "
                                           "auto-suppression is disabled and this run does "
                                           "not count as a shadow run (G10)"})
        armed = policy_mod.is_armed(cfg_for_policy)
        cal, cal_meta = calibration_mod.resolve(
            (config.get("score") or {}).get("calibration"), arm_results=results)
        decisions = policy_mod.apply_policy(
            merged, cfg_for_policy, now_iso=decided_at,
            # cfg_for_policy, not config: the shadow counter is keyed on a policy
            # fingerprint, and G10 changes the policy. Harmless today (a degraded
            # run has armed=False so this is 0 anyway) but reading two different
            # configs either side of one decision is the drift that keeps biting.
            prior_runs=_shadow_runs_completed(store, cfg_for_policy, out_dir, run_id) if armed else 0,
            history=store.history_counts(), calibration=cal)
        if cal is not None:
            cal_meta["applied_findings"] = sum(
                1 for d in decisions if d.score and "fitted_base" in d.score.terms)
        by_id = {f.id: f for f in merged}
        for d in decisions:
            if d.action in ("suppress", "shadow_suppress"):
                store.record_suppression(by_id[d.finding_id], now_iso=decided_at,
                                         shadow=d.action == "shadow_suppress")
        if armed:
            store.bump_armed_runs(cfg_for_policy, run_id=run_id, now_iso=decided_at)

        baseline = store.load_baseline()
        if baseline and baseline.get("integrity") != "intact":
            # R9: the entry set must match the digest written by `baseline set`.
            # A mismatch means the file was edited afterwards; a MISSING digest
            # is refused too, or "omit the field" would be the cheapest bypass
            # of the entire gate. Refusing means no baseline, and with no
            # baseline every finding gates — the fail-safe direction.
            why = ("content_sha256 mismatch — the file was modified after "
                   "`baseline set`" if baseline["integrity"] == "tampered"
                   else "no content_sha256 — created before integrity pinning "
                        "or hand-written")
            pre_degr.append({"kind": "baseline_refused",
                             "detail": f"baseline/latest.json {why}; baseline ignored "
                                       "(all findings gate). Re-run `baseline set`."})
            baseline = None
        baseline_delta = (decisions_mod.annotate_baseline(merged, baseline, partial=partial)
                          if baseline else None)
        if baseline_delta:
            baseline_delta["integrity"] = baseline.get("integrity")
            baseline_delta["content_sha256"] = baseline.get("content_sha256_actual")
            baseline_delta["set_at"] = baseline.get("set_at")
            baseline_delta["operator"] = baseline.get("operator")

        # fix lane (M-V4a): serial, after the scan/policy phase, each job in its
        # own fenced fresh copy. Only fix open, non-refuted findings.
        if fix_spec:
            fx_arts, fx_degr = _run_fix_jobs(target, merged, fix_spec, out_dir, store,
                                             run_id=run_id, collected_at=collected_at)
            artifacts += fx_arts
            pre_degr += fx_degr

        policy_rows = policy_mod.decisions_to_json(decisions)
        (out_dir / "policy.json").write_text(dumps(policy_rows))

        # degradations FIRST: the SARIF has to carry the run's execution status,
        # so it cannot be written before we know whether coverage was complete.
        exit_code, degradations = _exit_code(merged, results, config)
        degradations = pre_degr + degradations

        (out_dir / "merged.sarif").write_text(dumps(sarif.to_sarif(
            merged, tool_version=__version__, run_id=run_id,
            degradations=degradations)))
        by_source = {r.name: r.findings for r in results if r.findings}
        (out_dir / "raw.sarif").write_text(dumps(sarif.raw_sarif(
            by_source, tool_version=__version__,
            coverage_by_source={r.name: coverage.coverage_verdict(r) == coverage.VERIFIED
                                for r in results})))
        (out_dir / "findings.json").write_text(dumps([to_dict(f) for f in merged]))
        _, finished_at = _utc_stamp()
        manifest = build_manifest(
            run_id=run_id, target=str(target), arm_results=results + analysis_results,
            # cfg_for_policy: record the policy that actually RAN. Logging the
            # raw config would claim `auto_suppress: true` on a run where G10
            # disabled it — an audit record contradicting the run's own behaviour.
            merged=merged, config=cfg_for_policy,
            started_at=collected_at, finished_at=finished_at, git=ws.git_info(),
            degradations=degradations, exit_code=exit_code, scan_scope=scan_scope,
            disposition_actions=policy_mod.decisions_summary(decisions),
            baseline_delta=baseline_delta, prior_decisions=prior_decisions, artifacts=artifacts,
            calibration=cal_meta,
            reports=[{"path": str(out_dir / n), "format": fmt} for n, fmt in
                     (("merged.sarif", "sarif"), ("raw.sarif", "sarif"), ("findings.json", "json"),
                      ("summary.md", "markdown"), ("manifest.json", "json"),
                      ("policy.json", "json"))])
        (out_dir / "summary.md").write_text(markdown.to_markdown(
            merged, manifest, scores=calibration_mod.fitted_scores(policy_rows) or None))
        (out_dir / "manifest.json").write_text(dumps(manifest))
    finally:
        ws.cleanup()

    return ScanRun(run_id=run_id, out_dir=out_dir, findings=merged, arm_results=results,
                   manifest=manifest, exit_code=exit_code, degradations=degradations)
