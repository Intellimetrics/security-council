"""Scan orchestration: isolate, fan out arms, normalize, cluster, score, report."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, calibration as calibration_mod, decisions as decisions_mod, \
    entitlements as ent_mod, policy as policy_mod, signing as signing_mod
from .arms.base import Arm, ArmResult
from .artifacts import findings_digest
from .cluster import cluster_findings, merge_cluster
from .export import html_export, markdown, sarif
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



def _write_summaries(out_dir: Path, findings: list[Finding], manifest: dict, *, scores) -> None:
    """summary.md is the system of record; summary.html is rendered FROM that
    exact text (plus a computed dashboard), so the page cannot lag the markdown."""
    md = markdown.to_markdown(findings, manifest, scores=scores)
    (out_dir / "summary.md").write_text(md)
    (out_dir / "summary.html").write_text(html_export.to_html(
        findings, manifest, scores=scores, run_dir=out_dir, markdown_text=md))


def _point_latest(out_dir: Path) -> None:
    """`<runs>/latest` -> this run (a relative symlink, replaced each scan) so a
    human or a script can open the newest report without knowing the run id.
    Best-effort: a filesystem without symlinks just goes without."""
    link = out_dir.parent / "latest"
    try:
        if link.is_symlink() or link.exists():
            if link.is_dir() and not link.is_symlink():
                return                      # a real directory named latest: leave it alone
            link.unlink()
        os.symlink(out_dir.name, link)
    except OSError:
        pass


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


def _verify_one_patch(target: Path, patch_path: Path, findings: list[Finding],
                      merged: list[Finding], scan_arms: list[Arm], out_dir: Path, store, *,
                      run_id: str, collected_at: str, base_commit: str | None,
                      fix_family: str | None = None,
                      patch_label: str | None = None) -> tuple[dict, list[dict], list[dict]]:
    """Deterministic verify-fix for ONE patch (R11 Q4): apply it to a scratch
    copy, re-run the scanners that reported each finding, record the verdicts
    as machine evidence. Returns (manifest block, artifacts, degradations).
    The findings' dispositions are deliberately never touched."""
    from . import verify_patch as _vp
    pv = _vp.verify_patch(target, patch_path, findings, merged, arms=scan_arms,
                          out_dir=out_dir, run_id=run_id, collected_at=collected_at,
                          base_commit=base_commit, patch_label=patch_label)
    arts = _vp.evidence_artifacts(pv, run_id=run_id, collected_at=collected_at,
                                  fix_family=fix_family)
    _vp.record_evidence(store, pv, findings, now_iso=collected_at)
    degr: list[dict] = []
    if findings and not pv.applied:
        degr.append({"kind": "verify_patch_not_applied", "arm": _vp.PRODUCER,
                     "detail": f"{pv.patch}: {pv.apply_error} — every verdict is unproven"})
    for a in pv.arms:
        if not a["ok"]:
            degr.append({"kind": "verify_patch_arm_failed", "arm": a["name"],
                         "detail": f"{a['name']} failed on the patched copy: {a['error']}"})
        elif a["coverage_verdict"] != coverage.VERIFIED:
            degr.append({"kind": "verify_patch_coverage", "arm": a["name"],
                         "detail": f"{a['name']} covered the patched copy only "
                                   f"'{a['coverage_verdict']}'; it cannot vouch for an absence"})
    return pv.to_dict(), arts, degr


def _run_fix_jobs(target: Path, merged: list[Finding], fix_spec: dict, out_dir: Path,
                  store, *, run_id: str, collected_at: str,
                  scan_arms: list[Arm] | None = None,
                  base_commit: str | None = None) -> tuple[list[dict], list[dict], list[dict]]:
    """Run fix jobs SERIALLY (each makes its own fenced fresh copy). Only open,
    non-refuted findings are fixable. If `verify`, each produced patch is verified
    DETERMINISTICALLY (`verify_patch`: scratch copy + the scanners that reported
    the finding) and recorded as machine evidence — NEVER changing the finding's
    state. Returns (artifacts, degradations, patch-verification blocks)."""
    from .arms.fix import FixArm
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
    verifications: list[dict] = []
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
            block, v_arts, v_degr = _verify_one_patch(
                target, Path(res.raw_path), [f], merged, list(scan_arms or []), out_dir, store,
                run_id=run_id, collected_at=collected_at,
                base_commit=meta.get("base_commit") or base_commit, fix_family=arm.family,
                patch_label=f"{arm.name}:{f.id[:8]}")
            verifications.append(block)
            artifacts += v_arts
            degr += v_degr
            # a verify verdict is evidence only; f.disposition is deliberately untouched
    return artifacts, degr, verifications


def _verify_patch_lane(target: Path, merged: list[Finding], spec: dict, out_dir: Path,
                       store, scan_arms: list[Arm], *, run_id: str, collected_at: str,
                       base_commit: str | None) -> tuple[list[dict], list[dict], list[dict]]:
    """`scan --verify-patch FILE [--for IDS]`: verify the OPERATOR's own patch
    against this run's findings — the fix lane is not involved at all."""
    from . import verify_patch as _vp
    patch_path = Path(spec["patch"]).resolve()
    files = _vp._patches.validate_patch(
        patch_path.read_text(encoding="utf-8", errors="replace")).files
    chosen, unknown = _vp.select_findings(merged, files=files,
                                         finding_ids=spec.get("finding_ids"))
    degr: list[dict] = []
    if unknown:
        degr.append({"kind": "verify_patch_unknown_ids", "arm": _vp.PRODUCER,
                     "detail": "no open finding in this run has id " + ", ".join(unknown)
                               + " (ids come from this run's summary; a refuted or "
                                 "suppressed finding is not verified)"})
    if not chosen:
        degr.append({"kind": "verify_patch_nothing_to_verify", "arm": _vp.PRODUCER,
                     "detail": f"{patch_path.name} touches {len(files)} file(s) "
                               f"({', '.join(files[:5]) or 'none parsed'}) but no open finding "
                               "of this run lives there; pass --for <finding-id> to name one"})
    block, arts, v_degr = _verify_one_patch(
        target, patch_path, chosen, merged, scan_arms, out_dir, store, run_id=run_id,
        collected_at=collected_at, base_commit=base_commit, patch_label=patch_path.name)
    return [block], arts, degr + v_degr


def run_scan(target: str | Path, arms: list[Arm], config: dict, *, out_dir: Path | None = None,
             isolate: bool = True, validate: bool = False, validate_max_findings: int | None = None,
             validate_budget_usd: float = 0.5, diff=None, analysis_arms: list[Arm] | None = None,
             fix_spec: dict | None = None, vendor_validate: bool = False,
             verify_patch: dict | None = None) -> ScanRun:
    target = Path(target).resolve()
    if fix_spec and not isolate:
        raise ValueError("the fix lane requires isolation (an in-place fix would edit the "
                         "real tree); --inplace is refused with fix jobs (R6/MV4-2).")
    if verify_patch and not isolate:
        raise ValueError("patch verification requires isolation (the patch is applied to a "
                         "scratch copy only); --inplace is refused with --verify-patch.")
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
                     for n, fmt in (("summary.md", "markdown"), ("summary.html", "html"),
                                    ("manifest.json", "json"))])
        _write_summaries(out_dir, [], manifest, scores=None)
        (out_dir / "manifest.json").write_text(dumps(manifest))
        return ScanRun(run_id=run_id, out_dir=out_dir, findings=[], arm_results=[],
                       manifest=manifest, exit_code=code, degradations=degr)

    # M-V1 diff lane: a diff run must stay scope-coherent — run only diff-capable
    # arms, and record the rest as an informational (not failing) degradation, so
    # a full-tree scanner's findings never get corroborated against a diff-scoped
    # arm that never looked at the same code.
    pre_degr: list[dict] = []
    history_audit: list[dict] = []
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
    if ws.excluded:
        scan_scope = {**scan_scope, "excluded": ws.excluded}    # what the copy left out
    try:
        maxc = int(config.get("defaults", {}).get("max_concurrency", 4))
        with ThreadPoolExecutor(max_workers=max(1, maxc)) as ex:
            results = list(ex.map(
                lambda a: _safe_run(a, ws.root, out_dir, run_id, collected_at), run_arms))
            # analysis arms (M-V3) produce artifacts, not findings — run alongside,
            # but keep them out of coverage/clustering/gate accounting. The
            # findings-scoped jobs (writeup, attack-path) get a digest of what
            # the scan arms just reported: context for the document, never a
            # decision record (pre-cluster, pre-policy, no snippets).
            for a in analysis_arms:
                if getattr(a, "needs_findings", False):
                    a.findings_context = findings_digest([f for r in results for f in r.findings])
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
        # R9 signing lane: the level comes from OPERATOR config (defaults <
        # profile < config file), resolved once here and recorded in the
        # manifest with its reason. Machine (auto) suppressions replay only
        # while the operator's standing double opt-in still arms them.
        sig_policy = signing_mod.resolve_policy(
            config, store_initialised=store.store_meta() is not None,
            store_has_decisions=store.has_decisions(), now_iso=collected_at)
        sig_policy["store_id"] = store.store_id()
        sig_policy["trusted_principals"] = store.trusted_principals()
        prior_decisions = store.apply_prior_decisions(
            merged, now_iso=collected_at, signature_policy=sig_policy["effective"],
            machine_replay=policy_mod.is_armed(config))
        refused = [p for p in prior_decisions if p.get("action") == "refused_signature"]
        if refused:
            pre_degr.append({"kind": "decisions_refused_unsigned",
                             "detail": f"{len(refused)} stored decision(s) not applied: "
                                       "signature " + ", ".join(sorted({
                                           str(p.get("signature")) for p in refused}))
                                       + " (require_signatures: enforce); the findings "
                                         "are open and gate. `security-council decisions "
                                         "verify` lists them."})
        machine = [p for p in prior_decisions if p.get("signature") == signing_mod.MACHINE
                   and str(p.get("action", "")).startswith("reapplied")]
        if machine and sig_policy["effective"] == "enforce":
            # R13: machine writes are never signed (Q6), so in an ARMED repo a
            # forged `kind: auto` record replays under enforce, bounded only by
            # G1/G7 and the operator's double opt-in. Say so, every run.
            pre_degr.append({"kind": "machine_decisions_replayed",
                             "detail": f"{len(machine)} automatic suppression(s) reapplied "
                                       "without a signature (machine writes are never "
                                       "signed; they replay only because auto-suppression "
                                       "is armed in this config). Review them in the "
                                       "summary's reapplied table."})
        warned = [p for p in prior_decisions if p.get("signature_warning")]
        if warned:
            # Q2: `warn` must be loud or it is functionally `off`
            pre_degr.append({"kind": "decisions_applied_unsigned",
                             "detail": f"{len(warned)} stored decision(s) applied WITHOUT a "
                                       "verified signature (require_signatures: warn — "
                                       f"{sig_policy['reason']}). Sign them or set "
                                       "decisions.require_signatures: enforce."})
        if (sig_policy["effective"] == "enforce" and sig_policy.get("verifier") is None
                and any(p.get("signature") in (signing_mod.UNVERIFIABLE,) for p in refused)):
            pre_degr.append({"kind": "signature_verifier_missing",
                             "detail": "ssh-keygen -Y (OpenSSH >= 8.2) is not on PATH; "
                                       "signed decisions cannot be checked and are refused "
                                       "(fail-closed)."})

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
            history=store.history_counts(signature_policy=sig_policy["effective"],
                                         audit=history_audit), calibration=cal)
        rogue_records = [a for a in history_audit if a.get("signature") == "noncanonical_record"]
        mark_audit = [a for a in history_audit if a.get("signature") != "noncanonical_record"]
        if rogue_records:
            pre_degr.append({"kind": "records_ignored",
                             "detail": f"{len(rogue_records)} decision record file(s) not named "
                                       "by the root cause they claim were ignored: "
                                       + ", ".join(str(a.get("file")) for a in rogue_records[:5])
                                       + ". A record can only live at its own slug."})
        if mark_audit and sig_policy["effective"] == "warn":
            pre_degr.append({"kind": "outcome_marks_unsigned",
                             "detail": f"{len(mark_audit)} outcome mark(s) feeding the score "
                                       "history term have no verified signature "
                                       "(require_signatures: warn)."})
        elif mark_audit and sig_policy["effective"] == "enforce":
            # R13 round 2: refused marks were only in manifest.history_audit;
            # a reviewer reading the summary never saw them.
            pre_degr.append({"kind": "outcome_marks_refused",
                             "detail": f"{len(mark_audit)} outcome mark(s) not counted: "
                                       + ", ".join(sorted({str(a.get("signature"))
                                                           for a in mark_audit}))
                                       + " (require_signatures: enforce). `security-council "
                                         "decisions verify` lists them."})
        roster_refusals = [m for s, m in signing_mod.roster_problems(store.allowed_signers_path)
                           if s == "refuse"]
        if roster_refusals and sig_policy["effective"] != "off":
            pre_degr.append({"kind": "roster_refused",
                             "detail": "allowed_signers contains a line that would vouch for "
                                       f"anyone ({roster_refusals[0]}); every signature is "
                                       "refused until it is removed."})
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

        baseline = store.load_baseline(signature_policy=sig_policy["effective"])
        if (baseline and baseline.get("integrity") == "intact"
                and sig_policy["effective"] == "enforce"
                and baseline.get("signature_status") != signing_mod.VERIFIED):
            # R9 signing lane: an intact digest proves the file was not edited
            # after it was written — not WHO wrote it. Under enforce the
            # baseline must carry a verified operator signature, or it is no
            # baseline and everything gates.
            pre_degr.append({"kind": "baseline_refused",
                             "detail": "baseline/latest.json signature "
                                       f"{baseline.get('signature_status')} "
                                       f"({baseline.get('signature_detail', '')[:120]}); "
                                       "require_signatures is enforce, so the baseline is "
                                       "ignored (all findings gate). Re-run `baseline set` "
                                       "with --signing-key."})
            baseline = None
        elif (baseline and baseline.get("integrity") == "intact"
                and sig_policy["effective"] == "warn"
                and baseline.get("signature_status") != signing_mod.VERIFIED):
            pre_degr.append({"kind": "baseline_unsigned",
                             "detail": "baseline/latest.json applied WITHOUT a verified "
                                       f"signature ({baseline.get('signature_status')}; "
                                       "require_signatures: warn)."})
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
            baseline_delta["signature"] = baseline.get("signature_status")
            # R13: a signed baseline has no expiry (Q3's replay bound is the
            # suppression's expires_at), so at least its AGE is printed.
            try:
                set_at = datetime.fromisoformat(str(baseline.get("set_at")).replace("Z", "+00:00"))
                baseline_delta["age_days"] = max(
                    0, (datetime.fromisoformat(collected_at.replace("Z", "+00:00")) - set_at).days)
            except (ValueError, TypeError):
                baseline_delta["age_days"] = None

        # fix lane (M-V4a): serial, after the scan/policy phase, each job in its
        # own fenced fresh copy. Only fix open, non-refuted findings.
        # Deterministic verify-fix (R11 Q4) hangs off both the fix lane and
        # `--verify-patch`; its verdicts are evidence in the manifest and the
        # store, never a disposition, and never touch the gate.
        verify_blocks: list[dict] = []
        if fix_spec or verify_patch:
            base_commit = ws.git_info().get("git_commit")
        if fix_spec:
            fx_arts, fx_degr, fx_ver = _run_fix_jobs(
                target, merged, fix_spec, out_dir, store, run_id=run_id,
                collected_at=collected_at, scan_arms=run_arms, base_commit=base_commit)
            artifacts += fx_arts
            pre_degr += fx_degr
            verify_blocks += fx_ver
        if verify_patch:
            vp_blocks, vp_arts, vp_degr = _verify_patch_lane(
                target, merged, verify_patch, out_dir, store, run_arms, run_id=run_id,
                collected_at=collected_at, base_commit=base_commit)
            artifacts += vp_arts
            pre_degr += vp_degr
            verify_blocks += vp_blocks
        verify_fix = ({"method": "deterministic", "patches": verify_blocks}
                      if verify_blocks else None)

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
            calibration=cal_meta, signature_policy=sig_policy, history_audit=history_audit,
            verify_fix=verify_fix,
            reports=[{"path": str(out_dir / n), "format": fmt} for n, fmt in
                     (("merged.sarif", "sarif"), ("raw.sarif", "sarif"), ("findings.json", "json"),
                      ("summary.md", "markdown"), ("summary.html", "html"),
                      ("manifest.json", "json"),
                      ("policy.json", "json"))])
        _write_summaries(out_dir, merged, manifest,
                         scores=calibration_mod.fitted_scores(policy_rows) or None)
        (out_dir / "manifest.json").write_text(dumps(manifest))
        _point_latest(out_dir)
    finally:
        ws.cleanup()

    return ScanRun(run_id=run_id, out_dir=out_dir, findings=merged, arm_results=results,
                   manifest=manifest, exit_code=exit_code, degradations=degradations)
