"""security-council command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .arms.base import DiffSpec
from .arms.registry import build_arm, known_arms
from .config import load_config
from .orchestrator import run_scan

EXIT_USAGE = 2


def _build_arms(names: list[str], config: dict | None = None, diff=None):
    options = ((config or {}).get("arms") or {}).get("options") or {}
    return [build_arm(n, options=options.get(n), diff=diff) for n in names]


def cmd_scan(args) -> int:
    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(target)
    except ValueError as e:                    # unknown profile in the config file
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    if getattr(args, "profile", None):
        from .config import PROFILES, deep_merge
        if args.profile not in PROFILES:
            print(f"error: unknown profile {args.profile!r}; known: {sorted(PROFILES)}",
                  file=sys.stderr)
            return EXIT_USAGE
        # an explicit CLI flag overrides the file's presets (unlike a file's
        # own `profile:` key, which sits UNDER the file's other keys)
        config = deep_merge(config, PROFILES[args.profile])
    if args.fail_on_severity:
        config["policy"]["fail_on_severity"] = args.fail_on_severity
    if args.min_arms is not None:
        config["policy"]["min_arms_ok"] = args.min_arms
    if getattr(args, "gate_baseline", None):
        config["policy"]["gate_baseline"] = args.gate_baseline
    names = [n.strip() for n in args.arms.split(",")] if args.arms else config["arms"]["enabled"]
    unknown = [n for n in names if n not in known_arms()]
    if unknown:
        print(f"error: unknown arms {unknown}; known: {known_arms()}", file=sys.stderr)
        return EXIT_USAGE
    if getattr(args, "tier", None):
        from . import entitlements as _ent
        model_id = _ent.tier_model(args.tier)
        if model_id is None:
            print(f"error: unknown tier {args.tier!r}; known: {sorted(_ent.KNOWN_TIERS)}",
                  file=sys.stderr)
            return EXIT_USAGE
        fam = _ent.KNOWN_TIERS[args.tier].family
        arm_opts = config["arms"].setdefault("options", {})
        for an in names:                       # route the tier model to same-family arms
            if an in (fam, f"{fam}-security"):
                arm_opts.setdefault(an, {})["model"] = model_id
    diff = None
    if getattr(args, "working_tree", False):
        diff = DiffSpec(kind="working_tree", base=args.diff)
    elif getattr(args, "diff", None):
        diff = DiffSpec(kind="diff", base=args.diff, head=args.diff_head)
    if getattr(args, "deep", False):
        opts = config["arms"].setdefault("options", {})
        for dn in ("codex-security", "claude-security"):
            opts.setdefault(dn, {})
            if dn == "codex-security":
                opts[dn]["mode"] = "deep"
            else:
                opts[dn]["effort"] = "high"
    if diff is not None and not any(
            getattr(build_arm(n), "supports_diff", False) for n in names):
        print(f"error: --diff/--working-tree needs a diff-capable arm "
              f"(claude-security, codex-security); selected: {names}", file=sys.stderr)
        return EXIT_USAGE
    analysis_arms = []
    if getattr(args, "analyze", None):
        from .artifacts import ANALYSIS_JOBS
        from .arms.registry import build_analysis_arm
        jobs = [j.strip() for j in args.analyze.split(",") if j.strip()]
        unknown_j = [j for j in jobs if j not in ANALYSIS_JOBS]
        if unknown_j:
            print(f"error: unknown analysis job(s) {unknown_j}; known: {sorted(ANALYSIS_JOBS)}",
                  file=sys.stderr)
            return EXIT_USAGE
        options = (config.get("arms") or {}).get("options") or {}
        analysis_arms = [build_analysis_arm(j, options=options.get(f"analysis:{j}")) for j in jobs]
    if getattr(args, "sbom", False):
        from .arms.sbom import SbomArm
        analysis_arms.append(SbomArm())
    fix_spec = None
    if getattr(args, "fix", None):
        from .arms.fix import FIX_JOBS
        if args.fix_job not in FIX_JOBS:
            print(f"error: unknown fix job {args.fix_job!r}; known: {sorted(FIX_JOBS)}",
                  file=sys.stderr)
            return EXIT_USAGE
        ids = None if args.fix.strip() in ("gating", "all") else \
            [i.strip() for i in args.fix.split(",") if i.strip()]
        fix_model = None
        if getattr(args, "tier", None):
            from . import entitlements as _ent
            fix_model = _ent.tier_model(args.tier)
        fix_spec = {"jobs": [args.fix_job], "finding_ids": ids, "model": fix_model,
                    "verify": bool(getattr(args, "verify_fix", False))}
    run = run_scan(target, _build_arms(names, config, diff=diff), config,
                   # R12: must be ABSOLUTE — the scanner arms hand this path to
                   # `docker -v`, and a relative one is read as a volume NAME
                   # ("includes invalid characters for a local volume name").
                   out_dir=Path(args.out).resolve() if args.out else None,
                   isolate=not args.inplace,
                   validate=args.validate or bool((config.get("defaults") or {}).get("validate")),
                   validate_max_findings=args.validate_max,
                   validate_budget_usd=args.validate_budget, diff=diff,
                   analysis_arms=analysis_arms, fix_spec=fix_spec,
                   vendor_validate=bool(getattr(args, "vendor_validate", False)))
    if args.json:
        print(json.dumps({"run_id": run.run_id, "out_dir": str(run.out_dir),
                          "exit_code": run.exit_code, "counts": run.manifest["counts"],
                          "degradations": run.degradations}, indent=2))
    else:
        _print_summary(run)
    return run.exit_code


def _print_summary(run) -> None:
    m = run.manifest
    print(f"security-council scan {run.run_id}  (target {m['target']['root']})")
    for a in m["arms"]:
        status = "ok" if a["ok"] else f"FAILED: {a['error']}"
        print(f"  {a['name']:<13} {status:<24} raw={a['raw_results']} "
              f"normalized={a['normalized']} {a['elapsed_seconds']}s")
    c = m["counts"]
    print(f"findings: {c['total']} clusters  severity={c['by_severity']}")
    if run.degradations:
        print(f"degradations: {run.degradations}")
    print(f"reports: {run.out_dir}  (summary.md, merged.sarif, findings.json, manifest.json)")
    print(f"exit {run.exit_code}")


def cmd_doctor(args) -> int:
    print("security-council doctor")
    docker = shutil.which("docker")
    print(f"  docker         {'ready  ' + docker if docker else 'MISSING'}")
    for name in known_arms():
        ok, detail = build_arm(name).available()
        print(f"  {name:<13} {'ready' if ok else 'unavailable':<11} {detail}")
    from .arms.sbom import SbomArm
    ok, detail = SbomArm().available()
    print(f"  {'sbom':<13} {'ready' if ok else 'unavailable':<11} {detail}")
    return 0


def _load_findings(run_dir) -> list:
    from .jsonio import finding_from_dict
    fj = Path(run_dir) / "findings.json"
    return [finding_from_dict(d) for d in json.load(open(fj))] if fj.is_file() else []


def _load_scores(run_dir) -> dict:
    from . import calibration as cal_mod
    pj = Path(run_dir) / "policy.json"
    return cal_mod.fitted_scores(json.load(open(pj))) if pj.is_file() else {}


def _load_sbom(run_dir, manifest: dict) -> dict | None:
    """The run's syft SBOM artifact (scan --sbom), if one was produced."""
    art = next((a for a in (manifest.get("artifacts") or [])
                if a.get("kind") == "sbom"), None)
    if not art:
        return None
    try:
        return json.loads((Path(run_dir) / art["path"]).read_text())
    except (OSError, ValueError):
        return None


def _report_bundle(args, m: dict) -> int:
    """Write one audience's report set into a directory (R8 guided surface)."""
    run_dir = Path(args.run_dir)
    findings = _load_findings(run_dir)
    scores = _load_scores(run_dir) or None
    out_dir = Path(args.out_dir) if args.out_dir else run_dir / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    fmts: list[str] = []
    if args.bundle in ("triage", "all"):
        fmts += ["csv", "html", "md"]
    if args.bundle in ("gov", "all"):
        fmts += ["openvex", "oscal-ar", "oscal-poam", "cklb", "cyclonedx"]
        if args.app_name and args.app_version:
            fmts.append("emass")
        else:
            print("note: emass.json skipped — pass --app-name and --app-version to "
                  "include the eMASS payload", file=sys.stderr)
    names = {"csv": "findings.csv", "html": "summary.html", "md": "summary.md",
             "openvex": "openvex.json", "oscal-ar": "oscal-ar.json",
             "oscal-poam": "oscal-poam.json", "cklb": "checklist.cklb",
             "cyclonedx": "cyclonedx.json", "emass": "emass.json"}
    for fmt in fmts:
        path = out_dir / names[fmt]
        if fmt == "csv":
            from .export import csv_export
            path.write_text(csv_export.to_csv(findings))
        elif fmt == "html":
            from .export import html_export
            path.write_text(html_export.to_html(findings, m, scores=scores))
        elif fmt == "md":
            from .export import markdown
            path.write_text(markdown.to_markdown(findings, m, scores=scores))
        elif fmt == "openvex":
            from .export import vex
            path.write_text(json.dumps(vex.to_openvex(findings, m), indent=2) + "\n")
        elif fmt in ("oscal-ar", "oscal-poam"):
            from .export import oscal
            doc = (oscal.to_oscal_ar if fmt == "oscal-ar" else oscal.to_oscal_poam)(findings, m)
            path.write_text(json.dumps(doc, indent=2) + "\n")
        elif fmt == "cyclonedx":
            from .export import cyclonedx
            doc, _meta = cyclonedx.to_cyclonedx(findings, m, sbom=_load_sbom(run_dir, m))
            path.write_text(json.dumps(doc, indent=2) + "\n")
        elif fmt == "cklb":
            from .export import cklb
            doc, meta = cklb.to_cklb(findings, m, classification=args.classification)
            path.write_text(json.dumps(doc, indent=2) + "\n")
            print(f"  cklb: {meta['rules_open']}/{meta['rules_total']} mapped rules open · "
                  f"{meta['findings_exported']} findings · "
                  f"{meta['withheld_by_disposition']} withheld · {meta['stig']}",
                  file=sys.stderr)
        elif fmt == "emass":
            from .export import emass
            scan_date = args.scan_date if args.scan_date is not None \
                else emass.scan_date_from_manifest(m)
            body, _meta = emass.to_emass_static_code_scans(
                findings, application_name=args.app_name, version=args.app_version,
                scan_date=scan_date)
            path.write_text(json.dumps(body, indent=2) + "\n")
        print(f"wrote {path}")
    return 0


def cmd_report(args) -> int:
    mf = Path(args.run_dir) / "manifest.json"
    if not mf.is_file():
        print(f"error: no manifest.json in {args.run_dir}", file=sys.stderr)
        return EXIT_USAGE
    m = json.load(open(mf))
    if args.bundle:
        return _report_bundle(args, m)
    if args.format == "csv":
        from .export import csv_export
        print(csv_export.to_csv(_load_findings(args.run_dir)), end="")
        return 0
    if args.format == "html":
        from .export import html_export
        print(html_export.to_html(_load_findings(args.run_dir), m,
                                  scores=_load_scores(args.run_dir) or None))
        return 0
    if args.format == "cklb":
        from .export import cklb
        doc, meta = cklb.to_cklb(_load_findings(args.run_dir), m,
                                 classification=args.classification)
        print(json.dumps(doc, indent=2))
        print(f"cklb: {meta['rules_open']}/{meta['rules_total']} mapped rules open · "
              f"{meta['findings_exported']} findings exported · "
              f"{meta['withheld_by_disposition']} withheld · {meta['stig']}", file=sys.stderr)
        return 0
    if args.format == "cyclonedx":
        from .export import cyclonedx
        doc, meta = cyclonedx.to_cyclonedx(_load_findings(args.run_dir), m,
                                           sbom=_load_sbom(args.run_dir, m))
        print(json.dumps(doc, indent=2))
        comp = meta.get("sbom_components", meta.get("package_components", 0))
        print(f"cyclonedx: {meta['vulnerabilities']} vulnerabilities · {comp} components · "
              f"{meta['withheld_by_disposition']} withheld · {meta['note']}", file=sys.stderr)
        return 0
    if args.format == "emass":
        from .export import emass
        if not (args.app_name and args.app_version):
            print("error: --format emass requires --app-name and --app-version", file=sys.stderr)
            return EXIT_USAGE
        if args.emass_clear:
            print(json.dumps(emass.clear_findings_payload(
                application_name=args.app_name, version=args.app_version), indent=2))
            return 0
        findings = _load_findings(args.run_dir)
        scan_date = args.scan_date if args.scan_date is not None \
            else emass.scan_date_from_manifest(m)
        body, meta = emass.to_emass_static_code_scans(
            findings, application_name=args.app_name, version=args.app_version,
            scan_date=scan_date)
        print(json.dumps(body, indent=2))
        print(f"emass: {meta['rows']} rows from {meta['findings_exported']} findings; "
              f"{meta['withheld_by_disposition']} withheld by disposition; "
              f"{len(meta['skipped'])} skipped (no numeric CWE)", file=sys.stderr)
        for s in meta["skipped"]:
            print(f"  skipped {s['finding_id']}: {s['reason']} {s['cwe']}", file=sys.stderr)
        return 0
    if args.format in ("openvex", "oscal-ar", "oscal-poam"):
        findings = _load_findings(args.run_dir)
        if args.format == "openvex":
            from .export import vex
            doc = vex.to_openvex(findings, m)
        else:
            from .export import oscal
            doc = (oscal.to_oscal_ar if args.format == "oscal-ar" else oscal.to_oscal_poam)(findings, m)
        print(json.dumps(doc, indent=2))
        return 0
    if args.format in ("gitlab-sast", "gitlab-codequality"):
        from .export import gitlab as gl
        findings = _load_findings(args.run_dir)
        doc, meta = (gl.to_gitlab_sast(findings, m) if args.format == "gitlab-sast"
                     else gl.to_gitlab_code_quality(findings))
        print(json.dumps(doc, indent=2))
        print(f"gitlab: {meta}", file=sys.stderr)
        return 0
    if args.format == "md":
        from .export import markdown
        findings = _load_findings(args.run_dir)
        scores = _load_scores(args.run_dir)
        print(markdown.to_markdown(findings, m, detail_limit=args.detail_limit,
                                   scores=scores or None))
        return 0
    print(json.dumps({"run_id": m["run_id"], "counts": m["counts"], "exit_code": m.get("exit_code"),
                      "reports": [r["path"] for r in m["reports"]]}, indent=2))
    return 0


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _store(args):
    from .decisions import DecisionStore
    return DecisionStore(Path(args.target).resolve() / ".security-council")


def _run_dir(args) -> Path | None:
    if getattr(args, "run", None):
        d = Path(args.run)
        return d if (d / "findings.json").is_file() else None
    runs = Path(args.target).resolve() / ".security-council" / "runs"
    cands = sorted(d for d in runs.iterdir()
                   if (d / "findings.json").is_file()) if runs.is_dir() else []
    return cands[-1] if cands else None


def _find_row(run_dir: Path, finding_id: str) -> dict | None:
    rows = json.loads((run_dir / "findings.json").read_text())
    exact = [r for r in rows if r.get("id") == finding_id]
    if exact:
        return exact[0]
    pref = [r for r in rows if str(r.get("id", "")).startswith(finding_id)]
    return pref[0] if len(pref) == 1 else None


def _nested_write_refused(action: str) -> bool:
    """Decision-store writes are human actions. If this process is running inside
    a security-council arm (SECURITY_COUNCIL_NESTED set), refuse — a nested
    agent (or prompt-injected test code) must not be able to forge a human
    suppression / outcome mark / baseline against the real target (R6/MV4-4)."""
    import os
    if os.environ.get("SECURITY_COUNCIL_NESTED"):
        print(f"error: {action} is a human decision and is refused inside a "
              "security-council arm (SECURITY_COUNCIL_NESTED is set).", file=sys.stderr)
        return True
    return False


def _resolve(args) -> tuple[Path, dict] | None:
    run_dir = _run_dir(args)
    if run_dir is None:
        print("error: no run with findings.json found (pass --run)", file=sys.stderr)
        return None
    row = _find_row(run_dir, args.finding_id)
    if row is None:
        print(f"error: finding {args.finding_id!r} not found (or ambiguous) in {run_dir}",
              file=sys.stderr)
        return None
    return run_dir, row


def cmd_outcome_mark(args) -> int:
    if _nested_write_refused("outcome mark"):
        return EXIT_USAGE
    resolved = _resolve(args)
    if resolved is None:
        return EXIT_USAGE
    _, row = resolved
    verdict = {"tp": "true_positive", "fp": "false_positive"}.get(args.verdict, args.verdict)
    operator = args.operator or __import__("getpass").getuser()
    fp = row.get("fingerprints") or {}
    _store(args).mark_outcome(root_cause=fp.get("root_cause", ""), finding_id=row["id"],
                              verdict=verdict, operator=operator, note=args.note,
                              now_iso=_now_iso(), title=row.get("title", ""),
                              context_hash=fp.get("context_hash", ""))
    print(f"marked {row['id']} {verdict} (operator {operator}); "
          f"feeds the score history term for {fp.get('root_cause')}")
    return 0


def cmd_baseline_set(args) -> int:
    if _nested_write_refused("baseline set"):
        return EXIT_USAGE
    run_dir = _run_dir(args)
    if run_dir is None:
        print("error: no run with findings.json found (pass --run)", file=sys.stderr)
        return EXIT_USAGE
    mf = run_dir / "manifest.json"
    scope = (json.loads(mf.read_text()).get("scan_scope") or {}) if mf.is_file() else {}
    if scope.get("kind") not in (None, "full"):
        print(f"error: run {run_dir.name} is a partial ({scope.get('kind')}) scan; a baseline "
              "must come from a full scan, or it would treat unscanned findings as resolved. "
              "Run a full scan and baseline that.", file=sys.stderr)
        return EXIT_USAGE
    rows = json.loads((run_dir / "findings.json").read_text())
    bl = _store(args).set_baseline(rows, run_id=run_dir.name, now_iso=_now_iso(),
                                   operator=args.operator)
    print(f"baseline set from run {run_dir.name}: {len(bl['findings'])} findings")
    return 0


def cmd_baseline_show(args) -> int:
    bl = _store(args).load_baseline()
    if bl is None:
        print("no baseline set (security-council baseline set)", file=sys.stderr)
        return 1
    print(json.dumps({"run_id": bl.get("run_id"), "set_at": bl.get("set_at"),
                      "operator": bl.get("operator"),
                      "findings": len(bl.get("findings") or [])}, indent=2))
    return 0


def cmd_suppress(args) -> int:
    if _nested_write_refused("suppress"):
        return EXIT_USAGE
    resolved = _resolve(args)
    if resolved is None:
        return EXIT_USAGE
    _, row = resolved
    fp = row.get("fingerprints") or {}
    lifecycle = "accepted_risk" if args.accept_risk else "suppressed"
    _store(args).record_human_decision(
        root_cause=fp.get("root_cause", ""), context_hash=fp.get("context_hash", ""),
        finding_id=row["id"], title=row.get("title", ""), operator=args.operator,
        justification=args.justification, now_iso=_now_iso(), lifecycle=lifecycle,
        expires_days=args.expires_days, vex_justification=args.vex_justification)
    print(f"recorded human {lifecycle} for {row['id']} (root cause {fp.get('root_cause')}); "
          f"applies on future scans, expires in {args.expires_days} days")
    return 0


def cmd_entitlements(args) -> int:
    from . import entitlements as ent
    target = Path(args.target).resolve()
    config = load_config(target)
    declared = ent.declared_tiers(config)
    cache_dir = target / ".security-council" / "cache"
    rows = []
    for name in sorted(ent.KNOWN_TIERS):
        res = ent.probe_entitlement(name, config, cache_dir=cache_dir)
        avail = {True: "available", False: "unavailable", None: "unverifiable"}[res.available]
        rows.append({"tier": name, "family": res.family, "model": res.model_id,
                     "declared": res.declared, "availability": avail,
                     "safeguard_posture": res.safeguard_posture, "red": res.is_red,
                     "rung": res.rung, "source": res.source})
    print(json.dumps({"declared": sorted(declared), "tiers": rows}, indent=2))
    return 0


def cmd_eval(args) -> int:
    from .eval import runner
    root = Path(args.fixtures)
    if not (root / "EXPECTED.yaml").is_file():
        print(f"error: no EXPECTED.yaml under {root}", file=sys.stderr)
        return EXIT_USAGE
    run = runner.run_eval(root)
    print(json.dumps({"metrics": run.report.metrics, "violations": run.report.violations,
                      "disposition_actions": run.report.disposition_actions}, indent=2))
    return 1 if run.report.violations else 0


def cmd_setup(args) -> int:
    from .setup_wizard import run_setup
    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    return run_setup(target, profile=args.profile, yes=args.yes, force=args.force)


def cmd_calibrate(args) -> int:
    """Fit a calibration record from an OWASP Benchmark checkout + a prior scan
    of it (R7). Converter-only: the checkout is the user's own clone."""
    from .eval import calibrate as cal_fit
    from .eval import import_owasp
    from .jsonio import finding_from_dict
    checkout = Path(args.checkout)
    try:
        cases, meta = import_owasp.load_cases(checkout)
    except import_owasp.BenchmarkImportError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    run_dir = Path(args.run) if args.run else None
    if run_dir is None:
        runs = sorted((checkout / ".security-council" / "runs").glob("*"))
        if not runs:
            print("error: no prior scan of the checkout found — run "
                  f"`security-council scan {checkout} --arms semgrep` first, or pass --run",
                  file=sys.stderr)
            return EXIT_USAGE
        run_dir = runs[-1]
    fj, mf = run_dir / "findings.json", run_dir / "manifest.json"
    if not (fj.is_file() and mf.is_file()):
        print(f"error: {run_dir} has no findings.json/manifest.json", file=sys.stderr)
        return EXIT_USAGE
    findings = [finding_from_dict(d) for d in json.load(open(fj))]
    run_manifest = json.load(open(mf))
    arm = next((a for a in run_manifest.get("arms", []) if a.get("name") == "semgrep"), None)
    if arm is None or not arm.get("ok"):
        print("error: the run has no successful semgrep arm — the fit covers "
              "semgrep deterministic singletons only", file=sys.stderr)
        return EXIT_USAGE
    from .arms.scanner import SEMGREP_RULESET
    expected = import_owasp.ground_truth(cases)
    outcomes, audit = cal_fit.label_cases(expected, findings)
    record = cal_fit.fit(
        outcomes, corpus_meta=meta, audit=audit,
        scanner={"arm": "semgrep", "family": "semgrep",
                 "tool_version": arm.get("tool_version"), "ruleset": SEMGREP_RULESET},
        min_n=args.min_n, seed=args.seed)
    out_path = Path(args.out) if args.out else \
        checkout / ".security-council" / "calibration.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2) + "\n")
    m = record["metrics"]
    print(f"calibration record written: {out_path}")
    print(f"  corpus {meta['corpus']} {meta['version']} ({meta['cases_total']} cases) · "
          f"semgrep {arm.get('tool_version')} ({SEMGREP_RULESET})")
    for fam, row in record["families"].items():
        floored = "  [deployed value floored]" if row["floor_binding"] else ""
        print(f"  {fam:15} p={row['p']:.3f} logit={row['logit']:+.2f} "
              f"n={row['detections']} wilson95={row['wilson95']}{floored}")
    for fam, why in record["excluded_families"].items():
        print(f"  {fam:15} EXCLUDED: {why}")
    if m.get("test_detections"):
        print(f"  held-out: {m['test_detections']} detections · "
              f"ECE pre-clamp {m['ece_preclamp']} / post-clamp {m['ece_postclamp']} · "
              f"Brier {m['brier_preclamp']}/{m['brier_postclamp']}")
    print("  enable with: score.calibration: <path> (or 'auto' for the packaged record)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-council")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path")
    s.add_argument("--profile", choices=["quick", "ci", "deep", "gov"],
                   help="apply a preset for this run (quick=$0 scanners, ci=baseline "
                        "gating, deep=+AI reviewers+panel [costs money], gov=compliance "
                        "posture); overrides the config file's presets")
    s.add_argument("--arms", help="comma-separated arm names (default: config)")
    s.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low", "info"])
    s.add_argument("--gate-baseline", choices=["all", "new"],
                   help='"new" gates only findings absent from the operator-set baseline')
    s.add_argument("--diff", metavar="BASE",
                   help="change-scoped scan: committed range BASE..HEAD (diff-capable "
                        "arms only: claude-security, codex-security)")
    s.add_argument("--diff-head", metavar="REF", help="head ref for --diff (default HEAD)")
    s.add_argument("--working-tree", action="store_true",
                   help="change-scoped scan of staged+unstaged changes vs --diff BASE "
                        "(codex-security only)")
    s.add_argument("--deep", action="store_true",
                   help="run dedicated agentic arms in their deep mode (slower, costlier)")
    s.add_argument("--tier", help="route same-vendor arms to a gated model tier "
                                  "(mythos, daybreak-blue); must be declared in entitlements")
    s.add_argument("--analyze", metavar="JOBS",
                   help="comma-separated vendor analysis workflows to attach as artifacts "
                        "(threat-model, attack-path, hardening, policy, writeup); "
                        "dual-use ones (attack-path, writeup) are export-excluded")
    s.add_argument("--sbom", action="store_true",
                   help="also generate a CycloneDX SBOM artifact (syft, $0, no network; "
                        "`report --format cyclonedx` then merges findings into it)")
    s.add_argument("--fix", metavar="IDS",
                   help="generate reviewed .patch artifacts (NEVER applied) for these finding "
                        "ids, or 'gating'/'all' for all open findings; runs fenced (needs bwrap)")
    s.add_argument("--fix-job", choices=["suggest-patches", "fix-finding"],
                   default="suggest-patches", help="which vendor fix workflow (default: claude)")
    s.add_argument("--verify-fix", action="store_true",
                   help="after producing a patch, run verify-fix on it as machine evidence "
                        "(fenced, read-only; never closes a finding)")
    s.add_argument("--min-arms", type=int)
    s.add_argument("--out", help="output directory")
    s.add_argument("--json", action="store_true")
    s.add_argument("--inplace", action="store_true", help="scan the target directly (no isolated copy)")
    s.add_argument("--validate", action="store_true", help="run the cross-vendor validator panel")
    s.add_argument("--vendor-validate", action="store_true",
                   help="also collect the vendors' own validate/triage verdicts as "
                        "NON-INDEPENDENT advisory panel voters (never deciding)")
    s.add_argument("--validate-max", type=int, help="cap findings sent to validation")
    s.add_argument("--validate-budget", type=float, default=0.5, help="max USD per validated finding")
    s.set_defaults(fn=cmd_scan)
    su = sub.add_parser("setup", help="guided setup: pick a goal, write the config, "
                                      "print a repo-specific cheat sheet")
    su.add_argument("path", nargs="?", default=".")
    su.add_argument("--profile", choices=["quick", "ci", "deep", "gov"],
                    help="skip the questions and use this profile")
    su.add_argument("--yes", action="store_true",
                    help="non-interactive: accept defaults (profile quick unless --profile)")
    su.add_argument("--force", action="store_true", help="overwrite an existing config")
    su.set_defaults(fn=cmd_setup)

    d = sub.add_parser("doctor", help="check arm availability")
    d.set_defaults(fn=cmd_doctor)
    r = sub.add_parser("report", help="summarize or export a previous run directory")
    r.add_argument("run_dir")
    r.add_argument("--format",
                   choices=["json", "md", "html", "csv", "emass", "cklb", "cyclonedx",
                            "gitlab-sast", "gitlab-codequality",
                            "openvex", "oscal-ar", "oscal-poam"],
                   default="json",
                   help="json summary (default), markdown, self-contained HTML (print for "
                        "PDF), triage CSV, eMASS static-code-scans POST body, STIG Viewer "
                        "CKLB checklist (ASD V6R4), CycloneDX 1.6 VDR, GitLab SAST / Code "
                        "Quality report, OpenVEX, or OSCAL assessment-results / POA&M")
    r.add_argument("--bundle", choices=["triage", "gov", "all"],
                   help="write a set of reports for one audience into --out-dir instead of "
                        "printing one format: triage = csv+html+md, gov = openvex+oscal-ar+"
                        "oscal-poam+cklb (+emass when --app-name/--app-version given)")
    r.add_argument("--out-dir", help="bundle output directory (default: <run_dir>/exports)")
    r.add_argument("--detail-limit", type=int, default=50, help="findings rendered in full (md)")
    r.add_argument("--classification", default="UNCLASSIFIED",
                   help="classification stamped on CKLB rules (default UNCLASSIFIED)")
    r.add_argument("--app-name", help="eMASS applicationName (required for --format emass)")
    r.add_argument("--app-version", help="eMASS application version (required for --format emass)")
    r.add_argument("--scan-date", type=int,
                   help="unix scanDate for eMASS rows (default: the run's finished_at)")
    r.add_argument("--emass-clear", action="store_true",
                   help="emit the clear-findings body for the application instead")
    r.set_defaults(fn=cmd_report)
    en = sub.add_parser("entitlements", help="show declared gated model tiers and probe availability")
    en.add_argument("--target", default=".", help="repo whose config declares entitlements")
    en.set_defaults(fn=cmd_entitlements)
    e = sub.add_parser("eval", help="replay the recorded eval corpus; gate on wrongful suppression")
    e.add_argument("--fixtures", default="tests/fixtures",
                   help="corpus root containing seedrepo/, raw/, EXPECTED.yaml, eval/")
    e.set_defaults(fn=cmd_eval)

    cb = sub.add_parser("calibrate",
                        help="fit a score-calibration record from an OWASP Benchmark checkout")
    cb.add_argument("checkout", help="path to a user-cloned BenchmarkJava checkout (GPL; "
                                     "read at runtime, never vendored)")
    cb.add_argument("--run", help="scan run dir of the checkout (default: its latest run)")
    cb.add_argument("--out", help="record output path (default: "
                                  "<checkout>/.security-council/calibration.json)")
    cb.add_argument("--min-n", type=int, default=30, help="min train detections per family")
    cb.add_argument("--seed", type=int, default=0, help="train/test split seed")
    cb.set_defaults(fn=cmd_calibrate)

    o = sub.add_parser("outcome", help="record operator ground truth for a finding")
    osub = o.add_subparsers(dest="action", required=True)
    om = osub.add_parser("mark", help="mark a finding TP/FP (feeds the score history term)")
    om.add_argument("finding_id")
    om.add_argument("--verdict", required=True,
                    choices=["true_positive", "false_positive", "tp", "fp"])
    om.add_argument("--note", default="")
    om.add_argument("--operator", help="defaults to the OS user")
    om.add_argument("--run", help="run directory (default: latest under the target)")
    om.add_argument("--target", default=".", help="repo whose decision store to use")
    om.set_defaults(fn=cmd_outcome_mark)

    b = sub.add_parser("baseline", help="manage the operator-gated baseline")
    bsub = b.add_subparsers(dest="action", required=True)
    bs = bsub.add_parser("set", help="snapshot a run's findings as the baseline")
    bs.add_argument("--run", help="run directory (default: latest under the target)")
    bs.add_argument("--target", default=".")
    bs.add_argument("--operator")
    bs.set_defaults(fn=cmd_baseline_set)
    bw = bsub.add_parser("show", help="show the current baseline pointer")
    bw.add_argument("--target", default=".")
    bw.set_defaults(fn=cmd_baseline_show)

    from .model import OPENVEX_JUSTIFICATIONS
    sp = sub.add_parser(
        "suppress", help="record a HUMAN suppression for a finding's root cause "
                         "(root-cause-scoped, expiring; applies on future scans)")
    sp.add_argument("finding_id")
    sp.add_argument("--operator", required=True)
    sp.add_argument("--justification", required=True)
    sp.add_argument("--accept-risk", action="store_true",
                    help="record accepted_risk instead of suppressed")
    sp.add_argument("--expires-days", type=int, default=90)
    sp.add_argument("--vex-justification", choices=sorted(OPENVEX_JUSTIFICATIONS),
                    help="also mark OpenVEX not_affected with this justification")
    sp.add_argument("--run", help="run directory (default: latest under the target)")
    sp.add_argument("--target", default=".")
    sp.set_defaults(fn=cmd_suppress)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
