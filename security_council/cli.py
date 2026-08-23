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
    config = load_config(target)
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
                   out_dir=Path(args.out) if args.out else None,
                   isolate=not args.inplace,
                   validate=args.validate, validate_max_findings=args.validate_max,
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
    return 0


def cmd_report(args) -> int:
    mf = Path(args.run_dir) / "manifest.json"
    if not mf.is_file():
        print(f"error: no manifest.json in {args.run_dir}", file=sys.stderr)
        return EXIT_USAGE
    m = json.load(open(mf))
    if args.format == "emass":
        from .export import emass
        from .jsonio import finding_from_dict
        if not (args.app_name and args.app_version):
            print("error: --format emass requires --app-name and --app-version", file=sys.stderr)
            return EXIT_USAGE
        if args.emass_clear:
            print(json.dumps(emass.clear_findings_payload(
                application_name=args.app_name, version=args.app_version), indent=2))
            return 0
        fj = Path(args.run_dir) / "findings.json"
        findings = [finding_from_dict(d) for d in json.load(open(fj))] if fj.is_file() else []
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
        from .jsonio import finding_from_dict
        fj = Path(args.run_dir) / "findings.json"
        findings = [finding_from_dict(d) for d in json.load(open(fj))] if fj.is_file() else []
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
        from .jsonio import finding_from_dict
        fj = Path(args.run_dir) / "findings.json"
        findings = [finding_from_dict(d) for d in json.load(open(fj))] if fj.is_file() else []
        doc, meta = (gl.to_gitlab_sast(findings, m) if args.format == "gitlab-sast"
                     else gl.to_gitlab_code_quality(findings))
        print(json.dumps(doc, indent=2))
        print(f"gitlab: {meta}", file=sys.stderr)
        return 0
    if args.format == "md":
        from .export import markdown
        from .jsonio import finding_from_dict
        fj = Path(args.run_dir) / "findings.json"
        findings = [finding_from_dict(d) for d in json.load(open(fj))] if fj.is_file() else []
        print(markdown.to_markdown(findings, m, detail_limit=args.detail_limit))
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-council")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path")
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
    d = sub.add_parser("doctor", help="check arm availability")
    d.set_defaults(fn=cmd_doctor)
    r = sub.add_parser("report", help="summarize or export a previous run directory")
    r.add_argument("run_dir")
    r.add_argument("--format",
                   choices=["json", "md", "emass", "gitlab-sast", "gitlab-codequality",
                            "openvex", "oscal-ar", "oscal-poam"],
                   default="json",
                   help="json summary (default), markdown, eMASS static-code-scans POST body, "
                        "GitLab SAST / Code Quality report, OpenVEX, or OSCAL "
                        "assessment-results / POA&M")
    r.add_argument("--detail-limit", type=int, default=50, help="findings rendered in full (md)")
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
