"""security-council command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .arms.registry import build_arm, known_arms
from .config import load_config
from .orchestrator import run_scan

EXIT_USAGE = 2


def _build_arms(names: list[str], config: dict | None = None):
    options = ((config or {}).get("arms") or {}).get("options") or {}
    return [build_arm(n, options=options.get(n)) for n in names]


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
    names = [n.strip() for n in args.arms.split(",")] if args.arms else config["arms"]["enabled"]
    unknown = [n for n in names if n not in known_arms()]
    if unknown:
        print(f"error: unknown arms {unknown}; known: {known_arms()}", file=sys.stderr)
        return EXIT_USAGE
    run = run_scan(target, _build_arms(names, config), config,
                   out_dir=Path(args.out) if args.out else None,
                   isolate=not args.inplace,
                   validate=args.validate, validate_max_findings=args.validate_max,
                   validate_budget_usd=args.validate_budget)
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
    run_dir = _run_dir(args)
    if run_dir is None:
        print("error: no run with findings.json found (pass --run)", file=sys.stderr)
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
    s.add_argument("--min-arms", type=int)
    s.add_argument("--out", help="output directory")
    s.add_argument("--json", action="store_true")
    s.add_argument("--inplace", action="store_true", help="scan the target directly (no isolated copy)")
    s.add_argument("--validate", action="store_true", help="run the cross-vendor validator panel")
    s.add_argument("--validate-max", type=int, help="cap findings sent to validation")
    s.add_argument("--validate-budget", type=float, default=0.5, help="max USD per validated finding")
    s.set_defaults(fn=cmd_scan)
    d = sub.add_parser("doctor", help="check arm availability")
    d.set_defaults(fn=cmd_doctor)
    r = sub.add_parser("report", help="summarize a previous run directory")
    r.add_argument("run_dir")
    r.add_argument("--format", choices=["json", "md"], default="json",
                   help="json summary (default) or regenerate the markdown report")
    r.add_argument("--detail-limit", type=int, default=50, help="findings rendered in full (md)")
    r.set_defaults(fn=cmd_report)
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
