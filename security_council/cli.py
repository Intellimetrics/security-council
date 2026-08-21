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
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
