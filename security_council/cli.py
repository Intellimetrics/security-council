"""security-council command-line interface."""

from __future__ import annotations

import argparse
import json
import os
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


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1 (omit to validate everything)")
    return n


def _print_validation_preview(p: dict) -> None:
    """R19 A4: one stderr line BEFORE any panel convenes — what `--validate`
    is about to attempt and its budget ceiling (stderr so `--json` stdout
    stays parseable)."""
    cap = p.get("max_findings")
    line = (f"validation: {p['selected']} of {p['eligible']} eligible finding(s) "
            f"selected (cap {cap if cap else 'none'}, "
            f"strategy {p['strategy'].replace('_', ' ')})")
    if p.get("budget_ceiling_usd") is not None:
        line += (f"; budget ceiling ${p['budget_ceiling_usd']:.2f} "
                 f"({p['selected']} × ${p['per_finding_budget_usd']:.2f}/finding fuse — "
                 "an upper bound, not a spend prediction)")
    print(line, file=sys.stderr)


def cmd_scan(args) -> int:
    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(target,
                             explicit=Path(args.config) if getattr(args, "config", None) else None,
                             ignore_repo=bool(getattr(args, "ignore_repo_config", False)))
    except ValueError as e:                    # unknown profile / invalid value / bad path
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    if (config.get("_source") or {}).get("kind") == "repository":
        # not an error: a repo's own config is the normal local workflow. But a
        # CI gate on an untrusted branch must not let that branch configure the
        # scanner, so say where the config came from every time.
        print(f"note: config loaded from the scanned repository: "
              f"{config['_source']['path']} — in CI pass --ignore-repo-config or "
              f"--config <operator file> so the branch under test cannot configure "
              f"its own scan", file=sys.stderr)
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
    if getattr(args, "require_signatures", None):
        # R13: CI is the operator-side trust boundary, so the templates name
        # the level explicitly (`enforce`) rather than inherit whatever the
        # defaults or an operator file say. Last, so the flag wins.
        if not isinstance(config.get("decisions"), dict):
            config["decisions"] = {}
        config["decisions"]["require_signatures"] = args.require_signatures
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
        # R12: this only ever touched the two dedicated plugin arms, so once the
        # `deep` PROFILE moved to the house arms the `--deep` FLAG became a
        # no-op for it. Apply depth to whichever arms are actually enabled.
        opts = config["arms"].setdefault("options", {})
        enabled = set(names)      # `names` is the effective list; --arms wins over config
        for dn, key, val in (("codex-security", "mode", "deep"),
                             ("claude-security", "effort", "high"),
                             ("claude", "effort", "high"),
                             ("agy", "effort", "high")):
            if dn in enabled:
                opts.setdefault(dn, {})[key] = val
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
        analysis_arms = [build_analysis_arm(j, family=getattr(args, "analyze_with", None),
                                            options=options.get(f"analysis:{j}")) for j in jobs]
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
    verify_patch = None
    if getattr(args, "verify_patch", None):
        patch_file = Path(args.verify_patch).resolve()
        if not patch_file.is_file():
            print(f"error: --verify-patch {patch_file} is not a file", file=sys.stderr)
            return EXIT_USAGE
        if args.inplace:
            print("error: --verify-patch applies the patch to a scratch copy only; it is "
                  "refused with --inplace", file=sys.stderr)
            return EXIT_USAGE
        ids = [i.strip() for i in (getattr(args, "verify_for", None) or "").split(",")
               if i.strip()]
        verify_patch = {"patch": str(patch_file), "finding_ids": ids or None}
    elif getattr(args, "verify_for", None):
        print("error: --for names the finding(s) for --verify-patch; pass a patch file",
              file=sys.stderr)
        return EXIT_USAGE
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
                   vendor_validate=bool(getattr(args, "vendor_validate", False)),
                   verify_patch=verify_patch,
                   on_validation_preview=_print_validation_preview)
    if getattr(args, "open", False):
        _open_report(run.out_dir)
    if args.json:
        print(json.dumps({"run_id": run.run_id, "out_dir": str(run.out_dir),
                          "exit_code": run.exit_code, "counts": run.manifest["counts"],
                          "degradations": run.degradations,
                          "verify_fix": run.manifest.get("verify_fix")}, indent=2))
    else:
        _print_summary(run)
    return run.exit_code


def cmd_consolidate(args) -> int:
    """Combine already-produced canonical artifacts into one gated report.

    Import-only BY CONSTRUCTION: this verb builds exclusively `kind ==
    "import"` arms, so it can never re-run a paid producer. Every source is
    revision-bound to the current clean checkout (the arm fails closed on a
    mismatch or dirty tree). Import paths come ONLY from these flags — never
    from the scanned repository's config, so a hostile repo cannot choose the
    evidence that gets ingested. `--validate` convenes the external panel over
    the consolidated findings; that is the read-only cross-examination lane,
    not a producer re-run.
    """
    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    from .arms.import_bundle import (CodexSecurityBundleImportArm,
                                     SecurityCouncilRunImportArm)
    arms = ([SecurityCouncilRunImportArm(run_dir=d) for d in (args.import_run or [])]
            + [CodexSecurityBundleImportArm(bundle_dir=b)
               for b in (args.import_codex_bundle or [])])
    if not arms:
        print("error: name at least one source: --import-run DIR and/or "
              "--import-codex-bundle DIR", file=sys.stderr)
        return EXIT_USAGE
    # structural guard by kind (never a name allowlist): whatever ends up in
    # `arms`, nothing that can execute a producer may pass this verb
    non_import = [getattr(a, "name", "?") for a in arms
                  if getattr(a, "kind", None) != "import"]
    if non_import:
        print(f"error: consolidate accepts only import arms; got {non_import}",
              file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(target,
                             explicit=Path(args.config) if getattr(args, "config", None) else None,
                             ignore_repo=bool(getattr(args, "ignore_repo_config", False)))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    if (config.get("_source") or {}).get("kind") == "repository":
        print(f"note: config loaded from the scanned repository: "
              f"{config['_source']['path']} — policy only; import paths always "
              f"come from the command line", file=sys.stderr)
    if args.fail_on_severity:
        config["policy"]["fail_on_severity"] = args.fail_on_severity
    if getattr(args, "gate_baseline", None):
        config["policy"]["gate_baseline"] = args.gate_baseline
    if getattr(args, "require_signatures", None):
        if not isinstance(config.get("decisions"), dict):
            config["decisions"] = {}
        config["decisions"]["require_signatures"] = args.require_signatures
    run = run_scan(target, arms, config,
                   out_dir=Path(args.out).resolve() if args.out else None,
                   validate=args.validate,
                   validate_max_findings=args.validate_max,
                   validate_budget_usd=args.validate_budget,
                   on_validation_preview=_print_validation_preview)
    if getattr(args, "open", False):
        _open_report(run.out_dir)
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
    for pv in ((m.get("verify_fix") or {}).get("patches") or []):
        cnt = pv.get("counts") or {}
        print(f"patch verification {pv.get('patch')}: {cnt.get('fixed', 0)} fixed, "
              f"{cnt.get('not_fixed', 0)} not fixed, {cnt.get('unproven', 0)} unproven "
              f"— machine evidence, requires human review (never closes a finding)")
        for r in pv.get("results") or []:
            print(f"  {r.get('finding_id')}  {r.get('verdict'):<10} {r.get('uri')}  "
                  f"{'; '.join(r.get('reasons') or [])[:160]}")
    if run.degradations:
        print(f"degradations: {run.degradations}")
    print(f"reports: {run.out_dir}  (summary.html, summary.md, merged.sarif, findings.json, "
          "manifest.json)")
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
    from . import signing
    ver = signing.verifier()
    print(f"  {'ssh-keygen':<13} {'ready' if ver else 'MISSING':<11} "
          f"{ver or 'no ssh-keygen -Y (OpenSSH >= 8.2): decision signing unavailable; '
                     'require_signatures: enforce refuses every signed decision (fail-closed)'}")
    lc = shutil.which("llm-council")
    print(f"  {'llm-council':<13} {'ready' if lc else 'unavailable':<11} "
          + (f"{lc}  (validator panel backend for `scan --validate`)" if lc else
             "not on PATH: `scan --validate` cannot convene a panel — findings would be "
             "needs_human and the run degraded (validator_unavailable); "
             "https://github.com/Intellimetrics/llm-council"))
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


def _open_report(run_dir: Path, *, system_name: str | None = None) -> int:
    """Render (or refresh) summary.html for a run and open it in the browser."""
    import webbrowser
    from .export import html_export
    mf = run_dir / "manifest.json"
    if not mf.is_file():
        print(f"error: no manifest.json in {run_dir}", file=sys.stderr)
        return EXIT_USAGE
    m = json.load(open(mf))
    if system_name:
        m = dict(m, report_identity={"system_name": system_name})
    page = run_dir / "summary.html"
    md = run_dir / "summary.md"
    page.write_text(html_export.to_html(
        _load_findings(run_dir), m, scores=_load_scores(run_dir) or None, run_dir=run_dir,
        markdown_text=md.read_text() if md.is_file() else None))
    print(f"report: {page}")
    if not webbrowser.open(page.resolve().as_uri()):
        print("note: no browser could be opened here; open the path above by hand",
              file=sys.stderr)
    return 0


def cmd_serve(args) -> int:
    """Read-only viewer for a target's runs (and the docs), loopback by default."""
    import time
    import webbrowser
    from .serve import ReportServer, ServeRefused, needs_token
    token = args.token
    if token is None and needs_token(args.bind):
        token = "auto"
    try:
        srv = ReportServer(args.target, bind=args.bind, port=args.port, token=token,
                           include_dual_use=args.include_dual_use, docs_root=args.docs)
        url = srv.start()
    except ServeRefused as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as e:
        print(f"error: cannot bind {args.bind}:{args.port}: {e}", file=sys.stderr)
        return EXIT_USAGE
    exposure = ("loopback only — this machine" if not needs_token(args.bind)
                else f"LAN-exposed on {args.bind} — anyone with the token can read every report")
    print(f"security-council viewer: {url}\n  {exposure}\n  read-only · GET only · "
          f"dual-use artifacts {'INCLUDED' if args.include_dual_use else 'withheld'} · "
          f"docs {'mounted' if srv.docs_root else 'not found'}\n  Ctrl-C to stop", flush=True)
    if args.open:
        webbrowser.open(url)
    if getattr(args, "_once", False):            # tests
        srv.stop()
        return 0
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0


def cmd_runs(args) -> int:
    """List a target's runs, newest first — the answer to 'where did it go?'."""
    target = Path(args.target).resolve()
    dirs = run_dirs(target)
    rows = []
    for d in dirs:
        try:
            m = json.loads((d / "manifest.json").read_text())
        except (OSError, ValueError):
            continue
        sev = (m.get("counts") or {}).get("by_severity") or {}
        rows.append({"run_id": d.name, "path": str(d), "started_at": m.get("started_at"),
                     "exit_code": m.get("exit_code"), "total": (m.get("counts") or {}).get("total"),
                     "by_severity": sev, "arms": [a.get("name") for a in m.get("arms") or []],
                     "failed_arms": [a.get("name") for a in m.get("arms") or [] if not a.get("ok")],
                     "scope": (m.get("scan_scope") or {}).get("kind", "full"),
                     "degradations": len(m.get("degradations") or []),
                     "summary_html": str(d / "summary.html") if (d / "summary.html").is_file()
                     else None})
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print(f"no runs under {target / '.security-council' / 'runs'}", file=sys.stderr)
        return 1
    from .export.markdown import EXIT_LABELS
    link = target / ".security-council" / "runs" / "latest"
    tail = f"; latest -> {link.resolve().name}" if link.is_symlink() else ""
    print(f"runs under {target / '.security-council' / 'runs'} (newest first{tail}):")
    for r in rows:
        sev = " ".join(f"{k}={v}" for k, v in r["by_severity"].items())
        flags = []
        if r["scope"] != "full":
            flags.append(f"partial:{r['scope']}")
        if r["failed_arms"]:
            flags.append("failed:" + ",".join(r["failed_arms"]))
        if r["degradations"]:
            flags.append(f"degr={r['degradations']}")
        print(f"  {r['run_id']}  exit {r['exit_code']}  {EXIT_LABELS.get(r['exit_code'], ''):<34} "
              f"{str(r['total']):>3} findings  {sev:<30} arms={','.join(r['arms'])}"
              + (f"  [{' '.join(flags)}]" if flags else ""))
    print(f"open the newest: security-council report --open   "
          f"(or {dirs[0] / 'summary.html'})")
    return 0


def cmd_report(args) -> int:
    if not args.run_dir:
        d = latest_run(Path(args.target).resolve(), need_findings=False)
        if d is None:
            print(f"error: no runs under {Path(args.target).resolve() / '.security-council' / 'runs'}"
                  " (pass a run directory)", file=sys.stderr)
            return EXIT_USAGE
        args.run_dir = str(d)
    if getattr(args, "open", False):
        return _open_report(Path(args.run_dir), system_name=args.system_name)
    mf = Path(args.run_dir) / "manifest.json"
    if not mf.is_file():
        print(f"error: no manifest.json in {args.run_dir}", file=sys.stderr)
        return EXIT_USAGE
    m = json.load(open(mf))
    if args.system_name:
        m = dict(m, report_identity={"system_name": args.system_name})
    if args.bundle:
        return _report_bundle(args, m)
    if args.format == "csv":
        from .export import csv_export
        print(csv_export.to_csv(_load_findings(args.run_dir)), end="")
        return 0
    if args.format == "html":
        from .export import html_export
        md = Path(args.run_dir) / "summary.md"
        print(html_export.to_html(_load_findings(args.run_dir), m,
                                  scores=_load_scores(args.run_dir) or None,
                                  run_dir=Path(args.run_dir),
                                  markdown_text=md.read_text() if md.is_file() else None))
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


def _signer(args, store, *, action: str):
    """Resolve the signing key for a human write (flag > env > config) and the
    effective signature policy for this target. Returns (Signer|None, policy)
    — or raises SystemExit-free: prints and returns (None, None) on refusal.

    Under `enforce` an unsigned write is refused HERE, not silently written
    and then refused on every scan: a record that can never apply is worse
    than an error message that says what to do."""
    from . import signing
    from .decisions import Signer
    config = load_config(Path(args.target).resolve())
    policy = signing.resolve_policy(config, store_initialised=store.store_meta() is not None,
                                    store_has_decisions=store.has_decisions(),
                                    now_iso=_now_iso())
    key = (getattr(args, "signing_key", None)
           or os.environ.get("SECURITY_COUNCIL_SIGNING_KEY")
           or (config.get("decisions") or {}).get("signing_key"))
    if key:
        return Signer(key_path=str(key)), policy
    if policy["effective"] == "enforce":
        print(f"error: {action} must be signed here (decisions.require_signatures: "
              f"{policy['configured']} -> enforce: {policy['reason']}).\n"
              "  1. security-council decisions trust --principal <operator> "
              "--key ~/.ssh/id_ed25519.pub\n"
              f"  2. re-run with --signing-key ~/.ssh/id_ed25519 (or set "
              "$SECURITY_COUNCIL_SIGNING_KEY / decisions.signing_key in config)\n"
              "  or set decisions.require_signatures: warn to record unsigned decisions.",
              file=sys.stderr)
        return None, None
    return None, policy


def _signing_failed(e) -> int:
    print(f"error: signing failed: {e}", file=sys.stderr)
    return EXIT_USAGE


def _run_dir(args) -> Path | None:
    if getattr(args, "run", None):
        d = Path(args.run)
        return d if (d / "findings.json").is_file() else None
    return latest_run(Path(args.target).resolve())


def run_dirs(target: Path) -> list[Path]:
    """Completed run directories under the target, newest first. The `latest`
    symlink is skipped (it is one of the others) and so is anything that is
    not shaped like a run id."""
    import re
    runs = target / ".security-council" / "runs"
    if not runs.is_dir():
        return []
    out = [d for d in runs.iterdir()
           if d.is_dir() and not d.is_symlink() and re.fullmatch(r"\d{8}_\d{6}", d.name)
           and (d / "manifest.json").is_file()]
    return sorted(out, key=lambda d: d.name, reverse=True)


def latest_run(target: Path, *, need_findings: bool = True) -> Path | None:
    for d in run_dirs(target):
        if not need_findings or (d / "findings.json").is_file():
            return d
    return None


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
    store = _store(args)
    signer, policy = _signer(args, store, action="outcome mark")
    if policy is None:
        return EXIT_USAGE
    from .signing import SigningError
    try:
        store.mark_outcome(root_cause=fp.get("root_cause", ""), finding_id=row["id"],
                           verdict=verdict, operator=operator, note=args.note,
                           now_iso=_now_iso(), title=row.get("title", ""),
                           context_hash=fp.get("context_hash", ""), signer=signer)
    except SigningError as e:
        return _signing_failed(e)
    print(f"marked {row['id']} {verdict} (operator {operator}, "
          f"{'signed' if signer else 'UNSIGNED'}); "
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
    store = _store(args)
    signer, policy = _signer(args, store, action="baseline set")
    if policy is None:
        return EXIT_USAGE
    if signer and not args.operator:
        print("error: --operator is required to sign the baseline (it is the signing "
              "principal)", file=sys.stderr)
        return EXIT_USAGE
    from .signing import SigningError
    try:
        bl = store.set_baseline(rows, run_id=run_dir.name, now_iso=_now_iso(),
                                operator=args.operator, signer=signer)
    except SigningError as e:
        return _signing_failed(e)
    print(f"baseline set from run {run_dir.name}: {len(bl['findings'])} findings "
          f"({'signed' if signer else 'UNSIGNED'})")
    return 0


def cmd_baseline_show(args) -> int:
    bl = _store(args).load_baseline(signature_policy="enforce")
    if bl is None:
        print("no baseline set (security-council baseline set)", file=sys.stderr)
        return 1
    print(json.dumps({"run_id": bl.get("run_id"), "set_at": bl.get("set_at"),
                      "operator": bl.get("operator"),
                      "findings": len(bl.get("findings") or []),
                      "integrity": bl.get("integrity"),
                      "signature": bl.get("signature_status")}, indent=2))
    return 0


def cmd_decisions_init(args) -> int:
    if _nested_write_refused("decisions init"):
        return EXIT_USAGE
    store = _store(args)
    fresh = store.store_meta() is None
    meta = store.init_store(operator=args.operator, now_iso=_now_iso())
    print(f"{'initialised' if fresh else 'already initialised'}: store {meta['store_id']} "
          f"at {store.store_path}\n"
          f"roster: {store.allowed_signers_path} "
          f"({len(store.trusted_principals())} signer(s))\n"
          "next: security-council decisions trust --principal <operator> "
          "--key ~/.ssh/id_ed25519.pub")
    return 0


def cmd_decisions_trust(args) -> int:
    if _nested_write_refused("decisions trust"):
        return EXIT_USAGE
    from .signing import SigningError
    key = Path(os.path.expanduser(args.key))
    if not key.is_file():
        print(f"error: public key file not found: {key}", file=sys.stderr)
        return EXIT_USAGE
    try:
        line = _store(args).add_trusted_signer(principal=args.principal,
                                               pubkey_text=key.read_text(),
                                               now_iso=_now_iso(), operator=args.operator)
    except SigningError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    print(f"trusted: {line.strip()}\n"
          "commit .security-council/allowed_signers and store.json with the decisions, "
          "behind CODEOWNERS + required review.")
    return 0


def cmd_decisions_verify(args) -> int:
    from . import signing
    store = _store(args)
    config = load_config(Path(args.target).resolve())
    policy = signing.resolve_policy(config, store_initialised=store.store_meta() is not None,
                                    store_has_decisions=store.has_decisions(),
                                    now_iso=_now_iso())
    level = args.policy or policy["effective"]
    audit = store.verify_store(signature_policy=level)
    audit["policy_resolution"] = policy
    if args.json:
        print(json.dumps(audit, indent=2))
    else:
        s = audit["summary"]
        print(f"store {audit['store_id'] or '(not initialised)'} · policy {level} "
              f"(configured {policy['configured']}: {policy['reason']})")
        print(f"verifier: {audit['verifier'] or 'MISSING'} · roster: "
              f"{', '.join(audit['roster']) or '(empty)'}")
        for w in audit.get("roster_warnings") or []:
            print(f"  ⚠ roster {w}")
        for r in audit["rows"]:
            who = r.get("operator") or "—"
            what = r.get("lifecycle") or r.get("verdict") or r.get("kind")
            mark = "ok " if r["applies"] else "REFUSED"
            print(f"  {mark:<8} {r['kind']:<12} {r['signature']:<12} {what:<16} {who:<20} "
                  f"{(r.get('finding_id') or r.get('run_id') or '')[:20]:<20} "
                  f"{r.get('detail', '')[:60]}")
        print(f"{s['rows']} decision(s): {s['verified']} verified · {s['not_verified']} not "
              f"verified · {s['machine']} machine · {s['would_refuse']} would be refused "
              f"under {level}")
    return 1 if audit["summary"]["would_refuse"] else 0


def cmd_suppress(args) -> int:
    if _nested_write_refused("suppress"):
        return EXIT_USAGE
    resolved = _resolve(args)
    if resolved is None:
        return EXIT_USAGE
    _, row = resolved
    fp = row.get("fingerprints") or {}
    lifecycle = "accepted_risk" if args.accept_risk else "suppressed"
    store = _store(args)
    signer, policy = _signer(args, store, action="suppress")
    if policy is None:
        return EXIT_USAGE
    from .signing import SigningError
    try:
        store.record_human_decision(
            root_cause=fp.get("root_cause", ""), context_hash=fp.get("context_hash", ""),
            finding_id=row["id"], title=row.get("title", ""), operator=args.operator,
            justification=args.justification, now_iso=_now_iso(), lifecycle=lifecycle,
            expires_days=args.expires_days, vex_justification=args.vex_justification,
            signer=signer)
    except SigningError as e:
        return _signing_failed(e)
    print(f"recorded human {lifecycle} for {row['id']} (root cause {fp.get('root_cause')}, "
          f"{'signed by ' + args.operator if signer else 'UNSIGNED'}); "
          f"applies on future scans, expires in {args.expires_days} days")
    if not signer and policy["effective"] == "warn":
        print("note: this decision is unsigned; scans will apply it but flag it "
              f"({policy['reason']})", file=sys.stderr)
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


_SIGNING_KEY_HELP = ("SSH key to sign this decision with (ssh-keygen -Y; private key, or a "
                     ".pub whose key is in ssh-agent). Defaults to $SECURITY_COUNCIL_SIGNING_KEY, "
                     "then decisions.signing_key in config. Required when "
                     "require_signatures resolves to enforce.")


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
    s.add_argument("--config", metavar="PATH",
                   help="load THIS config file (no directory walk) — the operator's file, "
                        "not the scanned repository's")
    s.add_argument("--ignore-repo-config", action="store_true",
                   help="ignore any .security-council.yaml in the scanned repository and "
                        "use the defaults plus CLI flags; use in CI so the branch under "
                        "test cannot configure its own scan")
    s.add_argument("--arms", help="comma-separated arm names (default: config)")
    s.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low", "info"])
    s.add_argument("--gate-baseline", choices=["all", "new"],
                   help='"new" gates only findings absent from the operator-set baseline')
    s.add_argument("--open", action="store_true",
                   help="open the run's summary.html in a browser when the scan finishes")
    s.add_argument("--require-signatures", choices=["off", "warn", "enforce", "auto"],
                   help="decision-signature policy for this run (docs/signing.md); the CI "
                        "templates pass `enforce` so a committed store cannot lower it")
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
                   help="house analysis documents, attached as artifacts (never findings, "
                        "never gate): threat-model, attack-path, hardening, policy, writeup "
                        "(comma-separated). Sends the scanned tree to the chosen CLI's "
                        "vendor; attack-path and writeup are dual-use (raw/-only)")
    s.add_argument("--analyze-with", choices=["claude", "codex", "agy"], default=None,
                   help="which house CLI runs the --analyze jobs (default claude, or "
                        "arms.options.'analysis:<job>'.cli)")
    s.add_argument("--sbom", action="store_true",
                   help="also generate a CycloneDX SBOM artifact (syft, $0, no network; "
                        "`report --format cyclonedx` then merges findings into it)")
    s.add_argument("--fix", metavar="IDS",
                   help="[NOT FUNCTIONAL IN 0.2.0 — refuses honestly] generate reviewed .patch "
                        "artifacts (NEVER applied); the no-network fence cannot reach a vendor "
                        "CLI, see docs/reviews/R11-fix-lane-and-fence.md")
    s.add_argument("--fix-job", choices=["suggest-patches", "fix-finding"],
                   default="suggest-patches", help="which vendor fix workflow (default: claude)")
    s.add_argument("--verify-fix", action="store_true",
                   help="verify each patch --fix produces DETERMINISTICALLY: apply it to a "
                        "scratch copy and re-run the scanners that reported the finding "
                        "(fixed | not_fixed | unproven, machine evidence, never closes a "
                        "finding). Depends on --fix, which is not functional in 0.2.0 — to "
                        "verify your OWN patch use --verify-patch")
    s.add_argument("--verify-patch", metavar="FILE",
                   help="verify YOUR patch, $0 and offline: apply FILE to a scratch copy "
                        "(never your tree), re-run the deterministic scanners that reported "
                        "each finding, and record fixed | not_fixed | unproven as machine "
                        "evidence in the manifest, summary and decision store — a human "
                        "still decides; nothing is closed. Without --for, every open finding "
                        "in the files the patch touches is checked (docs/verify-fix.md)")
    s.add_argument("--for", dest="verify_for", metavar="IDS",
                   help="finding id(s) to check with --verify-patch (comma-separated, from "
                        "the summary; a unique prefix of 6+ characters is accepted)")
    s.add_argument("--min-arms", type=int)
    s.add_argument("--out", help="output directory")
    s.add_argument("--json", action="store_true")
    s.add_argument("--inplace", action="store_true", help="scan the target directly (no isolated copy)")
    s.add_argument("--validate", action="store_true", help="run the cross-vendor validator panel")
    s.add_argument("--vendor-validate", action="store_true",
                   help="also collect the vendors' own validate/triage verdicts as "
                        "NON-INDEPENDENT advisory panel voters (never deciding)")
    s.add_argument("--validate-max", type=_positive_int)
    s.add_argument("--validate-budget", type=float, default=0.5, help="max USD per validated finding")
    s.set_defaults(fn=cmd_scan)
    cs = sub.add_parser("consolidate",
                        help="combine prior runs / sealed bundles into one gated report "
                             "without re-running their producers (revision-bound)")
    cs.add_argument("path")
    cs.add_argument("--import-run", action="append", metavar="DIR",
                    help="a prior security-council run directory (repeatable)")
    cs.add_argument("--import-codex-bundle", action="append", metavar="DIR",
                    help="a sealed Codex Security bundle directory (repeatable)")
    cs.add_argument("--config", help="load THIS config file (no directory walk)")
    cs.add_argument("--ignore-repo-config", action="store_true",
                    help="never load config from the consolidated repository")
    cs.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low", "info"])
    cs.add_argument("--gate-baseline", choices=["all", "new"])
    cs.add_argument("--require-signatures", choices=["off", "warn", "enforce", "auto"])
    cs.add_argument("--validate", action="store_true",
                    help="convene the external validator panel over the consolidated findings")
    cs.add_argument("--validate-max", type=_positive_int)
    cs.add_argument("--validate-budget", type=float, default=0.5)
    cs.add_argument("--out", help="run output directory")
    cs.add_argument("--json", action="store_true")
    cs.add_argument("--open", action="store_true", help="open summary.html when done")
    cs.set_defaults(fn=cmd_consolidate)
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
    sv = sub.add_parser("serve", help="read-only web viewer for a target's run reports (and "
                                      "the docs); loopback by default, LAN with a token")
    sv.add_argument("--target", default=".")
    sv.add_argument("--bind", default="127.0.0.1",
                    help="address to listen on; anything but loopback requires a token "
                         "(default 127.0.0.1; use 0.0.0.0 or your LAN IP to expose)")
    sv.add_argument("--port", type=int, default=8642)
    sv.add_argument("--token", help="access token for non-loopback binds; `auto` generates "
                                    "one and prints it (the default when exposing)")
    sv.add_argument("--include-dual-use", action="store_true",
                    help="also serve dual-use analysis artifacts (attack paths, write-ups)")
    sv.add_argument("--docs", help="directory of user docs to mount at /docs (default: the "
                                   "checkout's docs/ if present)")
    sv.add_argument("--open", action="store_true", help="open the viewer in a browser")
    sv.set_defaults(fn=cmd_serve)

    ru = sub.add_parser("runs", help="list a target's scan runs, newest first, with exit code "
                                     "and counts — where the reports are")
    ru.add_argument("--target", default=".")
    ru.add_argument("--json", action="store_true")
    ru.set_defaults(fn=cmd_runs)

    r = sub.add_parser("report", help="summarize or export a run directory (default: the "
                                      "latest run under --target)")
    r.add_argument("run_dir", nargs="?", help="run directory (default: latest run)")
    r.add_argument("--target", default=".", help="repo whose latest run to use when run_dir "
                                                 "is omitted")
    r.add_argument("--open", action="store_true",
                   help="write summary.html into the run directory and open it in a browser")
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
    r.add_argument("--system-name",
                   help="display name for the assessed system in HTML reports "
                        "(default: target directory name)")
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
    om.add_argument("--signing-key", help=_SIGNING_KEY_HELP)
    om.set_defaults(fn=cmd_outcome_mark)

    b = sub.add_parser("baseline", help="manage the operator-gated baseline")
    bsub = b.add_subparsers(dest="action", required=True)
    bs = bsub.add_parser("set", help="snapshot a run's findings as the baseline")
    bs.add_argument("--run", help="run directory (default: latest under the target)")
    bs.add_argument("--target", default=".")
    bs.add_argument("--operator")
    bs.add_argument("--signing-key", help=_SIGNING_KEY_HELP)
    bs.set_defaults(fn=cmd_baseline_set)

    dc = sub.add_parser("decisions", help="decision-store identity, signer roster, and "
                                          "signature audit (R9 signing lane)")
    dsub = dc.add_subparsers(dest="action", required=True)
    di = dsub.add_parser("init", help="give the store an identity (store.json) and an empty "
                                      "allowed_signers roster; idempotent")
    di.add_argument("--target", default=".")
    di.add_argument("--operator")
    di.set_defaults(fn=cmd_decisions_init)
    dt = dsub.add_parser("trust", help="add an operator's SSH public key to allowed_signers "
                                       "(the principal is the --operator name they sign with)")
    dt.add_argument("--principal", required=True,
                    help="one token, e.g. an email; must equal the operator on their decisions")
    dt.add_argument("--key", required=True, help="path to the .pub file")
    dt.add_argument("--target", default=".")
    dt.add_argument("--operator", help="who is adding the signer (recorded on init)")
    dt.set_defaults(fn=cmd_decisions_trust)
    dv = dsub.add_parser("verify", help="check every stored decision's signature; exit 1 if "
                                        "any would be refused under the effective policy")
    dv.add_argument("--target", default=".")
    dv.add_argument("--policy", choices=["off", "warn", "enforce"],
                    help="audit against this level instead of the configured one")
    dv.add_argument("--json", action="store_true")
    dv.set_defaults(fn=cmd_decisions_verify)
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
    sp.add_argument("--signing-key", help=_SIGNING_KEY_HELP)
    sp.set_defaults(fn=cmd_suppress)
    return p



def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
