"""MCP stdio server: the `sc_*` tools over the CLI core (D4: CLI core + MCP wrapper).

Follows llm-council's `_serve` pattern (mcp 2.x constructor-callback Server;
handler exceptions converted to `isError` tool results so callers see real
messages). Two hard guards:

- **Root scoping** (`SECURITY_COUNCIL_MCP_ROOT`): every `target`/`run_dir`
  argument must be an absolute path that resolves inside the configured root —
  relative paths and escapes are refused with an actionable error. Omitting the
  path uses the root itself.
- **Nesting guard** (presence-based): the arms set `SECURITY_COUNCIL_NESTED=1`
  in every subprocess they spawn. If that variable is present, this process is
  running *inside* a security-council arm, and `sc_scan` refuses — an agentic
  arm must not be able to recursively launch scans.

Handlers are transport-independent plain functions (dict in -> JSON-able dict
out) so they are testable without the `mcp` SDK; the SDK is imported only in
`serve()` and is an optional extra (`pip install security-council[mcp]`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from . import __version__
from .config import load_config

SERVER_NAME = "security-council"
NESTED_ENV = "SECURITY_COUNCIL_NESTED"
ROOT_ENV = "SECURITY_COUNCIL_MCP_ROOT"


def _root() -> Path:
    return Path(os.environ.get(ROOT_ENV) or ".").resolve()


def _refuse_if_nested(action: str) -> None:
    """Decision-store writes are human actions — refuse when nested inside an arm
    (R6/MV4-12; symmetric with the CLI guard). Belt-and-braces: the real fence
    is M1 making the target's decision store unreachable to a fenced agent."""
    if os.environ.get(NESTED_ENV):
        raise ValueError(f"{action} is a human decision and is refused inside a "
                         f"security-council arm ({NESTED_ENV} is set).")


def _resolve_dir(arguments: dict, key: str, *, default_to_root: bool = True) -> Path:
    root = _root()
    requested = arguments.get(key)
    if requested is None and not default_to_root:
        raise ValueError(f"{key} is required")
    if requested and not Path(str(requested)).is_absolute():
        raise ValueError(
            f"PathMustBeAbsolute: {key}={requested!r}; configured_root={root}. "
            "This MCP server is project-scoped; pass an absolute path.")
    p = Path(requested or root).resolve()
    if not p.is_dir():
        raise ValueError(f"{key} is not a directory: {p}")
    try:
        p.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"ProjectRootMismatch: {key}={p}; configured_root={root}. "
            "Reconnect this MCP server from the target checkout or use that "
            "checkout's .mcp.json.") from exc
    return p


def _resolve_file(arguments: dict, key: str) -> Path | None:
    """Resolve an optional operator-owned file inside the MCP root."""
    requested = arguments.get(key)
    if requested is None:
        return None
    root = _root()
    p = Path(str(requested))
    if not p.is_absolute():
        raise ValueError(
            f"PathMustBeAbsolute: {key}={requested!r}; configured_root={root}.")
    p = p.resolve()
    try:
        p.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"ProjectRootMismatch: {key}={p}; configured_root={root}.") from exc
    if not p.is_file():
        raise ValueError(f"{key} is not a file: {p}")
    return p


def _resolve_output_root(arguments: dict) -> Path | None:
    """Resolve an optional reports root; the orchestrator appends the run id."""
    requested = arguments.get("reports_root")
    if requested is None:
        return None
    root = _root()
    p = Path(str(requested))
    if not p.is_absolute():
        raise ValueError(
            f"PathMustBeAbsolute: reports_root={requested!r}; configured_root={root}.")
    p = p.resolve()
    try:
        p.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"ProjectRootMismatch: reports_root={p}; configured_root={root}.") from exc
    return p


def _resolve_dir_list(arguments: dict, key: str) -> list[Path]:
    """Resolve a comma-separated list of operator-owned directories, each
    absolute and inside the MCP root (same containment as `target`)."""
    raw = arguments.get(key)
    if raw is None:
        return []
    values = [v.strip() for v in str(raw).split(",") if v.strip()]
    return [_resolve_dir({key: v}, key, default_to_root=False) for v in values]


def _validator_runner(arguments: dict):
    """One shared reading of the validator peer controls (sc_scan and
    sc_consolidate must not each re-implement the exclusion rules)."""
    import functools
    validator_current = arguments.get("validator_current")
    validator_participants_raw = arguments.get("validator_participants")
    validator_config = _resolve_file(arguments, "validator_config_path")
    if not (validator_current or validator_participants_raw or validator_config):
        return None
    if not validator_current:
        raise ValueError("validator_current is required when customizing validator peers")
    participants = tuple(
        item.strip() for item in str(validator_participants_raw or "").split(",")
        if item.strip()
    )
    if not participants:
        raise ValueError("validator_participants must name at least one external peer")
    allowed = {"claude", "codex", "antigravity"}
    unknown_peers = sorted(set(participants) - allowed)
    if unknown_peers:
        raise ValueError(f"unknown validator participants {unknown_peers}")
    if validator_current in participants:
        raise ValueError("validator_participants must exclude validator_current")
    from .validate.council_client import run_council
    return functools.partial(
        run_council,
        config_file=validator_config,
        current=validator_current,
        participants=participants,
    )


# --------------------------------------------------------------------------- #
# tool handlers (transport-independent)
# --------------------------------------------------------------------------- #


def _arms(names: list[str], config: dict):
    """Separate seam so tests can inject fakes while sc_scan uses the real flow."""
    from .arms.registry import build_arm
    options = (config.get("arms") or {}).get("options") or {}
    return [build_arm(n, options=options.get(n)) for n in names]


def sc_scan(arguments: dict) -> dict:
    if os.environ.get(NESTED_ENV):
        raise ValueError(
            "NestedScanRefused: this process is running inside a security-council "
            f"arm ({NESTED_ENV} is set); recursive scans are not allowed.")
    from .arms.registry import known_arms
    from .orchestrator import run_scan
    target = _resolve_dir(arguments, "target")
    config_path = _resolve_file(arguments, "config_path")
    ignore_repo = bool(arguments.get("ignore_repo_config", False))
    if config_path is not None and ignore_repo:
        raise ValueError("config_path and ignore_repo_config are mutually exclusive")
    config = load_config(target, explicit=config_path, ignore_repo=ignore_repo)
    profile = arguments.get("profile")
    if profile:
        from .config import PROFILES, deep_merge
        config = deep_merge(config, PROFILES[profile])
    for k in ("fail_on_severity", "gate_baseline"):
        if arguments.get(k):
            config["policy"][k] = arguments[k]
    if arguments.get("min_arms") is not None:
        config["policy"]["min_arms_ok"] = int(arguments["min_arms"])
    if arguments.get("require_signatures"):
        if not isinstance(config.get("decisions"), dict):
            config["decisions"] = {}
        config["decisions"]["require_signatures"] = arguments["require_signatures"]
    raw = arguments.get("arms")
    names = ([n.strip() for n in raw.split(",")] if isinstance(raw, str)
             else list(raw) if raw else config["arms"]["enabled"])
    unknown = [n for n in names if n not in known_arms()]
    if unknown:
        raise ValueError(f"unknown arms {unknown}; known: {known_arms()}")
    if arguments.get("deep"):
        opts = config["arms"].setdefault("options", {})
        enabled = set(names)
        for arm_name, key, value in (("codex-security", "mode", "deep"),
                                     ("claude-security", "effort", "high"),
                                     ("claude", "effort", "high"),
                                     ("agy", "effort", "high")):
            if arm_name in enabled:
                opts.setdefault(arm_name, {})[key] = value
    reports_root = _resolve_output_root(arguments)
    analysis_arms = []
    if arguments.get("sbom"):
        from .arms.sbom import SbomArm
        analysis_arms.append(SbomArm())
    validate = (bool(arguments["validate"]) if "validate" in arguments
                else bool((config.get("defaults") or {}).get("validate", False)))
    validator_runner = _validator_runner(arguments)
    run = run_scan(target, _arms(names, config), config,
                   isolate=not arguments.get("inplace", False),
                   validate=validate,
                   validate_max_findings=arguments.get("validate_max"),
                   validate_budget_usd=arguments.get("validate_budget", 0.5),
                   validator_runner=validator_runner,
                   validator_timeout=arguments.get("validator_timeout", 600),
                   analysis_arms=analysis_arms, reports_root=reports_root)
    return {"run_id": run.run_id, "out_dir": str(run.out_dir), "exit_code": run.exit_code,
            "counts": run.manifest["counts"], "degradations": run.degradations,
            "disposition_actions": run.manifest.get("disposition_actions"),
            "baseline_delta": run.manifest.get("baseline_delta"),
            "reports": [r["path"] for r in run.manifest["reports"]]}


def sc_doctor(arguments: dict) -> dict:
    from .arms.registry import build_arm, known_arms
    _resolve_dir(arguments, "target")     # root-scope check only
    rows = []
    for name in known_arms():
        try:
            ok, detail = build_arm(name).available()
        except Exception as exc:  # noqa: BLE001 - doctor reports, never raises
            ok, detail = False, f"probe failed: {exc}"
        rows.append({"arm": name, "ready": ok, "detail": detail})
    return {"arms": rows, "root": str(_root()), "version": __version__}


def _manifest(run_dir: Path) -> dict:
    mf = run_dir / "manifest.json"
    if not mf.is_file():
        raise ValueError(f"no manifest.json in {run_dir}")
    return json.loads(mf.read_text())


def sc_report(arguments: dict) -> dict:
    run_dir = _resolve_dir(arguments, "run_dir", default_to_root=False)
    m = _manifest(run_dir)
    if arguments.get("system_name"):     # same identity field as `report --system-name`
        m = dict(m, report_identity={"system_name": str(arguments["system_name"])})
    fmt = arguments.get("format") or "json"
    if arguments.get("bundle"):
        from types import SimpleNamespace

        from .cli import _report_bundle
        bundle = arguments["bundle"]
        if bundle not in ("triage", "gov", "all"):
            raise ValueError(f"unknown bundle {bundle!r} (triage|gov|all)")
        # R17: run dirs live inside the scanned, committable repo — a planted
        # `exports` symlink (or a symlinked file inside it) must not redirect
        # bundle writes outside the root (same class serve._confine closes).
        exports = run_dir / "exports"
        if exports.is_symlink():
            raise ValueError(f"exports is a symlink and is refused: {exports}")
        exports.mkdir(parents=True, exist_ok=True)
        exports = exports.resolve()
        try:
            exports.relative_to(_root())
        except ValueError as exc:
            raise ValueError(f"ProjectRootMismatch: exports={exports}; "
                             f"configured_root={_root()}.") from exc
        planted = sorted(q.name for q in exports.iterdir() if q.is_symlink())
        if planted:
            raise ValueError(f"exports contains symlink(s) {planted}; refused")
        shim = SimpleNamespace(run_dir=str(run_dir), bundle=bundle, out_dir=str(exports),
                               app_name=arguments.get("app_name"),
                               app_version=arguments.get("app_version"),
                               scan_date=arguments.get("scan_date"),
                               classification=arguments.get("classification") or "UNCLASSIFIED")
        _report_bundle(shim, m)
        return {"out_dir": str(exports),
                "written": sorted(q.name for q in exports.iterdir() if q.is_file())}
    if fmt == "json":
        return {"run_id": m["run_id"], "counts": m["counts"], "exit_code": m.get("exit_code"),
                "disposition_actions": m.get("disposition_actions"),
                "baseline_delta": m.get("baseline_delta"),
                "reports": [r["path"] for r in m["reports"]]}
    from .jsonio import finding_from_dict
    fj = run_dir / "findings.json"
    findings = [finding_from_dict(d) for d in json.loads(fj.read_text())] if fj.is_file() else []
    if fmt == "md":
        from .export import markdown
        return {"markdown": markdown.to_markdown(findings, m)}
    if fmt == "csv":
        from .export import csv_export
        return {"csv": csv_export.to_csv(findings)}
    if fmt == "html":
        from .export import html_export
        md = run_dir / "summary.md"
        page = html_export.to_html(findings, m, run_dir=run_dir,
                                   markdown_text=md.read_text() if md.is_file() else None)
        page_path = run_dir / "summary.html"
        if page_path.is_symlink():   # a committed run dir must not redirect the write
            raise ValueError(f"summary.html is a symlink and is refused: {page_path}")
        page_path.write_text(page)   # the named path really exists
        return {"html": page, "path": str(page_path)}
    if fmt == "emass":
        from .export import emass
        app, ver = arguments.get("app_name"), arguments.get("app_version")
        if not (app and ver):
            raise ValueError("format=emass requires app_name and app_version")
        scan_date = arguments.get("scan_date") or emass.scan_date_from_manifest(m)
        body, meta = emass.to_emass_static_code_scans(
            findings, application_name=app, version=ver, scan_date=int(scan_date))
        return {"body": body, "meta": meta}
    raise ValueError(f"unknown format {fmt!r} (json|md|csv|html|emass)")


def _latest_run(target: Path) -> Path | None:
    from .cli import latest_run
    return latest_run(target, need_findings=False)


def sc_last_run(arguments: dict) -> dict:
    target = _resolve_dir(arguments, "target")
    run_dir = _latest_run(target)
    if run_dir is None:
        return {"found": False}
    return {"found": True, "run_dir": str(run_dir),
            **sc_report({"run_dir": str(run_dir), "format": "json"})}


def _cli_ns(arguments: dict, target: Path, **extra) -> SimpleNamespace:
    return SimpleNamespace(target=str(target), run=arguments.get("run"),
                           finding_id=arguments.get("finding_id"), **extra)


def sc_baseline(arguments: dict) -> dict:
    from . import cli
    target = _resolve_dir(arguments, "target")
    from .decisions import DecisionStore
    store = DecisionStore(target / ".security-council")
    action = arguments.get("action") or "show"
    if action == "show":
        bl = store.load_baseline()
        return {"set": bl is not None,
                **({"run_id": bl.get("run_id"), "set_at": bl.get("set_at"),
                    "findings": len(bl.get("findings") or [])} if bl else {})}
    if action != "set":
        raise ValueError(f"unknown action {action!r} (set|show)")
    _refuse_if_nested("baseline set")
    ns = _cli_ns(arguments, target)
    run_dir = cli._run_dir(ns)
    if run_dir is None:
        raise ValueError("no run with findings.json found (pass run)")
    rows = json.loads((run_dir / "findings.json").read_text())
    signer = _mcp_signer(arguments, target, store, action="baseline set")
    if signer and not arguments.get("operator"):
        raise ValueError("operator is required to sign the baseline (it is the principal)")
    bl = store.set_baseline(rows, run_id=run_dir.name, now_iso=cli._now_iso(),
                            operator=arguments.get("operator"), signer=signer)
    return {"set": True, "run_id": bl["run_id"], "findings": len(bl["findings"]),
            "signed": signer is not None}


def _mcp_signer(arguments: dict, target: Path, store, *, action: str):
    """Same resolution as the CLI (argument > env > config); under `enforce` an
    unsigned write is refused with the steps to fix it. Signing over MCP needs
    a key without a passphrase prompt (there is no terminal): a .pub whose
    private half is in ssh-agent is the recommended shape."""
    from . import cli, signing
    from .decisions import Signer
    config = load_config(target)
    policy = signing.resolve_policy(config, store_initialised=store.store_meta() is not None,
                                    store_has_decisions=store.has_decisions(),
                                    now_iso=cli._now_iso())
    key = (arguments.get("signing_key") or os.environ.get("SECURITY_COUNCIL_SIGNING_KEY")
           or (config.get("decisions") or {}).get("signing_key"))
    if key:
        return Signer(key_path=str(key))
    if policy["effective"] == "enforce":
        raise ValueError(f"{action} must be signed here (require_signatures resolves to "
                         f"enforce: {policy['reason']}). Pass signing_key (an SSH key trusted "
                         "via `security-council decisions trust`), or set "
                         "decisions.require_signatures: warn.")
    return None


def sc_decisions_verify(arguments: dict) -> dict:
    from . import cli, signing
    from .decisions import DecisionStore
    target = _resolve_dir(arguments, "target")
    store = DecisionStore(target / ".security-council")
    config = load_config(target)
    policy = signing.resolve_policy(config, store_initialised=store.store_meta() is not None,
                                    store_has_decisions=store.has_decisions(),
                                    now_iso=cli._now_iso())
    audit = store.verify_store(signature_policy=arguments.get("policy") or policy["effective"])
    audit["policy_resolution"] = policy
    return audit


def _resolve_finding(arguments: dict, target: Path) -> tuple[Any, dict]:
    from . import cli
    ns = _cli_ns(arguments, target)
    run_dir = cli._run_dir(ns)
    if run_dir is None:
        raise ValueError("no run with findings.json found (pass run)")
    if not arguments.get("finding_id"):
        raise ValueError("finding_id is required")
    row = cli._find_row(run_dir, arguments["finding_id"])
    if row is None:
        raise ValueError(f"finding {arguments['finding_id']!r} not found (or ambiguous) in {run_dir}")
    return run_dir, row


def sc_suppress(arguments: dict) -> dict:
    from . import cli
    from .decisions import DecisionStore
    _refuse_if_nested("suppress")
    target = _resolve_dir(arguments, "target")
    if not arguments.get("operator") or not arguments.get("justification"):
        raise ValueError("operator and justification are required")
    _, row = _resolve_finding(arguments, target)
    fp = row.get("fingerprints") or {}
    lifecycle = "accepted_risk" if arguments.get("accept_risk") else "suppressed"
    store = DecisionStore(target / ".security-council")
    signer = _mcp_signer(arguments, target, store, action="suppress")
    store.record_human_decision(
        root_cause=fp.get("root_cause", ""), context_hash=fp.get("context_hash", ""),
        finding_id=row["id"], title=row.get("title", ""), operator=arguments["operator"],
        justification=arguments["justification"], now_iso=cli._now_iso(),
        lifecycle=lifecycle, expires_days=int(arguments.get("expires_days") or 90),
        vex_justification=arguments.get("vex_justification"), signer=signer)
    return {"recorded": lifecycle, "finding_id": row["id"],
            "root_cause": fp.get("root_cause"), "applies": "future scans",
            "signed": signer is not None}


def sc_outcome_mark(arguments: dict) -> dict:
    from . import cli
    from .decisions import DecisionStore
    _refuse_if_nested("outcome mark")
    target = _resolve_dir(arguments, "target")
    verdict = {"tp": "true_positive", "fp": "false_positive"}.get(
        arguments.get("verdict"), arguments.get("verdict"))
    if not arguments.get("operator"):
        raise ValueError("operator is required (outcome marks feed the score history term)")
    _, row = _resolve_finding(arguments, target)
    fp = row.get("fingerprints") or {}
    store = DecisionStore(target / ".security-council")
    signer = _mcp_signer(arguments, target, store, action="outcome mark")
    store.mark_outcome(
        root_cause=fp.get("root_cause", ""), finding_id=row["id"], verdict=verdict,
        operator=arguments["operator"], note=arguments.get("note") or "",
        now_iso=cli._now_iso(), title=row.get("title", ""),
        context_hash=fp.get("context_hash", ""), signer=signer)
    return {"marked": verdict, "finding_id": row["id"], "root_cause": fp.get("root_cause"),
            "signed": signer is not None}


_SERVER: dict[str, Any] = {}


def sc_consolidate(arguments: dict) -> dict:
    """Combine prior runs / sealed bundles into one gated report.

    Import-only BY CONSTRUCTION — only `kind == "import"` arms are built, so
    no paid producer can re-run. Sources are revision-bound to the current
    clean checkout (arms fail closed). Import paths come only from tool
    arguments, resolved absolute-and-inside-root exactly like `target`.
    """
    if os.environ.get(NESTED_ENV):
        raise ValueError(
            "NestedScanRefused: this process is running inside a security-council "
            "arm; a consolidation from here would recurse.")
    from .arms.import_bundle import (CodexSecurityBundleImportArm,
                                     SecurityCouncilRunImportArm)
    from .orchestrator import run_scan
    target = _resolve_dir(arguments, "target")
    run_dirs = _resolve_dir_list(arguments, "import_runs")
    bundle_dirs = _resolve_dir_list(arguments, "import_bundles")
    arms = ([SecurityCouncilRunImportArm(run_dir=d) for d in run_dirs]
            + [CodexSecurityBundleImportArm(bundle_dir=b) for b in bundle_dirs])
    if not arms:
        raise ValueError("name at least one source: import_runs and/or import_bundles")
    non_import = [getattr(a, "name", "?") for a in arms
                  if getattr(a, "kind", None) != "import"]
    if non_import:   # structural, by kind — never a name allowlist
        raise ValueError(f"consolidate accepts only import arms; got {non_import}")
    config_path = _resolve_file(arguments, "config_path")
    ignore_repo = bool(arguments.get("ignore_repo_config", False))
    if config_path is not None and ignore_repo:
        raise ValueError("config_path and ignore_repo_config are mutually exclusive")
    config = load_config(target, explicit=config_path, ignore_repo=ignore_repo)
    for k in ("fail_on_severity", "gate_baseline"):
        if arguments.get(k):
            config["policy"][k] = arguments[k]
    if arguments.get("require_signatures"):
        if not isinstance(config.get("decisions"), dict):
            config["decisions"] = {}
        config["decisions"]["require_signatures"] = arguments["require_signatures"]
    run = run_scan(target, arms, config,
                   reports_root=_resolve_output_root(arguments),
                   validate=bool(arguments.get("validate", False)),
                   validate_max_findings=arguments.get("validate_max"),
                   validate_budget_usd=arguments.get("validate_budget", 0.5),
                   validator_runner=_validator_runner(arguments),
                   validator_timeout=arguments.get("validator_timeout", 600))
    return {"run_id": run.run_id, "out_dir": str(run.out_dir), "exit_code": run.exit_code,
            "counts": run.manifest["counts"], "degradations": run.degradations,
            "validation": run.manifest.get("validation"),
            "reports": run.manifest.get("reports")}


def sc_serve(arguments: dict) -> dict:
    """start | stop | status of the read-only report viewer. The server lives
    as long as this MCP process (the assistant's session); loopback unless a
    bind is given, in which case a token is generated and returned."""
    from .serve import ReportServer, ServeRefused, needs_token
    action = arguments.get("action") or "status"
    cur = _SERVER.get("server")
    if action == "status":
        return ({"running": True, "url": cur.url, "bind": cur.bind, "port": cur.port,
                 "target": str(cur.target)} if cur and cur.running else {"running": False})
    if action == "stop":
        if cur:
            cur.stop()
            _SERVER.clear()
            return {"running": False, "stopped": True}
        return {"running": False}
    if action != "start":
        raise ValueError(f"unknown action {action!r} (start|stop|status)")
    if cur and cur.running:
        return {"running": True, "url": cur.url, "note": "already running; stop it first to change"}
    target = _resolve_dir(arguments, "target")
    bind = arguments.get("bind") or "127.0.0.1"
    token = arguments.get("token") or ("auto" if needs_token(bind) else None)
    port = int(arguments["port"]) if "port" in arguments else 8642
    try:
        srv = ReportServer(target, bind=bind, port=port,
                           token=token, include_dual_use=bool(arguments.get("include_dual_use")))
        url = srv.start()
    except ServeRefused as e:
        raise ValueError(str(e)) from e
    _SERVER["server"] = srv
    return {"running": True, "url": url, "bind": bind, "port": srv.port, "target": str(target),
            "exposure": "loopback only" if not needs_token(bind) else
            "LAN: anyone with the token can read every report",
            "lifetime": "this MCP session"}


def sc_config(arguments: dict) -> dict:
    target = _resolve_dir(arguments, "target")
    return {"target": str(target), "config": load_config(target)}


# --------------------------------------------------------------------------- #
# tool registry + schemas
# --------------------------------------------------------------------------- #


def _target_prop() -> dict:
    return {"type": "string",
            "description": "Absolute path inside SECURITY_COUNCIL_MCP_ROOT "
                           "(default: the root itself)."}


def _obj(props: dict, required: list[str] | None = None) -> dict:
    out = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        out["required"] = required
    return out


_SIGNING_KEY_PROP = {"type": "string",
                     "description": "SSH key to sign with (ssh-keygen -Y): a .pub whose private "
                                    "half is in ssh-agent, or an unencrypted private key. "
                                    "Defaults to $SECURITY_COUNCIL_SIGNING_KEY, then "
                                    "decisions.signing_key. Required under require_signatures: "
                                    "enforce."}

TOOLS: list[tuple[str, str, dict, Any]] = [
    ("sc_scan",
     "Scan a repository with the configured arms; returns run summary + exit code. "
     "Refuses when running nested inside a security-council arm.",
     _obj({"target": _target_prop(),
           "arms": {"type": "string", "description": "comma-separated arm names"},
           "profile": {"enum": ["quick", "ci", "deep", "gov"]},
           "config_path": {"type": "string", "description":
                           "Absolute operator-owned config file inside the MCP root."},
           "ignore_repo_config": {"type": "boolean"},
           "reports_root": {"type": "string", "description":
                            "Absolute reports root inside the MCP root; run id is appended."},
           "deep": {"type": "boolean", "description":
                    "Use high effort for enabled agentic arms."},
           "validate": {"type": "boolean"},
           "validate_max": {"type": "integer", "minimum": 1},
           "validate_budget": {"type": "number", "exclusiveMinimum": 0},
           "validator_current": {"enum": ["claude", "codex", "antigravity"]},
           "validator_participants": {"type": "string", "description":
                                      "Comma-separated external peers; must exclude current host."},
           "validator_config_path": {"type": "string", "description":
                                     "Absolute operator-owned llm-council config inside MCP root."},
           "validator_timeout": {"type": "integer", "minimum": 1},
           "min_arms": {"type": "integer", "minimum": 1},
           "sbom": {"type": "boolean"},
           "require_signatures": {"enum": ["off", "warn", "enforce", "auto"]},
           "fail_on_severity": {"enum": ["critical", "high", "medium", "low", "info"]},
           "gate_baseline": {"enum": ["all", "new"]},
           "inplace": {"type": "boolean"}}),
     sc_scan),
    ("sc_consolidate",
     "Combine prior security-council runs and/or sealed Codex Security bundles into "
     "one gated report WITHOUT re-running their producers. Sources are revision-bound "
     "to the current clean checkout; only import arms can be built through this tool.",
     _obj({"target": _target_prop(),
           "import_runs": {"type": "string", "description":
                           "Comma-separated absolute prior run directories inside the MCP root."},
           "import_bundles": {"type": "string", "description":
                              "Comma-separated absolute sealed Codex Security bundle "
                              "directories inside the MCP root."},
           "config_path": {"type": "string", "description":
                           "Absolute operator-owned config file inside the MCP root."},
           "ignore_repo_config": {"type": "boolean"},
           "reports_root": {"type": "string", "description":
                            "Absolute reports root inside the MCP root; run id is appended."},
           "validate": {"type": "boolean", "description":
                        "Convene the external validator panel over the consolidated findings."},
           "validate_max": {"type": "integer", "minimum": 1},
           "validate_budget": {"type": "number", "exclusiveMinimum": 0},
           "validator_current": {"enum": ["claude", "codex", "antigravity"]},
           "validator_participants": {"type": "string", "description":
                                      "Comma-separated external peers; must exclude current host."},
           "validator_config_path": {"type": "string", "description":
                                     "Absolute operator-owned llm-council config inside MCP root."},
           "validator_timeout": {"type": "integer", "minimum": 1},
           "require_signatures": {"enum": ["off", "warn", "enforce", "auto"]},
           "fail_on_severity": {"enum": ["critical", "high", "medium", "low", "info"]},
           "gate_baseline": {"enum": ["all", "new"]}}),
     sc_consolidate),
    ("sc_doctor", "Check which arms are available.",
     _obj({"target": _target_prop()}), sc_doctor),
    ("sc_report", "Summarize or export a run directory (json | md | csv | html | emass), "
     "or write a full audience bundle into <run_dir>/exports.",
     _obj({"run_dir": {"type": "string"},
           "format": {"enum": ["json", "md", "csv", "html", "emass"]},
           "system_name": {"type": "string", "description":
                           "Display name for the assessed system (same field as "
                           "`report --system-name`)."},
           "bundle": {"enum": ["triage", "gov", "all"], "description":
                      "Write this audience's report set into <run_dir>/exports "
                      "and return the file list."},
           "classification": {"type": "string"},
           "app_name": {"type": "string"}, "app_version": {"type": "string"},
           "scan_date": {"type": "integer"}}, ["run_dir"]),
     sc_report),
    ("sc_last_run", "Summary of the most recent run for a target.",
     _obj({"target": _target_prop()}), sc_last_run),
    ("sc_baseline", "Show or set the operator-gated baseline for a target.",
     _obj({"target": _target_prop(), "action": {"enum": ["set", "show"]},
           "run": {"type": "string"}, "operator": {"type": "string"},
           "signing_key": _SIGNING_KEY_PROP}),
     sc_baseline),
    ("sc_suppress",
     "Record a HUMAN suppression/accepted-risk decision for a finding's root cause "
     "(expiring, applied on future scans).",
     _obj({"target": _target_prop(), "finding_id": {"type": "string"},
           "operator": {"type": "string"}, "justification": {"type": "string"},
           "accept_risk": {"type": "boolean"}, "expires_days": {"type": "integer"},
           "vex_justification": {"type": "string"}, "run": {"type": "string"},
           "signing_key": _SIGNING_KEY_PROP},
          ["finding_id", "operator", "justification"]),
     sc_suppress),
    ("sc_outcome_mark",
     "Record operator ground truth (true_positive|false_positive) for a finding; "
     "feeds the score history term.",
     _obj({"target": _target_prop(), "finding_id": {"type": "string"},
           "verdict": {"enum": ["true_positive", "false_positive", "tp", "fp"]},
           "operator": {"type": "string"}, "note": {"type": "string"},
           "run": {"type": "string"}, "signing_key": _SIGNING_KEY_PROP},
          ["finding_id", "verdict", "operator"]),
     sc_outcome_mark),
    ("sc_decisions_verify",
     "Audit every stored decision's ssh-keygen signature against allowed_signers and say "
     "which the effective require_signatures policy would refuse.",
     _obj({"target": _target_prop(), "policy": {"enum": ["off", "warn", "enforce"]}}),
     sc_decisions_verify),
    ("sc_serve",
     "Start, stop or query the read-only web viewer for a target's reports (loopback by "
     "default; a non-loopback bind gets a generated token). Lives for this session.",
     _obj({"target": _target_prop(), "action": {"enum": ["start", "stop", "status"]},
           "bind": {"type": "string"}, "port": {"type": "integer"},
           "token": {"type": "string"}, "include_dual_use": {"type": "boolean"}}),
     sc_serve),
    ("sc_config", "Effective merged configuration for a target.",
     _obj({"target": _target_prop()}), sc_config),
]

HANDLERS = {name: fn for name, _, _, fn in TOOLS}


def call_tool(name: str, arguments: dict | None) -> dict:
    fn = HANDLERS.get(name)
    if fn is None:
        raise ValueError(f"Unknown tool: {name}")
    return fn(dict(arguments or {}))


# --------------------------------------------------------------------------- #
# mcp 2.x transport (optional extra)
# --------------------------------------------------------------------------- #


async def _serve() -> None:
    try:
        from mcp import types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except Exception as exc:  # pragma: no cover - environment-dependent
        raise SystemExit(
            "The 'mcp' Python package (>=2,<3) is required for MCP server mode: "
            "pip install 'security-council[mcp]'") from exc

    async def _on_list_tools(ctx: Any, params: Any) -> Any:
        return types.ListToolsResult(tools=[
            types.Tool(name=name, description=desc, input_schema=schema)
            for name, desc, schema, _ in TOOLS])

    async def _on_call_tool(ctx: Any, params: Any) -> Any:
        try:
            result = call_tool(params.name, dict(params.arguments or {}))
        except Exception as exc:  # noqa: BLE001 - surface the real message to the client
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))], is_error=True)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, indent=2))])

    app = Server(SERVER_NAME, version=__version__,
                 on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    import argparse
    import asyncio
    parser = argparse.ArgumentParser(description="Run the security-council MCP server")
    parser.parse_args(argv or [])
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
