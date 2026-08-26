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
    config = load_config(target)
    for k in ("fail_on_severity", "gate_baseline"):
        if arguments.get(k):
            config["policy"][k] = arguments[k]
    raw = arguments.get("arms")
    names = ([n.strip() for n in raw.split(",")] if isinstance(raw, str)
             else list(raw) if raw else config["arms"]["enabled"])
    unknown = [n for n in names if n not in known_arms()]
    if unknown:
        raise ValueError(f"unknown arms {unknown}; known: {known_arms()}")
    run = run_scan(target, _arms(names, config), config,
                   isolate=not arguments.get("inplace", False),
                   validate=bool(arguments.get("validate", False)),
                   validate_max_findings=arguments.get("validate_max"))
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
    fmt = arguments.get("format") or "json"
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
    if fmt == "emass":
        from .export import emass
        app, ver = arguments.get("app_name"), arguments.get("app_version")
        if not (app and ver):
            raise ValueError("format=emass requires app_name and app_version")
        scan_date = arguments.get("scan_date") or emass.scan_date_from_manifest(m)
        body, meta = emass.to_emass_static_code_scans(
            findings, application_name=app, version=ver, scan_date=int(scan_date))
        return {"body": body, "meta": meta}
    raise ValueError(f"unknown format {fmt!r} (json|md|emass)")


def _latest_run(target: Path) -> Path | None:
    runs = target / ".security-council" / "runs"
    cands = sorted(d for d in runs.iterdir()
                   if (d / "manifest.json").is_file()) if runs.is_dir() else []
    return cands[-1] if cands else None


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
           "validate": {"type": "boolean"},
           "validate_max": {"type": "integer"},
           "fail_on_severity": {"enum": ["critical", "high", "medium", "low", "info"]},
           "gate_baseline": {"enum": ["all", "new"]},
           "inplace": {"type": "boolean"}}),
     sc_scan),
    ("sc_doctor", "Check which arms are available.",
     _obj({"target": _target_prop()}), sc_doctor),
    ("sc_report", "Summarize or export a run directory (json | md | emass).",
     _obj({"run_dir": {"type": "string"},
           "format": {"enum": ["json", "md", "emass"]},
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
