"""Dedicated arm: Anthropic's `claude-security` plugin (Claude Code), headless.

The plugin's scan job is gated by up to three AskUserQuestion prompts (job, shape,
cost). Per its own recipe — confirmed by the M0 S4 spike — every gate collapses
when the request names the job, the shape (whole repository or a scope), the
effort, *and* acknowledges the cost in so many words. We send exactly that, with
``--max-budget-usd`` as the hard fuse.

The plugin writes ``CLAUDE-SECURITY-<ts>/`` *into the scanned directory* (its
``.md``/``.jsonl``/``.sarif`` products + a revision stamp). The orchestrator
already runs arms against a scratch copy, so the report is moved out into the run's
``raw/claude-security/`` and the copy is discarded. We ingest the SARIF: it carries
the full JSONL record per result plus the 3-voter panel tally and the renderer's
``verification.status`` stamp, which we surface as coverage — a report that is
``unverified`` (or never rendered because the budget ran out) is never reported
as a clean scan.

D8 applies: the served model is read from ``modelUsage`` and a pin mismatch
drops the arm loudly (classifier_fallback).
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import shutil
from pathlib import Path

from .. import entitlements as _entitlements
from .. import proc
from ..normalize import registry
from ..normalize.base import ParseContext
from .base import ArmResult, DiffSpec
from .llm_cli import _model_matches

ARM_NAME = "claude-security"
PLUGIN_MARKETPLACE = "claude-plugins-official"
_PLUGIN_CACHE_GLOB = os.path.expanduser(
    f"~/.claude/plugins/cache/{PLUGIN_MARKETPLACE}/claude-security/*")
ACKNOWLEDGEMENT = ("I understand it may take a while and use a significant number of tokens; "
                   "proceed without asking.")
EFFORTS = ("low", "medium", "high", "max")
REPORT_GLOB = "CLAUDE-SECURITY-2*"
SARIF_NAME = "CLAUDE-SECURITY-RESULTS.sarif"


def build_prompt(*, effort: str, scope: list[str] | None,
                 diff: DiffSpec | None = None) -> str:
    if diff is not None:
        # scan-changes: committed diff/PR against a base (working_tree unsupported here)
        base = diff.base or "origin/HEAD"
        shape = (f"scan only the committed changes in {', '.join(scope)}" if scope
                 else "scan the committed changes")
        return (f"/claude-security scan-changes --base {base} --effort {effort}"
                + (f" --scope {','.join(scope)}" if scope else "")
                + f"\n\nRun the scan-changes job now: {shape} against base {base} at "
                + f"{effort} effort. {ACKNOWLEDGEMENT}")
    shape = (f"scan only these directories: {', '.join(scope)}" if scope
             else "scan the whole repository")
    return (f"/claude-security scan-codebase --effort {effort}"
            + (f" --scope {','.join(scope)}" if scope else "")
            + f"\n\nRun the scan-codebase job now: {shape} at {effort} effort. {ACKNOWLEDGEMENT}")


class ClaudeSecurityArm:
    kind = "agent_cli"
    family = "claude"
    name = ARM_NAME
    supports_diff = True                  # M-V1: scan-changes job (committed diffs)

    def __init__(self, *, model: str | None = None, effort: str = "low",
                 max_budget_usd: float = 10.0, scope: list[str] | None = None,
                 timeout: int = 3600, command: str = "claude",
                 diff: DiffSpec | None = None) -> None:
        if effort not in EFFORTS:
            raise ValueError(f"claude-security effort must be one of {EFFORTS}, got {effort!r}")
        self.model = model
        self.effort = effort
        self.max_budget_usd = float(max_budget_usd)
        self.scope = list(scope) if scope else None
        self.timeout = int(timeout)
        self.command = command
        self.diff = diff

    # ------------------------------------------------------------------ #
    def plugin_dirs(self) -> list[str]:
        return sorted(glob.glob(_PLUGIN_CACHE_GLOB))

    def available(self) -> tuple[bool, str]:
        p = shutil.which(self.command)
        if not p:
            return False, f"{self.command} not on PATH"
        dirs = self.plugin_dirs()
        if not dirs:
            return False, (f"claude-security plugin not installed "
                           f"(claude plugin install claude-security@{PLUGIN_MARKETPLACE})")
        # R12: `scan-changes` scans COMMITTED changes only. DiffSpec's docstring
        # already said this arm "is skipped in this mode", but nothing skipped
        # it — so asking for a working-tree scan silently got a committed-diff
        # scan instead, and uncommitted vulnerable code went unexamined while
        # the arm reported success. Refuse, and let the run degrade honestly.
        if getattr(self, "diff", None) is not None and self.diff.kind == "working_tree":
            return False, ("claude-security scan-changes covers committed changes only; "
                           "it cannot scan the working tree (use codex-security, or drop "
                           "--working-tree)")
        return True, f"local: {p} + plugin {Path(dirs[-1]).name}"

    def _env(self) -> dict:
        env = dict(os.environ)
        env["SECURITY_COUNCIL_NESTED"] = "1"
        env["LLM_COUNCIL_NESTED"] = "1"
        return env

    def _cmd(self, prompt: str) -> list[str]:
        cmd = [self.command, "-p", prompt, "--output-format", "json",
               "--dangerously-skip-permissions", "--no-session-persistence",
               "--strict-mcp-config", "--max-budget-usd", f"{self.max_budget_usd:g}"]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    # ------------------------------------------------------------------ #
    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = Path(out_dir) / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        prompt = build_prompt(effort=self.effort, scope=self.scope, diff=self.diff)
        cmd = self._cmd(prompt)
        before = set(glob.glob(str(target / REPORT_GLOB)))
        r = proc.run_command(cmd, timeout=self.timeout, cwd=str(target), env=self._env())

        outer = _parse_stdout(r.stdout)
        (raw_dir / "claude-result.json").write_text(json.dumps(outer or {"stdout": r.stdout[-4000:],
                                                                          "stderr": r.stderr[-4000:]},
                                                               indent=2))
        served = _served_model(outer) if outer else None
        cost = outer.get("total_cost_usd") if outer else None
        subtype = outer.get("subtype") if outer else None
        is_error = bool(outer.get("is_error")) if outer else False

        # move the plugin's report dir(s) out of the scanned tree into raw/
        report_dirs = sorted(set(glob.glob(str(target / REPORT_GLOB))) - before) or \
            sorted(glob.glob(str(target / REPORT_GLOB)))
        moved: list[Path] = []
        for d in report_dirs:
            dest = raw_dir / Path(d).name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(d, dest)
            moved.append(dest)
        report = moved[-1] if moved else None
        sarif_path = (report / SARIF_NAME) if report else None

        base_cov = {"cost_usd": cost, "claude_subtype": subtype, "effort": self.effort,
                    "report_dir": str(report) if report else None,
                    "scan_scope": self.diff.as_dict() if self.diff else {"kind": "full"}}

        if r.timed_out:
            return self._fail(cmd, r, error=f"timed out after {self.timeout}s", cov=base_cov)
        if self.model and served and not _model_matches(self.model, served):
            return self._fail(cmd, r, error=f"model_substituted: requested {self.model} served {served}",
                              classifier_fallback=True, cov=base_cov)
        if sarif_path is None or not sarif_path.is_file():
            why = subtype or ("is_error" if is_error else f"exit {r.exit_code}")
            salvaged = report is not None and (report / ".claude-security-run" / "findings.json").is_file()
            return self._fail(cmd, r, error=f"no report rendered ({why}; cost ${cost if cost is not None else '?'})"
                              + ("; raw unverified findings salvaged under raw/" if salvaged else ""),
                              cov=base_cov)

        sarif = json.load(open(sarif_path))
        _tier = _entitlements.classify_model(served or self.model)
        ctx = ParseContext(repo_root=target, source_id=self.name, source_kind="agent_cli",
                           family=self.family, run_id=run_id, collected_at=collected_at,
                           model_id=served or self.model or "claude-account-default",
                           prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
                           entitlement=_tier.name if _tier else None,
                           safeguard_posture=_tier.safeguard_posture if _tier else "default")
        findings, meta = registry.normalize_claude_security(sarif, ctx)
        ctx_tool = meta.get("plugin_version")
        for f in findings:
            for p in f.provenance:
                p.tool_version = ctx_tool
        verified = meta.get("verification_status") == "verified"
        cov = {**base_cov, "raw_results": meta.get("results"), "normalized": len(findings),
               "plugin_version": ctx_tool, "verification_status": meta.get("verification_status"),
               "verification_reason": meta.get("verification_reason"),
               "completion": "complete" if verified and not is_error else "partial",
               "skipped": dict(ctx.skipped)}
        if not findings and not verified:
            cov["coverage_unverified"] = True
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=findings,
                         tool_version=served or self.model, elapsed_seconds=r.elapsed_seconds,
                         command=_redact(cmd), raw_path=str(sarif_path), coverage=cov)

    def _fail(self, cmd, r, *, error: str, classifier_fallback: bool = False, cov: dict | None = None):
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                         exit_code=r.exit_code, error=error, findings=[],
                         elapsed_seconds=r.elapsed_seconds, command=_redact(cmd),
                         coverage={**(cov or {}), "classifier_fallback": classifier_fallback})


def _parse_stdout(stdout: str) -> dict | None:
    s = (stdout or "").strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        # stream-ish output: take the last JSON object line
        for line in reversed(s.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return None
    return obj if isinstance(obj, dict) else None


def _served_model(outer: dict) -> str | None:
    mu = outer.get("modelUsage") or {}
    if mu:
        return max(mu, key=lambda k: (mu[k] or {}).get("outputTokens", 0))
    return outer.get("model") or (outer.get("usage") or {}).get("model")


def _redact(cmd: list[str]) -> list[str]:
    return [("<prompt>" if len(a) > 200 else a) for a in cmd]
