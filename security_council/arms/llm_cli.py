"""Generic LLM-CLI arm: the house-prompt 'floor' producer.

Runs claude / codex / agy read-only with the shared house prompt + the agent
finding envelope schema, then normalizes via the envelope adapter. Encodes the
M0 spike findings: codex needs --ignore-user-config; agy soft-denies with exit 0
(so status must be checked, not the exit code); a served model that differs from
a pin is a classifier substitution and fails the arm loudly (decision D8); an arm
that returns zero findings without a 'complete' self-report is coverage-unverified,
never 'clean'.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .. import proc
from ..normalize import registry
from ..normalize.base import ParseContext
from .base import ArmResult

_PKG = Path(__file__).resolve().parent.parent
_PROMPT_PATH = _PKG / "prompts" / "house-sast.md"
_SCHEMA_PATH = _PKG / "schemas" / "agent_finding_envelope.v1.json"


@dataclass
class _Parsed:
    envelope: Optional[dict]
    served_model: Optional[str]
    status_ok: bool
    note: str = ""


@dataclass(frozen=True)
class LlmCliSpec:
    name: str
    family: str
    command: str
    stdin_prompt: bool
    build_cmd: Callable[["LlmCliArm", str, Path, Path], list[str]]
    parse: Callable[["LlmCliArm", proc.ProcResult, Path], _Parsed]
    timeout: int = 1200


# --------------------------------------------------------------------------- #
# per-CLI command builders + parsers
# --------------------------------------------------------------------------- #


def _claude_cmd(arm, prompt, cwd, out):
    # claude wants the schema INLINE as JSON (codex/agy take a file path)
    cmd = ["claude", "-p", prompt, "--output-format", "json",
           "--json-schema", _SCHEMA_PATH.read_text(),
           "--permission-mode", "plan", "--tools", "Read,Grep,Glob,LS",
           "--strict-mcp-config", "--no-session-persistence"]
    if arm.model:
        cmd += ["--model", arm.model]
    return cmd


def _claude_parse(arm, r, out):
    if not r.stdout.strip():
        return _Parsed(None, None, False, (r.stderr or "no output")[:300])
    try:
        outer = json.loads(r.stdout)
    except json.JSONDecodeError:
        return _Parsed(None, None, False, "non-json stdout")
    # served model(s) are the keys of modelUsage; pick the one that produced the
    # most output (the primary). This is what D8 checks against a pin.
    mu = outer.get("modelUsage") or {}
    served = (max(mu, key=lambda k: mu[k].get("outputTokens", 0)) if mu
              else outer.get("model") or (outer.get("usage") or {}).get("model"))
    cand = outer.get("result", outer)
    env = _coerce_envelope(cand)
    return _Parsed(env, served, not outer.get("is_error", False))


def _codex_cmd(arm, prompt, cwd, out):
    cmd = ["codex", "exec", "--ignore-user-config", "-s", "read-only", "--skip-git-repo-check",
           "-C", str(cwd), "-c", "mcp_servers={}", "--output-schema", str(_SCHEMA_PATH),
           "--json", "-o", str(out / "codex-last.txt")]
    if arm.model:
        cmd += ["-m", arm.model]
    cmd += ["-"]
    return cmd


def _codex_parse(arm, r, out):
    last = out / "codex-last.txt"
    if not last.is_file():
        return _Parsed(None, None, r.ok, (r.stderr or "no last-message file")[:300])
    env = _coerce_envelope(last.read_text(errors="replace"))
    return _Parsed(env, arm.model, r.ok)


def _agy_cmd(arm, prompt, cwd, out):
    cmd = ["agy", "-p", prompt, "--output-format", "json", "--json-schema", str(_SCHEMA_PATH),
           "--mode", "plan", "--sandbox", "--print-timeout", "18m", "--add-dir", str(cwd)]
    if arm.model:
        cmd += ["--model", arm.model]
    return cmd


def _agy_parse(arm, r, out):
    if not r.stdout.strip():
        return _Parsed(None, None, False, (r.stderr or "no output")[:300])
    try:
        outer = json.loads(r.stdout)
    except json.JSONDecodeError:
        return _Parsed(None, None, False, "non-json stdout")
    status = outer.get("status")
    served = (outer.get("usage") or {}).get("model") or arm.model
    # soft-deny: agy exits 0 with a non-SUCCESS status — status is authoritative
    return _Parsed(outer.get("structured_output"), served, status == "SUCCESS",
                   "" if status == "SUCCESS" else f"status={status}")


def _coerce_envelope(cand) -> Optional[dict]:
    if isinstance(cand, dict) and "findings" in cand:
        return cand
    if isinstance(cand, str):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            return None
        return obj if isinstance(obj, dict) and "findings" in obj else None
    return None


LLM_CLI_SPECS: dict[str, LlmCliSpec] = {
    "claude": LlmCliSpec("claude", "claude", "claude", False, _claude_cmd, _claude_parse, timeout=900),
    "codex": LlmCliSpec("codex", "codex", "codex", True, _codex_cmd, _codex_parse, timeout=1200),
    "agy": LlmCliSpec("agy", "google", "agy", False, _agy_cmd, _agy_parse, timeout=1200),
}


class LlmCliArm:
    kind = "agent_cli"

    def __init__(self, name: str, *, model: str | None = None) -> None:
        if name not in LLM_CLI_SPECS:
            raise ValueError(f"unknown llm-cli arm: {name}")
        self.name = name
        self.spec = LLM_CLI_SPECS[name]
        self.family = self.spec.family
        self.model = model

    def available(self) -> tuple[bool, str]:
        p = shutil.which(self.spec.command)
        return (True, f"local: {p}") if p else (False, f"{self.spec.command} not on PATH")

    def _env(self) -> dict:
        env = dict(os.environ)
        env["SECURITY_COUNCIL_NESTED"] = "1"
        env["LLM_COUNCIL_NESTED"] = "1"   # an arm's own council/tools must not recurse
        return env

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = out_dir / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        prompt = _PROMPT_PATH.read_text()
        cmd = self.spec.build_cmd(self, prompt, target, raw_dir)
        if self.spec.stdin_prompt:
            r = _run_with_stdin(cmd, prompt, timeout=self.spec.timeout, cwd=str(target), env=self._env())
        else:
            r = proc.run_command(cmd, timeout=self.spec.timeout, cwd=str(target), env=self._env())

        parsed = self.spec.parse(self, r, raw_dir)
        (raw_dir / "envelope.json").write_text(json.dumps(parsed.envelope or {}, indent=2))

        # guard 1: hard failure (timeout / soft-deny / no output)
        if not parsed.status_ok or r.timed_out:
            return self._fail(cmd, r, error=f"arm not ok: {parsed.note or r.stderr[:200]}")
        # guard 2: model substitution (fail loudly per D8)
        if self.model and parsed.served_model and not _model_matches(self.model, parsed.served_model):
            return self._fail(cmd, r, error=f"model_substituted: requested {self.model} "
                              f"served {parsed.served_model}", classifier_fallback=True)
        # guard 3: no structured output at all
        if parsed.envelope is None:
            return self._fail(cmd, r, error="no structured output (coverage_unverified)")

        ctx = ParseContext(repo_root=target, source_id=self.name, source_kind="agent_cli",
                           family=self.family, run_id=run_id, collected_at=collected_at,
                           model_id=parsed.served_model or self.model or f"{self.name}-account-default",
                           prompt_sha256=__import__("hashlib").sha256(prompt.encode()).hexdigest(),
                           cli_version=None)
        findings, meta = registry.normalize_envelope(parsed.envelope, ctx)
        completion = (meta or {}).get("completion")
        raw_n = len(parsed.envelope.get("findings") or []) if isinstance(parsed.envelope, dict) else None
        cov = {"raw_results": raw_n, "normalized": len(findings), "completion": completion,
               "declined_categories": (meta or {}).get("declined_categories", [])}
        if not findings and completion != "complete":
            cov["coverage_unverified"] = True    # zero findings but not a clean complete scan
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=findings,
                         tool_version=parsed.served_model, elapsed_seconds=r.elapsed_seconds,
                         command=_redact(cmd), raw_path=str(raw_dir / "envelope.json"), coverage=cov)

    def _fail(self, cmd, r, *, error: str, classifier_fallback: bool = False) -> ArmResult:
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                         exit_code=r.exit_code, error=error, findings=[],
                         elapsed_seconds=r.elapsed_seconds, command=_redact(cmd),
                         coverage={"classifier_fallback": classifier_fallback})


def _redact(cmd: list[str]) -> list[str]:
    # the prompt can be long; don't dump it into the manifest command
    return [("<prompt>" if len(a) > 400 else a) for a in cmd]


def _model_matches(requested: str, served: str) -> bool:
    r, s = requested.lower(), served.lower()
    return r in s or s in r


def _run_with_stdin(cmd, text, *, timeout, cwd, env):
    import subprocess
    import time
    start = time.monotonic()
    try:
        p = subprocess.run(cmd, input=text, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, env=env, check=False)
    except subprocess.TimeoutExpired as e:
        return proc.ProcResult(False, None, e.stdout or "", (e.stderr or "") + "\n[timed out]",
                               time.monotonic() - start, True)
    except FileNotFoundError as e:
        return proc.ProcResult(False, None, "", f"[not found] {e}", time.monotonic() - start, False)
    return proc.ProcResult(p.returncode == 0, p.returncode, p.stdout, p.stderr,
                           time.monotonic() - start, False)
