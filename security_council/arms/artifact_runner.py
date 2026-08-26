"""Artifact runner (M-V3, house edition): drives one HOUSE analysis prompt
through a house CLI (claude / codex / agy) and attaches the returned document
as a run artifact — never a finding.

Why house prompts: R10 verified live that the vendors' analysis skills are not
reachable through any supported surface (see `artifacts.py`), so the lane now
runs OUR prompts (`prompts/house-analysis-<job>.md` + the shared preamble)
through exactly the plumbing the house scan arms use (`llm_cli.LLM_CLI_SPECS`):

- the same verified argv per CLI, with read-only enforced at the FLAG layer
  (claude `--permission-mode plan --tools Read,Grep,Glob,LS`; codex
  `-s read-only`; agy `--mode plan --sandbox`) — never by prompt prose (R10 §1);
- the same structured-output mechanism, with the analysis DOCUMENT schema
  in place of the finding schema;
- the same D8 model attestation (a pinned model that is substituted fails the
  arm loudly) and the same nesting env;
- cost: claude reports `total_cost_usd` and takes `--max-budget-usd` as a hard
  fuse; codex/agy report neither, so cost is `None` and `cost_stopped` can only
  be observed on claude. Recorded honestly in coverage and on the artifact.

Provenance is named for what it is: producer ``house:<family>``.

Blue scope (D5): the prompts forbid exploit steps and `redact_exploit_content`
post-checks every document (best-effort; see artifacts.py). A document that
fails validation, declines, or arrives after a budget stop is a FAILED arm —
which the orchestrator records as an informational `analysis_failed`
degradation that never touches coverage or the gate.

Status: built and pinned offline (fake-proc) against the flag contract that
the house scan arms have already run live on all three CLIs.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from .. import entitlements as _entitlements
from .. import proc
from ..artifacts import (ANALYSIS_JOBS, DOCUMENT_SCHEMA_VERSION, dumps_document, make_artifact,
                         redact_exploit_content, render_markdown, validate_document)
from .base import ArmResult
from .llm_cli import LLM_CLI_SPECS, _model_matches, _redact, _run_with_stdin

_PKG = Path(__file__).resolve().parent.parent
PROMPT_DIR = _PKG / "prompts"
PREAMBLE_PATH = PROMPT_DIR / "house-analysis-preamble.md"
SCHEMA_PATH = _PKG / "schemas" / "analysis_document.v1.json"

FAMILIES = tuple(LLM_CLI_SPECS)          # claude, codex, agy
DEFAULT_FAMILY = "claude"

# what "read-only" means per CLI, for `available()` and the docs — the flags
# themselves live in llm_cli's builders (one contract, one place)
READ_ONLY_FLAGS = {
    "claude": "--permission-mode plan --tools Read,Grep,Glob,LS",
    "codex": "-s read-only",
    "agy": "--mode plan --sandbox",
}


class ArtifactRunnerArm:
    """One house analysis job through one house CLI → one artifact.
    Selected as ``<cli>-analysis:<job>`` (e.g. ``claude-analysis:threat-model``)."""
    kind = "artifact"
    supports_diff = False
    envelope_key = "body_markdown"         # proves the CLI returned OUR document envelope
    schema_path = SCHEMA_PATH

    def __init__(self, *, job: str, family: str = DEFAULT_FAMILY, model: str | None = None,
                 max_cost_usd: float | None = 5.0, timeout: int | None = None) -> None:
        if job not in ANALYSIS_JOBS:
            raise ValueError(f"unknown analysis job {job!r}; known: {sorted(ANALYSIS_JOBS)}")
        if family not in LLM_CLI_SPECS:
            raise ValueError(f"unknown analysis CLI {family!r}; known: {list(FAMILIES)}")
        self.spec = ANALYSIS_JOBS[job]
        self.cli = LLM_CLI_SPECS[family]
        self.family = self.cli.family                 # claude / codex / google
        self.name = f"{family}-analysis:{job}"
        self.producer = f"house:{family}"
        self.model = model
        # claude's --max-budget-usd fuse (the only house CLI with one); None disables
        self.max_budget_usd = None if max_cost_usd is None else float(max_cost_usd)
        self.timeout = int(timeout) if timeout else self.cli.timeout
        self.needs_findings = self.spec.needs_findings
        self.findings_context: list[dict] | None = None    # set by the orchestrator
        self._prompt_path = PROMPT_DIR / self.spec.prompt

    # ------------------------------------------------------------------ #
    def available(self) -> tuple[bool, str]:
        p = shutil.which(self.cli.command)
        if not p:
            return False, f"{self.cli.command} not on PATH"
        if not self._prompt_path.is_file() or not PREAMBLE_PATH.is_file():
            return False, f"house prompt missing: {self._prompt_path.name}"
        fuse = (f"; fuse --max-budget-usd {self.max_budget_usd:g}"
                if self.cli.name == "claude" and self.max_budget_usd is not None
                else "; no cost fuse on this CLI")
        return True, (f"local: {p} (house prompt {self.spec.prompt}, read-only via "
                      f"{READ_ONLY_FLAGS[self.cli.name]}{fuse})")

    def _env(self) -> dict:
        env = dict(os.environ)
        env["SECURITY_COUNCIL_NESTED"] = "1"
        env["LLM_COUNCIL_NESTED"] = "1"
        return env

    def build_prompt(self) -> str:
        text = PREAMBLE_PATH.read_text() + "\n" + self._prompt_path.read_text()
        if self.needs_findings:
            rows = self.findings_context or []
            if rows:
                text += ("\n## Findings digest from this run (context, verify against the code)\n\n"
                         "```json\n" + json.dumps(rows, indent=1) + "\n```\n")
            else:
                text += ("\n## Findings digest from this run\n\nNone was supplied "
                         "(no scan arm reported findings, or none ran); proceed on your own "
                         "reading of the code.\n")
        return text

    # ------------------------------------------------------------------ #
    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_name = self.name.replace(":", "_")
        raw_dir = Path(out_dir) / "raw" / raw_name
        raw_dir.mkdir(parents=True, exist_ok=True)
        prompt = self.build_prompt()
        prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
        cmd = self.cli.build_cmd(self, prompt, target, raw_dir)
        if self.cli.stdin_prompt:
            r = _run_with_stdin(cmd, prompt, timeout=self.timeout, cwd=str(target), env=self._env())
        else:
            r = proc.run_command(cmd, timeout=self.timeout, cwd=str(target), env=self._env())
        parsed = self.cli.parse(self, r, raw_dir)

        served = parsed.served_model
        posture = _entitlements.safeguard_posture_for(self.model)
        tier = _entitlements.classify_model(self.model)
        cost_stopped = bool(parsed.subtype and "budget" in parsed.subtype.lower())
        cov = {"job": self.spec.key, "dual_use": self.spec.dual_use, "exit_code": r.exit_code,
               "safeguard_posture": posture, "prompt_sha256": prompt_sha,
               "cost_usd": parsed.cost_usd, "cost_stopped": cost_stopped,
               # codex never reports its served model (see §7.3); claude/agy do
               "model_unattested": served is None or self.cli.name == "codex",
               "served_model": served}

        def fail(error: str, *, classifier_fallback: bool = False) -> ArmResult:
            (raw_dir / "cli-output.txt").write_text(
                f"$ {' '.join(_redact(cmd))}\n\n[stdout tail]\n{r.stdout[-4000:]}\n\n"
                f"[stderr tail]\n{r.stderr[-4000:]}\n")
            return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                             exit_code=r.exit_code, error=error, findings=[],
                             elapsed_seconds=r.elapsed_seconds, command=_redact(cmd),
                             coverage={**cov, "classifier_fallback": classifier_fallback})

        if r.timed_out:
            return fail(f"timed out after {self.timeout}s")
        if cost_stopped:
            return fail(f"cost_stopped: {parsed.subtype} (fuse --max-budget-usd "
                        f"{self.max_budget_usd:g})")
        if not parsed.status_ok:
            return fail(f"arm not ok: {parsed.note or r.stderr[:200] or f'exit {r.exit_code}'}")
        if self.model and served and not _model_matches(self.model, served):
            return fail(f"model_substituted: requested {self.model} served {served}",
                        classifier_fallback=True)
        doc = parsed.envelope
        if isinstance(doc, str):          # agy hands structured_output through un-coerced
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                doc = None
        if doc is None:
            return fail("no structured output (no analysis document returned)")
        problems = validate_document(doc, job=self.spec)
        if problems:
            return fail("invalid analysis document: " + "; ".join(problems))
        hdr = doc["header"]
        if hdr["completion"] == "declined":
            return fail(f"declined: {hdr.get('notes') or 'no reason given'}")

        body, labels = redact_exploit_content(doc.get("body_markdown") or "",
                                              dual_use=self.spec.dual_use)
        doc = {**doc, "schema_version": DOCUMENT_SCHEMA_VERSION, "body_markdown": body,
               "header": {**hdr, "inputs_read": [str(x) for x in hdr.get("inputs_read") or []]}}
        cov["redactions"] = labels
        cov["completion"] = hdr["completion"]

        md_rel = f"raw/{raw_name}/{self.spec.key}.md"
        model_id = served or self.model or f"{self.cli.name}-account-default"
        art = make_artifact(job=self.spec, path=md_rel, producer=self.producer,
                            family=self.family, run_id=run_id, created_at=collected_at,
                            model_id=model_id, entitlement=tier.name if tier else None,
                            safeguard_posture=posture, prompt_sha256=prompt_sha,
                            inputs_read=doc["header"]["inputs_read"],
                            completion=hdr["completion"], redactions=len(labels),
                            cost_usd=parsed.cost_usd,
                            model_attested=not cov["model_unattested"],
                            related_finding_ids=[row["id"] for row in (self.findings_context or [])
                                                 if isinstance(row, dict) and row.get("id")])
        (raw_dir / "document.json").write_text(dumps_document(doc))
        (raw_dir / f"{self.spec.key}.md").write_text(
            render_markdown(doc, art, cli=self.cli.name, prompt_name=self.spec.prompt))
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=[],
                         tool_version=served, elapsed_seconds=r.elapsed_seconds,
                         command=_redact(cmd), raw_path=str(raw_dir / f"{self.spec.key}.md"),
                         coverage=cov, artifacts=[art.to_dict()])
