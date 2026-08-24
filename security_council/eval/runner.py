"""Replay-based eval runner: recorded raw fixtures -> real pipeline -> gate.

Replays `tests/fixtures/raw/` (every arm family: semgrep/gitleaks/osv SARIF, the
claude-security report, the codex-security sealed bundle, and a house-arm
envelope) through the SAME normalize -> cluster -> coverage -> score -> policy
code the scanner runs, then injects panel verdicts from a fixture
(`eval/panel_verdicts.yaml`) so the demote/suppress branches of `apply_policy`
are actually exercised (R3: without a validated-run input the gate only tests
the no-op branch). No live LLM/scanner cost; fully deterministic.

The panel-verdict fixture models a CORRECT panel (TPs validated, decoy refuted);
tests also run a deliberately-wrong panel to prove the gate catches wrongful
demotion. Timestamps are fixed for determinism.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .. import policy as policy_mod
from ..cluster import cluster_findings, merge_cluster
from ..model import EvidenceCitation, Finding, PanelOpinion, Validation
from ..normalize import coverage, registry
from ..normalize.base import ParseContext
from ..validate.panel import _state_for
from . import metrics

COLLECTED_AT = "2026-08-21T00:00:00Z"
NOW_ISO = "2026-08-22T00:00:00Z"
_SHA = "e" * 64   # fixed sha-shaped prompt hash for replay provenance

# (source_id, kind, family) — must mirror what load_corpus ingests, so the
# coverage stage sees the same roster the orchestrator would.
SOURCES = (
    ("semgrep", "scanner", "semgrep"),
    ("gitleaks", "scanner", "gitleaks"),
    ("osv-scanner", "scanner", "osv"),
    ("claude-security", "agent_cli", "claude"),
    ("codex-security", "agent_cli", "codex"),
    ("claude", "agent_cli", "claude"),
)


@dataclass
class EvalRun:
    report: metrics.EvalReport
    findings: list[Finding] = field(default_factory=list)
    decisions: list = field(default_factory=list)


def _scanner_ctx(repo_root: Path, source_id: str, family: str) -> ParseContext:
    return ParseContext(repo_root=repo_root, scan_root="/src", source_id=source_id,
                        source_kind="scanner", family=family, tool_version="eval-fixture",
                        collected_at=COLLECTED_AT)


def _agent_ctx(repo_root: Path, source_id: str, family: str, model_id: str) -> ParseContext:
    return ParseContext(repo_root=repo_root, source_id=source_id, source_kind="agent_cli",
                        family=family, collected_at=COLLECTED_AT, model_id=model_id,
                        prompt_sha256=_SHA)


def load_corpus(fixtures_root: Path) -> list[Finding]:
    """Normalize every recorded raw fixture exactly as the arms would."""
    root = Path(fixtures_root)
    repo, raw = root / "seedrepo", root / "raw"
    fs: list[Finding] = []
    for name, source_id, family in (("semgrep", "semgrep", "semgrep"),
                                    ("gitleaks", "gitleaks", "gitleaks"),
                                    ("osv", "osv-scanner", "osv")):
        doc = json.load(open(raw / f"{name}.sarif"))
        fs += registry.normalize_sarif(doc, source_id, _scanner_ctx(repo, source_id, family))
    cs = json.load(open(raw / "claude-security" / "CLAUDE-SECURITY-RESULTS.sarif"))
    fs += registry.normalize_claude_security(
        cs, _agent_ctx(repo, "claude-security", "claude", "claude-fable-5"))[0]
    cx_dir = raw / "codex-security"
    fs += registry.normalize_codex_security(
        json.load(open(cx_dir / "findings.json")),
        _agent_ctx(repo, "codex-security", "codex", "codex-security-default"),
        manifest=json.load(open(cx_dir / "scan-manifest.json")),
        coverage=json.load(open(cx_dir / "coverage.json")))[0]
    env = json.load(open(raw / "house-claude.envelope.json"))
    fs += registry.normalize_envelope(
        env, _agent_ctx(repo, "claude", "claude", "claude-fable-5"))[0]
    return fs


def merge_and_cover(findings: list[Finding], *, min_distinct_vendors: int = 2) -> list[Finding]:
    clusters = cluster_findings(findings, min_distinct_vendors=min_distinct_vendors)
    run_ctx = coverage.RunContext(
        sources=[coverage.SourceRun(s, k, f, ran=True) for s, k, f in SOURCES],
        min_distinct_vendors=min_distinct_vendors)
    return [coverage.apply(merge_cluster(c), run_ctx) for c in clusters]


def _panel(f: Finding, verdict: str) -> list[PanelOpinion]:
    loc = f.locations[0]
    cite = EvidenceCitation(path=loc.uri, start_line=loc.start_line, end_line=loc.end_line,
                            claim="eval replay citation", verified=True)
    return [PanelOpinion(role=role, participant=name, family=fam, prompt_sha256=_SHA,
                         verdict=verdict, rationale="eval replay", model_id=f"eval-{name}",
                         citations=[cite], citation_pass_rate=1.0, status="ok")
            for role, name, fam in (("prosecutor", "claude", "claude"),
                                    ("defender", "codex", "codex"),
                                    ("adjudicator", "antigravity", "google"))]


def apply_verdicts(findings: list[Finding], expected: dict, verdicts: dict[str, str]) -> None:
    """Attach a unanimous 3-seat panel per matched case and set the panel state,
    reusing the real `_state_for` mapping. A cluster matched by several cases
    (SQLi+CMDI) keeps its first verdict; the fixture keeps them consistent."""
    matches, _ = metrics.match(expected, findings)
    for case_id, verdict in verdicts.items():
        for f in matches.get(case_id, []):
            if f.validation is not None:
                continue
            val = Validation(verdict=verdict, confidence=1.0, panel=_panel(f, verdict),
                             evidence_check={"citations_total": 3, "citations_verified": 3,
                                             "hallucinated": 0, "defender_hallucinated": False})
            f.validation = val
            f.disposition.state = _state_for(f, val)


def run_eval(fixtures_root: str | Path, *, config: dict | None = None, prior_runs: int = 99,
             history: dict | None = None, verdicts: dict[str, str] | None = None,
             calibration=None) -> EvalRun:
    root = Path(fixtures_root)
    expected = yaml.safe_load(open(root / "EXPECTED.yaml"))
    if verdicts is None:
        verdicts = yaml.safe_load(open(root / "eval" / "panel_verdicts.yaml"))["verdicts"]
    findings = merge_and_cover(load_corpus(root))
    apply_verdicts(findings, expected, verdicts)
    decisions = policy_mod.apply_policy(findings, config or {}, now_iso=NOW_ISO,
                                        prior_runs=prior_runs, history=history,
                                        calibration=calibration)
    report = metrics.compute(expected, findings)
    report.disposition_actions = policy_mod.decisions_summary(decisions)
    return EvalRun(report=report, findings=findings, decisions=decisions)
