"""Analysis-artifact lane (M-V3), reframed onto HOUSE prompts (2026-08-26).

Analysis jobs (threat model, attack-path analysis, hardening proposals, a
security-policy proposal, vulnerability write-ups) produce *documents*, not
gate-able findings. Per R5 they attach to a run as manifest-indexed artifacts
and NEVER enter `findings.json` or the finding model's invariant surface.

Trust-boundary rules this module encodes (unchanged since R5):
- **Artifacts are not findings.** They live under `raw/<producer>/` and are
  listed in the manifest's `artifacts` index; the SARIF/eMASS/GitLab exporters
  (which render findings) never touch them.
- **Dual-use artifacts are export-excluded by default.** attack-path analysis
  and vulnerability write-ups are attacker-facing narratives; they stay
  `raw/`-resident, are flagged in the summary, and their content is never
  inlined into a shareable report unless an operator opts in.
- Every artifact carries provenance: producer, model id, entitlement,
  safeguard posture, prompt hash, files read.

Who produces them — **reframed after R10/R11.** The vendors' analysis
"skills" are internal phases of `codex-security scan`, not a public surface
(R10 §4: `codex plugin add` cannot register the bundled plugin, the reference
producer inlines the skill text with plugins disabled, and the skill files are
not self-contained). So the lane no longer pretends to drive them. Instead
each job is one of OUR prompts (`prompts/house-analysis-<job>.md`, with the
shared preamble) driven through the same read-only CLI contract the house scan
arms use (`arms/llm_cli.py`: claude / codex / agy). The producer is therefore
named honestly as ``house:<family>`` — never a vendor skill name.

Blue scope (D5): the prompts forbid exploit steps, and `redact_exploit_content`
post-checks the document for payload-shaped text. That check is deliberately
simple and documented as best-effort — a model that ignores the prompt can
phrase an attack in prose the regexes will not see. Its job is to keep an
obvious runbook (shell blocks, reverse shells, injection strings) out of an
artifact that is by design attacker-facing, not to certify the document safe.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Optional

_RAW_PATH_RE = re.compile(r"^raw/[^/].*[^/]$")

DOCUMENT_SCHEMA_VERSION = "sc-analysis-doc/1"
COMPLETIONS = ("complete", "partial", "declined")


@dataclass(frozen=True)
class AnalysisJob:
    key: str                 # short selector, e.g. "threat-model"
    prompt: str              # house prompt file under prompts/
    title: str
    dual_use: bool           # attacker-facing → export-excluded by default
    needs_findings: bool     # wants the run's findings digest as context


# House analysis jobs. `family` is no longer a property of the job — any of the
# three house CLIs can run any job; the caller picks (default claude).
ANALYSIS_JOBS: dict[str, AnalysisJob] = {
    "threat-model": AnalysisJob("threat-model", "house-analysis-threat-model.md",
                                "Repository threat model", False, False),
    "attack-path": AnalysisJob("attack-path", "house-analysis-attack-path.md",
                               "Attack-path analysis", True, True),
    "hardening": AnalysisJob("hardening", "house-analysis-hardening.md",
                             "Security hardening proposals", False, False),
    "policy": AnalysisJob("policy", "house-analysis-policy.md",
                          "Security policy proposal", False, False),
    "writeup": AnalysisJob("writeup", "house-analysis-writeup.md",
                           "Vulnerability write-ups", True, True),
}


@dataclass
class Artifact:
    id: str
    kind: str                        # the job key
    title: str
    path: str                        # repo-relative, under raw/<producer>/
    producer: str                    # "house:<family>" for the analysis lane
    family: str
    dual_use: bool
    export_excluded: bool
    created_at: str
    model_id: Optional[str] = None
    entitlement: Optional[str] = None
    safeguard_posture: str = "default"
    format: str = "markdown"
    related_finding_ids: list[str] = field(default_factory=list)
    # M-V3 house lane provenance (None/empty for non-analysis artifacts)
    prompt_sha256: Optional[str] = None
    inputs_read: list[str] = field(default_factory=list)
    completion: Optional[str] = None
    redactions: int = 0
    cost_usd: Optional[float] = None
    model_attested: Optional[bool] = None

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "path": self.path,
                "producer": self.producer, "family": self.family, "dual_use": self.dual_use,
                "export_excluded": self.export_excluded, "created_at": self.created_at,
                "model_id": self.model_id, "entitlement": self.entitlement,
                "safeguard_posture": self.safeguard_posture, "format": self.format,
                "related_finding_ids": list(self.related_finding_ids),
                "prompt_sha256": self.prompt_sha256, "inputs_read": list(self.inputs_read),
                "completion": self.completion, "redactions": self.redactions,
                "cost_usd": self.cost_usd, "model_attested": self.model_attested}


def artifact_id(*, kind: str, producer: str, path: str, run_id: str) -> str:
    key = f"{run_id}\x00{producer}\x00{kind}\x00{path}"
    return "A" + hashlib.sha256(key.encode()).hexdigest()[:15]


def make_artifact(*, job: AnalysisJob, path: str, producer: str, family: str, run_id: str,
                  created_at: str, model_id: str | None = None, entitlement: str | None = None,
                  safeguard_posture: str = "default",
                  related_finding_ids: list[str] | None = None,
                  export_excluded: bool | None = None, **extra) -> Artifact:
    if not _RAW_PATH_RE.match(path):
        raise ValueError(f"artifact path must be repo-relative under raw/: {path!r}")
    excl = job.dual_use if export_excluded is None else export_excluded
    return Artifact(
        id=artifact_id(kind=job.key, producer=producer, path=path, run_id=run_id),
        kind=job.key, title=job.title, path=path, producer=producer, family=family,
        dual_use=job.dual_use, export_excluded=excl, created_at=created_at,
        model_id=model_id, entitlement=entitlement, safeguard_posture=safeguard_posture,
        related_finding_ids=list(related_finding_ids or []), **extra)


def export_eligible(artifacts: list[dict]) -> list[dict]:
    """Artifacts safe to include in a shareable bundle — dual-use/export-excluded
    ones are held back (raw/-only)."""
    return [a for a in artifacts if not a.get("export_excluded")]


# --------------------------------------------------------------------------- #
# document envelope (what the house prompt must return)
# --------------------------------------------------------------------------- #


def _safe_relpath(p: str) -> bool:
    """Repository-relative, no absolute paths, no traversal, no scheme."""
    if not isinstance(p, str) or not p or p.startswith(("/", "\\")) or ":" in p[:8]:
        return False
    norm = posixpath.normpath(p.replace("\\", "/"))
    return not (norm == ".." or norm.startswith("../") or norm.startswith("/"))


def validate_document(doc, *, job: AnalysisJob) -> list[str]:
    """Problems with a returned analysis document, or [] when it is usable.

    Mirrors what the schema says, then adds what a portable schema cannot
    express: the kind must be the job asked for, the body must be non-empty,
    and `inputs_read` must be repository-relative paths (a model claiming to
    have read `/etc/passwd` or `../other-repo` is reporting something the
    read-only sandbox should not allow — flag it rather than index it)."""
    out: list[str] = []
    if not isinstance(doc, dict):
        return ["document is not a JSON object"]
    if doc.get("schema_version") != DOCUMENT_SCHEMA_VERSION:
        out.append(f"schema_version must be {DOCUMENT_SCHEMA_VERSION!r}, "
                   f"got {doc.get('schema_version')!r}")
    hdr = doc.get("header")
    if not isinstance(hdr, dict):
        out.append("header missing or not an object")
        hdr = {}
    if hdr.get("kind") != job.key:
        out.append(f"header.kind must be {job.key!r}, got {hdr.get('kind')!r}")
    if not isinstance(hdr.get("title"), str) or not hdr.get("title", "").strip():
        out.append("header.title must be a non-empty string")
    if hdr.get("completion") not in COMPLETIONS:
        out.append(f"header.completion must be one of {list(COMPLETIONS)}, "
                   f"got {hdr.get('completion')!r}")
    inputs = hdr.get("inputs_read")
    if not isinstance(inputs, list) or not all(isinstance(x, str) for x in inputs):
        out.append("header.inputs_read must be a list of strings")
    else:
        bad = [x for x in inputs if not _safe_relpath(x)]
        if bad:
            out.append(f"header.inputs_read has non-repository paths: {bad[:5]}")
    body = doc.get("body_markdown")
    if hdr.get("completion") != "declined":
        if not isinstance(body, str) or not body.strip():
            out.append("body_markdown must be a non-empty string")
    elif body is not None and not isinstance(body, str):
        out.append("body_markdown must be a string")
    return out


# --------------------------------------------------------------------------- #
# Blue-scope post-check: keep exploit-shaped content out of the document
# --------------------------------------------------------------------------- #

# Fenced code blocks whose language tag says "this is a shell session". Only
# applied to DUAL-USE jobs: a hardening proposal legitimately contains
# `chmod`/`apt` lines, an attack-path analysis has no business containing any
# shell block at all.
_SHELL_FENCE_RE = re.compile(
    r"```[ \t]*(?:bash|sh|shell|zsh|fish|console|terminal|powershell|pwsh|ps1|cmd|bat|batch)\b"
    r"[^\n]*\n.*?```", re.S | re.I)

# Payload signatures checked on EVERY job. Each is a (regex, label). The list
# is short on purpose: it targets text that has no defensive reading (reverse
# shells, exploit tooling, canonical injection strings), so a hit is a
# redaction, never a judgement call. It is best-effort by construction.
PAYLOAD_MARKERS: tuple[tuple[str, str], ...] = (
    (r"/dev/tcp/", "reverse-shell"),
    (r"\bbash\s+-i\s*>&", "reverse-shell"),
    (r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s", "reverse-shell"),
    (r"\b(?:msfvenom|msfconsole|meterpreter|sqlmap|mimikatz|hydra|responder\.py)\b",
     "exploit-tooling"),
    (r"'\s*(?:or|OR)\s*'?1'?\s*=\s*'?1", "sql-injection-payload"),
    (r"\bunion\s+(?:all\s+)?select\b", "sql-injection-payload"),
    (r"<script[\s>]", "xss-payload"),
    (r"(?:\.\./){3,}", "traversal-payload"),
    (r"\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b", "encoded-powershell"),
    (r"\bpython3?\s+-c\s+[\"']import\s+(?:socket|pty|os)\b", "reverse-shell"),
)
_PAYLOAD_RES = tuple((re.compile(rx, re.I), label) for rx, label in PAYLOAD_MARKERS)

REDACTION_NOTE = ("> [redacted by security-council: {what} removed — Blue scope, "
                  "no exploit steps (D5)]")


def redact_exploit_content(body: str, *, dual_use: bool) -> tuple[str, list[str]]:
    """Return (redacted_body, labels). Each label names one redaction.

    Dual-use jobs lose every shell-tagged fenced block; every job loses any
    LINE that matches a payload marker. Redactions are visible in the document
    (a quoted note stands where the text was) so an operator can see that the
    post-check fired and judge whether it over-reached. Documented limits:
    prose descriptions of an attack, untagged code fences, and payloads the
    marker list does not know are not caught."""
    labels: list[str] = []
    text = body or ""
    if dual_use:
        def _fence(m):
            labels.append("shell-block")
            return REDACTION_NOTE.format(what="shell block")
        text = _SHELL_FENCE_RE.sub(_fence, text)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        for rx, label in _PAYLOAD_RES:
            if rx.search(line):
                labels.append(label)
                lines[i] = REDACTION_NOTE.format(what=label.replace("-", " "))
                break
    return "\n".join(lines), labels


# --------------------------------------------------------------------------- #
# findings digest (context for the findings-scoped jobs) + rendering
# --------------------------------------------------------------------------- #


def findings_digest(findings, *, limit: int = 40) -> list[dict]:
    """A compact, de-duplicated (by root cause) view of what the scan arms
    found, for the `needs_findings` jobs. Titles, families, locations and
    source names only — no snippets (the model reads the tree itself), no
    dispositions (this is context, never a decision record)."""
    seen: set[str] = set()
    out: list[dict] = []
    for f in findings:
        rc = f.fingerprints.root_cause
        if rc in seen:
            continue
        seen.add(rc)
        out.append({
            "id": f.id, "title": f.title, "severity": f.severity.label,
            "cwe_family": f.taxonomy.cwe_family, "cwe": list(f.taxonomy.cwe),
            "locations": [f"{loc.uri}:{loc.start_line}-{loc.end_line}" for loc in f.locations],
            "sources": [p.source_id for p in f.provenance],
        })
        if len(out) >= limit:
            break
    return out


def render_markdown(doc: dict, art: Artifact, *, cli: str, prompt_name: str) -> str:
    """The on-disk `.md`: a provenance header a reader cannot miss, then the body."""
    hdr = doc.get("header") or {}
    lines = [
        "<!-- security-council analysis artifact — a DOCUMENT, not a finding; it never "
        f"affects the gate. producer={art.producer} model={art.model_id or 'unknown'} "
        f"entitlement={art.entitlement or 'none'} safeguard_posture={art.safeguard_posture} "
        f"prompt_sha256={art.prompt_sha256} dual_use={'yes' if art.dual_use else 'no'} -->",
        f"# {hdr.get('title') or art.title}",
        "",
        f"_Produced by security-council house prompt `{prompt_name}` through the `{cli}` CLI "
        f"(model: {art.model_id or 'unknown'}"
        + ("" if art.model_attested else ", not attested by the CLI")
        + f"; entitlement: {art.entitlement or 'none'}; safeguard posture: "
        f"{art.safeguard_posture}). Completion: {art.completion}. "
        f"Files read: {len(art.inputs_read)}._",
        "",
    ]
    if art.dual_use:
        lines += ["> **Dual-use document.** Kept under `raw/` only and excluded from "
                  "shareable reports. Written for defenders; exploit steps are refused by "
                  "the prompt and redacted by a post-check (best-effort).", ""]
    if art.redactions:
        lines += [f"> **{art.redactions} redaction(s)** applied by the Blue-scope post-check; "
                  "each is marked in place.", ""]
    if hdr.get("scope"):
        lines += [f"**Scope:** {hdr['scope']}", ""]
    if hdr.get("notes"):
        lines += [f"**Notes from the model:** {hdr['notes']}", ""]
    lines += [(doc.get("body_markdown") or "").rstrip(), ""]
    if art.inputs_read:
        lines += ["## Files read", ""] + [f"- `{p}`" for p in art.inputs_read] + [""]
    return "\n".join(lines)


def dumps_document(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
