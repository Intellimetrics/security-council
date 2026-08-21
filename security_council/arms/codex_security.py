"""Dedicated arm: OpenAI's `@openai/codex-security` CLI (headless scan).

Runs ``codex-security scan <target> --headless --format json --output-dir <tmp>``
and ingests the *canonical* bundle the scan seals (``scan-manifest.json``,
``findings.json``, ``coverage.json``) — not the lossy SARIF projection.

Hardening facts from the M0 S3 spike and the tool's own runtime checks, which
this arm satisfies rather than fights:
- the output directory must be outside the scanned tree and any enclosing git
  worktree, be private (0700), and every ancestor must be non-symlink, owned by
  us or root, and not group/world-writable unless sticky. Our run dir lives
  inside the target's worktree, so the scan writes to a fresh ``mkdtemp`` (0700
  under the sticky tmp) and the bundle is copied into ``raw/codex-security/``.
- ``~/.codex`` must not be group-writable (the operator already chmod'd it 700).
- it is slow and expensive (standard mode ~7-8 min on a 12-file repo, ~$4):
  ``--max-cost`` is the fuse; a cost-stopped scan still seals a *partial* bundle,
  which we report with ``completion: partial``.
- exit codes: 0 completed; 1 only with ``--fail-on-severity`` (we never pass it);
  2 = incomplete coverage *or* runtime error — so success is decided by the
  sealed manifest, not the exit code.

D8 applies: the served model comes from the JSON result's ``turnResult.model``
and a pin mismatch drops the arm loudly.
"""

from __future__ import annotations

import glob
import json
import os
import shlex
import shutil
import stat
import tempfile
from pathlib import Path

from .. import proc
from ..normalize import registry
from ..normalize.base import ParseContext
from .base import ArmResult
from .llm_cli import _model_matches

ARM_NAME = "codex-security"
CMD_ENV = "SECURITY_COUNCIL_CODEX_SECURITY_CMD"
MODES = ("standard", "deep")
BUNDLE_FILES = ("scan-manifest.json", "findings.json", "coverage.json", "report.md")


_NPX_CACHE_GLOB = os.path.expanduser("~/.npm/_npx/*/node_modules/@openai/codex-security")
INSTALL_HINT = "npm install -g @openai/codex-security (or set SECURITY_COUNCIL_CODEX_SECURITY_CMD)"


def _cached_package() -> Path | None:
    """Newest @openai/codex-security in the npx cache (left there by `npx @openai/codex-security`)."""
    best: tuple[tuple[int, ...], Path] | None = None
    for d in glob.glob(_NPX_CACHE_GLOB):
        pkg = Path(d)
        try:
            ver = json.load(open(pkg / "package.json")).get("version", "0")
            key = tuple(int(x) for x in str(ver).split(".") if x.isdigit())
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if (pkg / "bin" / "codex-security.mjs").is_file() and (best is None or key > best[0]):
            best = (key, pkg)
    return best[1] if best else None


def resolve_command() -> list[str] | None:
    """How to invoke codex-security, without ever auto-installing at scan time:
    env override > binary on PATH > cached npx package run via node > None."""
    override = os.environ.get(CMD_ENV)
    if override:
        return shlex.split(override)
    p = shutil.which("codex-security")
    if p:
        return [p]
    node = shutil.which("node")
    pkg = _cached_package()
    if node and pkg:
        return [node, str(pkg / "bin" / "codex-security.mjs")]
    return None


class CodexSecurityArm:
    kind = "agent_cli"
    family = "codex"
    name = ARM_NAME

    def __init__(self, *, model: str | None = None, mode: str = "standard",
                 effort: str | None = None, max_cost_usd: float = 5.0,
                 scope: list[str] | None = None, max_time_hours: float | None = None,
                 timeout: int = 3600) -> None:
        if mode not in MODES:
            raise ValueError(f"codex-security mode must be one of {MODES}, got {mode!r}")
        self.model = model
        self.mode = mode
        self.effort = effort
        self.max_cost_usd = float(max_cost_usd)
        self.scope = list(scope) if scope else None
        self.max_time_hours = max_time_hours
        self.timeout = int(timeout)

    # ------------------------------------------------------------------ #
    def available(self) -> tuple[bool, str]:
        base = resolve_command()
        if not base:
            return False, f"codex-security not installed: {INSTALL_HINT}"
        r = proc.run_command([*base, "--version"], timeout=90)
        if not r.ok:
            return False, f"{' '.join(base)} --version failed: {(r.stderr or r.stdout)[:120].strip()}"
        how = "local" if base[0].endswith("codex-security") else ("npx-cache" if base[-1].endswith(".mjs") else "custom")
        return True, f"{how}: {Path(base[-1]).name} {r.stdout.strip()[:40]}"

    def _env(self) -> dict:
        env = dict(os.environ)
        env["SECURITY_COUNCIL_NESTED"] = "1"
        env["LLM_COUNCIL_NESTED"] = "1"
        return env

    def _cmd(self, base: list[str], target: Path, out_dir: str) -> list[str]:
        cmd = [*base, "scan", str(target), "--headless", "--format", "json",
               "--output-dir", out_dir, "--mode", self.mode, "--max-cost", f"{self.max_cost_usd:g}"]
        if self.model:
            cmd += ["--model", self.model]
        if self.effort:
            cmd += ["--effort", self.effort]
        for p in self.scope or []:
            cmd += ["--path", p]
        if self.mode == "deep" and self.max_time_hours:
            cmd += ["--max-time-hours", f"{self.max_time_hours:g}"]
        return cmd

    # ------------------------------------------------------------------ #
    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = Path(out_dir) / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        base = resolve_command()
        if not base:
            return self._fail(["codex-security"], None, error="codex-security not available")
        tmp_out = tempfile.mkdtemp(prefix="security-council-codexsec-")
        os.chmod(tmp_out, stat.S_IRWXU)            # 0700: the tool refuses anything looser
        cmd = self._cmd(base, target, tmp_out)
        try:
            r = proc.run_command(cmd, timeout=self.timeout, cwd=str(target), env=self._env(),
                                 success_exit_codes=(0, 1, 2))
            outer = _parse_json(r.stdout)
            (raw_dir / "codex-security-result.json").write_text(json.dumps(
                outer if outer is not None else {"stdout": r.stdout[-4000:], "stderr": r.stderr[-4000:]},
                indent=2))
            manifest_path = _find_manifest(Path(tmp_out))
            scan_dir = manifest_path.parent if manifest_path else None
            if scan_dir:
                _copy_bundle(scan_dir, raw_dir)
        finally:
            shutil.rmtree(tmp_out, ignore_errors=True)

        served = _served_model(outer)
        cost = _cost_usd(outer)
        base_cov = {"cost_usd": cost, "mode": self.mode, "exit_code": r.exit_code}
        if r.timed_out:
            return self._fail(cmd, r, error=f"timed out after {self.timeout}s", cov=base_cov)
        if self.model and served and not _model_matches(self.model, served):
            return self._fail(cmd, r, error=f"model_substituted: requested {self.model} served {served}",
                              classifier_fallback=True, cov=base_cov)
        findings_path = raw_dir / "findings.json"
        if scan_dir is None or not findings_path.is_file():
            tail = (r.stderr or r.stdout or "").strip()[-300:]
            return self._fail(cmd, r, error=f"no sealed scan bundle (exit {r.exit_code}): {tail}", cov=base_cov)

        doc = json.load(open(findings_path))
        manifest = _load_json(raw_dir / "scan-manifest.json")
        coverage = _load_json(raw_dir / "coverage.json")
        ctx = ParseContext(repo_root=target, source_id=self.name, source_kind="agent_cli",
                           family=self.family, run_id=run_id, collected_at=collected_at,
                           model_id=served or self.model or "codex-security-default",
                           prompt_sha256=_bundle_prompt_sha(manifest),
                           tool_version=((manifest or {}).get("scan") or {}).get("producer", {}).get("version"))
        findings, meta = registry.normalize_codex_security(doc, ctx, manifest=manifest, coverage=coverage)
        status = meta.get("status")
        completeness = meta.get("completeness")
        complete = status == "completed" and completeness in (None, "complete")
        cov = {**base_cov, "raw_results": meta.get("results"), "normalized": len(findings),
               "scan_id": meta.get("scan_id"), "status": status, "completeness": completeness,
               "producer": meta.get("producer"), "completion": "complete" if complete else "partial",
               "skipped": dict(ctx.skipped)}
        if not findings and not complete:
            cov["coverage_unverified"] = True
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=findings,
                         tool_version=served or self.model, elapsed_seconds=r.elapsed_seconds,
                         command=cmd, raw_path=str(findings_path), coverage=cov)

    def _fail(self, cmd, r, *, error: str, classifier_fallback: bool = False, cov: dict | None = None):
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                         exit_code=getattr(r, "exit_code", None), error=error, findings=[],
                         elapsed_seconds=getattr(r, "elapsed_seconds", 0.0), command=list(cmd),
                         coverage={**(cov or {}), "classifier_fallback": classifier_fallback})


# ---------------------------------------------------------------------- #


def _parse_json(text: str) -> dict | None:
    s = (text or "").strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    # headless progress lines may precede the JSON document: find the first '{'
    i = s.find("{")
    if i >= 0:
        try:
            obj = json.loads(s[i:])
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _load_json(path: Path) -> dict | None:
    try:
        obj = json.load(open(path))
        return obj if isinstance(obj, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _find_manifest(root: Path) -> Path | None:
    cands = sorted(root.rglob("scan-manifest.json"), key=lambda p: p.stat().st_mtime)
    return cands[-1] if cands else None


def _copy_bundle(scan_dir: Path, raw_dir: Path) -> None:
    for name in BUNDLE_FILES:
        src = scan_dir / name
        if src.is_file():
            shutil.copy2(src, raw_dir / name)
    exports = scan_dir / "exports"
    if exports.is_dir():
        shutil.copytree(exports, raw_dir / "exports", dirs_exist_ok=True)


def _served_model(outer: dict | None) -> str | None:
    if not outer:
        return None
    tr = outer.get("turnResult") or {}
    return (tr.get("model") if isinstance(tr, dict) else None) or outer.get("model")


def _cost_usd(outer: dict | None) -> float | None:
    if not outer:
        return None
    cost = outer.get("cost")
    if isinstance(cost, (int, float)):
        return float(cost)
    if isinstance(cost, dict):
        for k in ("totalUsd", "estimatedUsd", "usd", "total", "estimatedCostUsd"):
            v = cost.get(k)
            if isinstance(v, (int, float)):
                return float(v)
    return None


def _bundle_prompt_sha(manifest: dict | None) -> str:
    """agent_cli provenance needs a sha-shaped prompt hash; the tool owns its prompts,
    so we hash the sealed scan identity (scan id + snapshot) as the reproducibility key."""
    import hashlib
    scan = (manifest or {}).get("scan") or {}
    tgt = scan.get("target") or {}
    key = json.dumps({"scan": scan.get("id"), "target": tgt.get("targetId"),
                      "snapshot": tgt.get("snapshotDigest") or tgt.get("revision"),
                      "producer": scan.get("producer")}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()
