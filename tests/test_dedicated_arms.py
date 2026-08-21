"""Dedicated agentic arms (claude-security plugin, codex-security CLI), offline.

Fixtures:
- tests/fixtures/raw/claude-security/  — rendered by the plugin's own render_report.py
  (v0.10.1) from hand-written findings/votes over the seedrepo: a real, `verified` SARIF
  with the JSONL record + panel tally per result and the stamp on the run.
- tests/fixtures/raw/codex-security/   — a canonical bundle (findings/manifest/coverage)
  hand-written to the bundled findings.schema.json (vendored under fixtures/schemas).
"""
import json
import pathlib
import shutil
import stat
import subprocess

import jsonschema

from security_council import model as m
from security_council.arms.claude_security import ClaudeSecurityArm, build_prompt
from security_council.arms.codex_security import CodexSecurityArm
from security_council.arms.registry import build_arm, known_arms
from security_council.normalize import registry
from security_council.normalize.base import ParseContext
from security_council.normalize.sources import claude_security as cs_adapter
from security_council.normalize.sources import codex_security as cx_adapter

HERE = pathlib.Path(__file__).parent
SEED = HERE / "fixtures" / "seedrepo"
CS_DIR = HERE / "fixtures" / "raw" / "claude-security"
CX_DIR = HERE / "fixtures" / "raw" / "codex-security"
CS_SARIF = CS_DIR / "CLAUDE-SECURITY-RESULTS.sarif"


def _ctx(source_id, family, **kw):
    return ParseContext(repo_root=SEED, source_id=source_id, source_kind="agent_cli", family=family,
                        collected_at="2026-08-20T00:00:00Z", model_id="mdl",
                        prompt_sha256="a" * 64, **kw)


class _FakeProc:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


# --------------------------------------------------------------------------- #
# claude-security adapter (real renderer output)
# --------------------------------------------------------------------------- #


def test_claude_security_fixture_is_real_and_verified():
    sarif = json.load(open(CS_SARIF))
    meta = cs_adapter.run_meta(sarif)
    assert meta["verification_status"] == "verified" and meta["effort"] == "low"
    assert meta["plugin_version"] == "0.10.1" and meta["results"] == 5
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Claude Security Plugin for Claude Code"
    assert (CS_DIR / "CLAUDE-SECURITY-RESULTS.jsonl").is_file()
    assert (CS_DIR / "CLAUDE-SECURITY-REVISION-UNVERSIONED.json").is_file()


def test_claude_security_sarif_normalizes_with_panel_and_redaction():
    sarif = json.load(open(CS_SARIF))
    findings, meta = registry.normalize_claude_security(sarif, _ctx("claude-security", "claude"))
    assert len(findings) == 5
    by_cwe = {}
    for f in findings:
        m.assert_invariants(f)
        assert f.provenance[0].source_kind == "agent_cli" and f.rule.source == "claude-security"
        assert f.rule.id.startswith("claude-security/")
        by_cwe[f.taxonomy.cwe[0]] = f
    md5 = by_cwe["CWE-916"]
    assert md5.taxonomy.cwe_family == "crypto" and md5.severity.label == "high"
    assert md5.locations[0].uri == "app/crypto_util.py" and md5.locations[0].start_line == 7
    assert md5.locations[0].symbol == "hash_password"
    assert "Claude Security panel: 3/3 verifiers confirmed (confidence high)" in md5.description
    assert "Impact:" in md5.description and "Exploit scenario:" in md5.description
    assert md5.remediation and "argon2id" in md5.remediation.summary
    sfp = md5.fingerprints.source_fingerprints
    assert len(sfp["claude-security:claude-security-plugin/v2"]) == 64 and sfp["claude-security:claudeSecurity/id"] == "F1"
    idor = by_cwe["CWE-639"]
    assert idor.taxonomy.cwe_family == "authz" and idor.locations[0].uri == "app/order_repo.py"
    cred = by_cwe["CWE-798"]
    assert cred.taxonomy.cwe_family == "secrets"
    assert cred.locations[0].snippet is None or "wJa9Xr2L" not in (cred.locations[0].snippet or "")
    assert "wJa9Xr2L" not in cred.description
    cmdi = by_cwe["CWE-78"]
    assert cmdi.taxonomy.cwe_family == "injection"
    assert "2/3 verifiers confirmed (confidence medium)" in cmdi.description   # vote-clamped
    debug = by_cwe["CWE-489"]                                                    # uncategorized rule
    assert debug.severity.label == "low" and debug.rule.id == "claude-security/CWE-489"


def test_claude_security_adapter_strips_scan_prefix_and_tolerates_missing_record():
    sarif = json.load(open(CS_SARIF))
    run = sarif["runs"][0]
    run["properties"]["claudeSecurityPlugin"]["scan_prefix"] = "svc/api/"
    res = run["results"][0]
    res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "svc/api/app/crypto_util.py"
    res["properties"]["claudeSecurityPlugin"].pop("file")
    res["properties"]["claudeSecurityPlugin"].pop("line")
    raws, _ = cs_adapter.parse_sarif(sarif)
    assert raws[0].path == "app/crypto_util.py" and raws[0].start_line == 7


# --------------------------------------------------------------------------- #
# codex-security adapter (canonical bundle)
# --------------------------------------------------------------------------- #


def test_codex_security_fixture_validates_against_bundled_schema():
    schema = json.load(open(HERE / "fixtures" / "schemas" / "codex-security-findings.schema.json"))
    doc = json.load(open(CX_DIR / "findings.json"))
    jsonschema.validate(instance=doc, schema=schema)
    assert json.load(open(CX_DIR / "scan-manifest.json"))["scan"]["status"] == "completed"


def test_codex_security_bundle_normalizes():
    doc = json.load(open(CX_DIR / "findings.json"))
    manifest = json.load(open(CX_DIR / "scan-manifest.json"))
    coverage = json.load(open(CX_DIR / "coverage.json"))
    findings, meta = registry.normalize_codex_security(doc, _ctx("codex-security", "codex"),
                                                       manifest=manifest, coverage=coverage)
    assert meta["status"] == "completed" and meta["completeness"] == "complete" and meta["results"] == 4
    assert len(findings) == 4
    by_rule = {f.rule.id: f for f in findings}
    for f in findings:
        m.assert_invariants(f)
        assert f.rule.source == "codex-security"
    cmdi = by_rule["codex-security/command-injection.os-system"]
    # sink role wins over user_input as the primary location
    assert cmdi.locations[0].uri == "app/reports.py" and cmdi.locations[0].start_line == 11
    assert cmdi.severity.label == "critical" and cmdi.taxonomy.cwe_family == "injection"
    assert "Root cause:" in cmdi.description and "Codex Security confidence: high" in cmdi.description
    assert ("Validation: confirmed — Offline static source review "
            "with focused forward/backward dataflow confirmation." in cmdi.description)
    assert cmdi.locations[0].snippet and "os.system" in cmdi.locations[0].snippet
    idor = by_rule["codex-security/authorization.missing-object-ownership-check"]
    assert idor.taxonomy.cwe == ["CWE-639", "CWE-862"] and idor.taxonomy.cwe_family == "authz"
    secret = by_rule["codex-security/secrets.hardcoded-cloud-credential"]
    assert secret.taxonomy.cwe_family == "secrets"
    assert "AKIA" not in (secret.locations[0].snippet or "") and "wJa9" not in (secret.locations[0].snippet or "")
    info = by_rule["codex-security/configuration.debug-enabled"]
    assert info.severity.label == "info"


def test_codex_security_raw_keeps_semantic_fingerprints():
    doc = json.load(open(CX_DIR / "findings.json"))
    raws = cx_adapter.parse_findings(doc)
    fps = raws[0].source_fingerprints
    assert fps["codex-security/v1"].startswith("codex-security/v1:sha256:")
    assert fps["codexSecurity/findingId"].startswith("csf_") and fps["codexSecurity/anchor"]
    # and they survive into the canonical model, namespaced by source
    [f] = [x for x in registry.normalize_codex_security(doc, _ctx("codex-security", "codex"))[0]
           if x.rule.id == "codex-security/command-injection.os-system"]
    assert f.fingerprints.source_fingerprints["codex-security:codex-security/v1"] == fps["codex-security/v1"]


# --------------------------------------------------------------------------- #
# claude-security arm (faked `claude -p`)
# --------------------------------------------------------------------------- #


def _claude_stdout(*, is_error=False, subtype="success", cost=2.5, model="claude-fable-5"):
    return json.dumps({"type": "result", "subtype": subtype, "is_error": is_error, "total_cost_usd": cost,
                       "num_turns": 12, "result": "Report written.",
                       "modelUsage": {model: {"inputTokens": 10, "outputTokens": 5000, "costUSD": cost}}})


def _fake_claude(monkeypatch, *, stdout, plant_report=True, plant_unrendered=False, returncode=0):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        cwd = pathlib.Path(kw["cwd"])
        if plant_report or plant_unrendered:
            d = cwd / "CLAUDE-SECURITY-20260820-120000"
            d.mkdir()
            (d / ".gitignore").write_text("*\n")
            if plant_report:
                for f in CS_DIR.iterdir():
                    shutil.copy2(f, d / f.name)
            else:
                (d / ".claude-security-run").mkdir()
                (d / ".claude-security-run" / "findings.json").write_text("[]")
        return _FakeProc(returncode, stdout)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _scratch_target(tmp_path):
    tgt = tmp_path / "copy"
    shutil.copytree(SEED, tgt, ignore=shutil.ignore_patterns(".git", ".security-council", "__pycache__"))
    return tgt


def test_claude_security_arm_happy_path(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    calls = _fake_claude(monkeypatch, stdout=_claude_stdout())
    arm = ClaudeSecurityArm(effort="low", max_budget_usd=8, model="claude-fable-5")
    res = arm.run(tgt, tmp_path / "out", run_id="r1", collected_at="2026-08-20T00:00:00Z")
    assert res.ok, res.error
    assert len(res.findings) == 5 and all(f.provenance[0].source_id == "claude-security" for f in res.findings)
    assert res.findings[0].provenance[0].model_id == "claude-fable-5"
    assert res.findings[0].provenance[0].tool_version == "0.10.1"
    assert res.tool_version == "claude-fable-5"
    cov = res.coverage
    assert cov["raw_results"] == 5 and cov["normalized"] == 5 and cov["completion"] == "complete"
    assert cov["verification_status"] == "verified" and cov["cost_usd"] == 2.5 and cov["plugin_version"] == "0.10.1"
    # the plugin's report dir was moved OUT of the scanned tree into raw/
    assert not list(tgt.glob("CLAUDE-SECURITY-*"))
    moved = tmp_path / "out" / "raw" / "claude-security" / "CLAUDE-SECURITY-20260820-120000"
    assert (moved / "CLAUDE-SECURITY-RESULTS.sarif").is_file() and res.raw_path.endswith(".sarif")
    assert (tmp_path / "out" / "raw" / "claude-security" / "claude-result.json").is_file()
    # command shape: headless json, cost fuse, pinned model, gate-collapsing prompt
    cmd, kw = calls[0]
    assert cmd[:3] == ["claude", "-p", build_prompt(effort="low", scope=None)]
    assert "--max-budget-usd" in cmd and cmd[cmd.index("--max-budget-usd") + 1] == "8"
    assert "--dangerously-skip-permissions" in cmd and "--no-session-persistence" in cmd
    assert cmd[cmd.index("--model") + 1] == "claude-fable-5"
    assert kw["cwd"] == str(tgt) and kw["env"]["SECURITY_COUNCIL_NESTED"] == "1"
    prompt = cmd[2]
    assert "scan-codebase --effort low" in prompt and "whole repository" in prompt
    assert "significant number of tokens" in prompt      # the cost acknowledgment that collapses the gate
    assert "<prompt>" in res.command                      # manifest command is redacted


def test_claude_security_prompt_carries_scope():
    p = build_prompt(effort="medium", scope=["app", "lib"])
    assert "--scope app,lib" in p and "scan only these directories: app, lib" in p


def test_claude_security_budget_exhausted_without_report_is_failure(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    _fake_claude(monkeypatch, stdout=_claude_stdout(is_error=True, subtype="error_max_budget_usd", cost=3.01),
                 plant_report=False, plant_unrendered=True)
    res = ClaudeSecurityArm(effort="low", max_budget_usd=3).run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok
    assert "no report rendered (error_max_budget_usd; cost $3.01)" in res.error
    assert "salvaged" in res.error
    assert res.coverage["cost_usd"] == 3.01 and res.coverage["classifier_fallback"] is False
    assert not list(tgt.glob("CLAUDE-SECURITY-*"))       # still cleaned out of the tree


def test_claude_security_model_substitution_fails_loudly(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    _fake_claude(monkeypatch, stdout=_claude_stdout(model="claude-opus-4-8"))
    res = ClaudeSecurityArm(model="claude-fable-5").run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "model_substituted" in res.error and res.coverage["classifier_fallback"] is True


def test_claude_security_unverified_report_is_partial_and_unverified_when_empty(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    # plant a report whose stamp says unverified and has no results
    sarif = json.load(open(CS_SARIF))
    sarif["runs"][0]["results"] = []
    sarif["runs"][0]["properties"]["claudeSecurityPlugin"]["verification"] = {
        "status": "unverified", "reason": "votes.json is absent"}

    def fake_run(cmd, **kw):
        d = pathlib.Path(kw["cwd"]) / "CLAUDE-SECURITY-20260820-130000"
        d.mkdir()
        (d / "CLAUDE-SECURITY-RESULTS.sarif").write_text(json.dumps(sarif))
        return _FakeProc(0, _claude_stdout())
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ClaudeSecurityArm().run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and res.findings == []
    assert res.coverage["completion"] == "partial" and res.coverage["coverage_unverified"] is True
    assert res.coverage["verification_reason"] == "votes.json is absent"


def test_claude_security_available_needs_cli_and_plugin(monkeypatch):
    arm = ClaudeSecurityArm()
    monkeypatch.setattr(shutil, "which", lambda c: None)
    assert arm.available()[0] is False
    monkeypatch.setattr(shutil, "which", lambda c: "/usr/bin/claude")
    monkeypatch.setattr(ClaudeSecurityArm, "plugin_dirs", lambda self: [])
    ok, why = arm.available()
    assert ok is False and "claude plugin install" in why
    monkeypatch.setattr(ClaudeSecurityArm, "plugin_dirs", lambda self: ["/x/claude-security/0.10.1"])
    ok, why = arm.available()
    assert ok is True and "0.10.1" in why


# --------------------------------------------------------------------------- #
# codex-security arm (faked CLI)
# --------------------------------------------------------------------------- #


def _codex_stdout(model="gpt-5.6-sol", cost=3.9):
    return ("[00:00] Preparing scan\n[07:30] Scan complete\n" +
            json.dumps({"scanDir": "/tmp/x", "turnResult": {"model": model, "status": "completed"},
                        "cost": {"totalUsd": cost, "inputTokens": 100}, "sarifPath": None,
                        "manifest": {"scan": {"id": "scan_seedrepo_fixture_001"}}}))


def _fake_codex(monkeypatch, *, stdout, stderr="", plant=True, returncode=0, nested=False):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if cmd[-1] == "--version":
            return _FakeProc(0, "0.1.16\n")
        out = pathlib.Path(cmd[cmd.index("--output-dir") + 1])
        assert out.is_dir() and stat.S_IMODE(out.stat().st_mode) == 0o700
        if plant:
            dest = out / "scan_seedrepo_fixture_001" if nested else out
            dest.mkdir(parents=True, exist_ok=True)
            for f in CX_DIR.iterdir():
                if f.is_file():
                    shutil.copy2(f, dest / f.name)
            (dest / "exports").mkdir(exist_ok=True)
            (dest / "exports" / "results.sarif").write_text('{"version":"2.1.0","runs":[]}')
        return _FakeProc(returncode, stdout, stderr)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("SECURITY_COUNCIL_CODEX_SECURITY_CMD", "codex-security")
    return calls


def test_codex_security_arm_happy_path(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    calls = _fake_codex(monkeypatch, stdout=_codex_stdout(), nested=True)
    arm = CodexSecurityArm(mode="standard", max_cost_usd=5, model="gpt-5.6-sol", scope=["app"])
    res = arm.run(tgt, tmp_path / "out", run_id="r1", collected_at="2026-08-20T00:00:00Z")
    assert res.ok, res.error
    assert len(res.findings) == 4 and res.tool_version == "gpt-5.6-sol"
    assert res.findings[0].provenance[0].model_id == "gpt-5.6-sol"
    assert res.findings[0].provenance[0].tool_version == "0.1.22"          # bundled plugin (producer)
    cov = res.coverage
    assert cov["raw_results"] == 4 and cov["normalized"] == 4 and cov["completion"] == "complete"
    assert cov["cost_usd"] == 3.9 and cov["status"] == "completed" and cov["scan_id"] == "scan_seedrepo_fixture_001"
    raw = tmp_path / "out" / "raw" / "codex-security"
    for n in ("findings.json", "scan-manifest.json", "coverage.json", "report.md",
              "codex-security-result.json"):
        assert (raw / n).is_file(), n
    assert (raw / "exports" / "results.sarif").is_file()
    cmd, kw = calls[0]
    assert cmd[0] == "codex-security" and cmd[1:3] == ["scan", str(tgt)]
    assert "--headless" in cmd and cmd[cmd.index("--format") + 1] == "json"
    assert cmd[cmd.index("--max-cost") + 1] == "5" and cmd[cmd.index("--mode") + 1] == "standard"
    assert cmd[cmd.index("--model") + 1] == "gpt-5.6-sol" and cmd[cmd.index("--path") + 1] == "app"
    out_dir = pathlib.Path(cmd[cmd.index("--output-dir") + 1])
    assert not str(out_dir).startswith(str(tgt))           # outside the scanned tree (tool requirement)
    assert not out_dir.exists()                             # private temp dir removed afterwards
    assert kw["cwd"] == str(tgt) and kw["env"]["SECURITY_COUNCIL_NESTED"] == "1"


LIVE_CODEX_STDERR = (
    "[00:11] Scan phase: enumerating files (0/9 files).\n"
    "[10:38] Running scan: reviewing files | Files: 9/9 | Tokens: 2,302,727 input, "
    "2,059,776 cached, 48,119 output | Cost: $3.688213\n"
    "[18:13] Estimated cost: $5.429646 of $5.00 limit\n"
    "Scan stopped: estimated cost $5.429646 exceeded the $5.00 limit; "
    "partial output remains at /tmp/security-council-codexsec-xyz.\n"
)


def test_codex_security_live_shape_empty_stdout_cost_from_stderr(monkeypatch, tmp_path):
    # observed live 2026-08-21 (CLI 0.1.16): stdout is EMPTY, progress + cost go to
    # stderr, and a cost-stop can land after the bundle sealed complete.
    tgt = _scratch_target(tmp_path)
    _fake_codex(monkeypatch, stdout="", stderr=LIVE_CODEX_STDERR, returncode=2)
    res = CodexSecurityArm().run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and len(res.findings) == 4
    cov = res.coverage
    assert cov["cost_usd"] == 5.429646 and cov["cost_stopped"] is True
    assert cov["model_unattested"] is True and res.tool_version is None
    assert cov["completion"] == "complete" and cov["exit_code"] == 2
    raw = tmp_path / "out" / "raw" / "codex-security"
    assert (raw / "stderr.log").read_text() == LIVE_CODEX_STDERR
    saved = json.loads((raw / "codex-security-result.json").read_text())
    assert set(saved) == {"stdout", "stderr"}          # fallback envelope, no JSON on stdout


def test_codex_security_no_bundle_is_failure_and_cleans_up(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    calls = _fake_codex(monkeypatch, stdout="", plant=False, returncode=2)
    res = CodexSecurityArm().run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "no sealed scan bundle (exit 2)" in res.error
    out_dir = pathlib.Path(calls[0][0][calls[0][0].index("--output-dir") + 1])
    assert not out_dir.exists()


def test_codex_security_partial_bundle_is_partial(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)

    def fake_run(cmd, **kw):
        out = pathlib.Path(cmd[cmd.index("--output-dir") + 1])
        for f in CX_DIR.iterdir():
            if f.is_file():
                shutil.copy2(f, out / f.name)
        cov = json.load(open(out / "coverage.json"))
        cov["completeness"] = "partial"
        (out / "coverage.json").write_text(json.dumps(cov))
        return _FakeProc(2, _codex_stdout())
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("SECURITY_COUNCIL_CODEX_SECURITY_CMD", "codex-security")
    res = CodexSecurityArm().run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and len(res.findings) == 4
    assert res.coverage["completion"] == "partial" and res.coverage["completeness"] == "partial"


def test_codex_security_model_substitution_fails_loudly(monkeypatch, tmp_path):
    tgt = _scratch_target(tmp_path)
    _fake_codex(monkeypatch, stdout=_codex_stdout(model="gpt-5.6-terra"))
    res = CodexSecurityArm(model="daybreak-blue-latest").run(tgt, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "model_substituted" in res.error and res.coverage["classifier_fallback"] is True


def test_codex_security_resolves_cached_npx_package_without_installing(monkeypatch, tmp_path):
    from security_council.arms import codex_security as cx
    monkeypatch.delenv("SECURITY_COUNCIL_CODEX_SECURITY_CMD", raising=False)
    monkeypatch.setattr(shutil, "which", lambda c: "/usr/bin/node" if c == "node" else None)
    for ver in ("0.1.9", "0.1.16"):
        pkg = tmp_path / ver / "node_modules" / "@openai" / "codex-security"
        (pkg / "bin").mkdir(parents=True)
        (pkg / "bin" / "codex-security.mjs").write_text("")
        (pkg / "package.json").write_text(json.dumps({"version": ver}))
    monkeypatch.setattr(cx, "_NPX_CACHE_GLOB", str(tmp_path / "*" / "node_modules" / "@openai" / "codex-security"))
    cmd = cx.resolve_command()
    assert cmd[0] == "/usr/bin/node" and cmd[1].endswith("0.1.16/node_modules/@openai/codex-security/bin/codex-security.mjs")
    assert "npx" not in " ".join(cmd)                      # never auto-installs at scan time
    monkeypatch.setattr(cx, "_NPX_CACHE_GLOB", str(tmp_path / "nothing" / "*"))
    assert cx.resolve_command() is None
    ok, why = CodexSecurityArm().available()
    assert ok is False and "npm install -g @openai/codex-security" in why


def test_codex_security_available_uses_version_probe(monkeypatch):
    monkeypatch.setenv("SECURITY_COUNCIL_CODEX_SECURITY_CMD", "codex-security")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _FakeProc(0, "0.1.16\n"))
    ok, why = CodexSecurityArm().available()
    assert ok and "0.1.16" in why
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _FakeProc(1, "", "not found"))
    assert CodexSecurityArm().available()[0] is False


# --------------------------------------------------------------------------- #
# registry / config plumbing
# --------------------------------------------------------------------------- #


def test_registry_builds_dedicated_arms_from_options():
    assert {"claude-security", "codex-security"} <= set(known_arms())
    a = build_arm("claude-security", options={"effort": "medium", "max_budget_usd": 12, "model": "claude-fable-5"})
    assert isinstance(a, ClaudeSecurityArm) and a.effort == "medium" and a.max_budget_usd == 12 and a.model == "claude-fable-5"
    b = build_arm("codex-security", options={"mode": "deep", "max_cost_usd": 20, "max_time_hours": 1.5})
    assert isinstance(b, CodexSecurityArm) and b.mode == "deep" and b.max_time_hours == 1.5
    assert build_arm("semgrep", options={"ignored": True}).name == "semgrep"


def test_cli_passes_arm_options_from_config(monkeypatch, tmp_path):
    from security_council import cli
    (tmp_path / ".security-council.yaml").write_text(
        "arms:\n  options:\n    claude-security: {effort: high, max_budget_usd: 2}\n")
    captured = {}

    def fake_run_scan(target, arms, config, **kw):
        captured["arms"] = arms
        raise SystemExit(0)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    try:
        cli.main(["scan", str(tmp_path), "--arms", "claude-security"])
    except SystemExit:
        pass
    [arm] = captured["arms"]
    assert arm.effort == "high" and arm.max_budget_usd == 2


def test_fixture_dirs_are_not_secret_bearing():
    # the seedrepo's fake AWS secret must not leak into committed fixture products
    for p in list(CS_DIR.iterdir()) + list(CX_DIR.iterdir()):
        if p.is_file():
            assert "wJa9Xr2LtDq7Fh0PkVbN3cMz8sQ1yUeR6gT4iOm" not in p.read_text(errors="replace"), p
