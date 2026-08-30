"""LLM-CLI arm tests with a faked subprocess (no real CLIs)."""
import json
import pathlib
import subprocess

import pytest

from security_council import model as m
from security_council.arms.llm_cli import LlmCliArm
from security_council.arms.registry import build_arm

FIX = pathlib.Path(__file__).parent / "fixtures" / "seedrepo"


class _FakeProc:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _envelope(findings, completion="complete"):
    return {"schema_version": "sc-agent-finding/1",
            "scan": {"angle": "crypto", "completion": completion, "files_examined": [],
                     "coverage_notes": "", "declined_categories": []},
            "findings": findings}


_CRYPTO_FINDING = {
    "local_id": "F1", "title": "MD5 password hash", "description": "unsalted md5",
    "cwe": ["CWE-916"], "category": "crypto", "severity": "high", "confidence": "high",
    "locations": [{"path": "app/crypto_util.py", "start_line": 6, "end_line": 7, "role": "primary",
                   "symbol": "hash_password", "snippet": "hashlib.md5(pw)"}],
    "data_flow": [], "entry_point": "/api/register", "exploit_precondition": "hash store leak",
    "remediation": "argon2", "evidence": [{"path": "app/crypto_util.py", "start_line": 6,
                                            "end_line": 7, "claim": "md5"}]}


def _patch(monkeypatch, stdout, *, returncode=0, last_file_content=None):
    def fake_run(cmd, **kw):
        if last_file_content is not None and "-o" in cmd:
            out_path = pathlib.Path(cmd[cmd.index("-o") + 1])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(last_file_content)
        return _FakeProc(returncode, stdout)
    monkeypatch.setattr(subprocess, "run", fake_run)


def _run(name, monkeypatch, tmp_path, **kw):
    _patch(monkeypatch, **kw)
    return LlmCliArm(name, model=kw.pop("model", None)).run(
        FIX, tmp_path, run_id="r", collected_at="2026-08-20T00:00:00Z")


def test_claude_envelope_normalizes(monkeypatch, tmp_path):
    stdout = json.dumps({"result": json.dumps(_envelope([_CRYPTO_FINDING])),
                         "model": "claude-fable-5", "is_error": False})
    res = _run("claude", monkeypatch, tmp_path, stdout=stdout)
    assert res.ok and len(res.findings) == 1
    f = res.findings[0]
    m.assert_invariants(f)
    assert f.taxonomy.cwe_family == "crypto"
    assert f.provenance[0].source_kind == "agent_cli"
    assert f.provenance[0].model_id == "claude-fable-5"


def test_agy_soft_deny_is_failure(monkeypatch, tmp_path):
    secret = "github_pat_0123456789abcdefghijklmnopqrstuvwxyz"
    stdout = json.dumps({"status": "CANCELED", "structured_output": None,
                         "diagnostic": secret})
    res = _run("agy", monkeypatch, tmp_path, stdout=stdout)      # exit 0 but not SUCCESS
    assert not res.ok and "CANCELED" in res.error
    diagnostic = pathlib.Path(res.raw_path).read_text()
    assert secret not in diagnostic and "<redacted>" in diagnostic


def test_agy_success_but_no_structured_output(monkeypatch, tmp_path):
    stdout = json.dumps({"status": "SUCCESS", "structured_output": None})
    res = _run("agy", monkeypatch, tmp_path, stdout=stdout)
    assert not res.ok and "no structured output" in res.error


def test_house_arm_options_reach_vendor_commands(tmp_path):
    claude = build_arm("claude", options={"model": "fable", "effort": "high",
                                          "max_budget_usd": 12,
                                          "fallback_model": "claude-opus-5"})
    ccmd = claude.spec.build_cmd(claude, "review", FIX, tmp_path)
    assert ccmd[ccmd.index("--model") + 1] == "fable"
    assert ccmd[ccmd.index("--effort") + 1] == "high"
    assert ccmd[ccmd.index("--max-budget-usd") + 1] == "12"
    assert ccmd[ccmd.index("--fallback-model") + 1] == "claude-opus-5"

    agy = build_arm("agy", options={"model": "gemini-3.7-flash-high", "effort": "high"})
    acmd = agy.spec.build_cmd(agy, "review", FIX, tmp_path)
    assert acmd[acmd.index("--model") + 1] == "gemini-3.7-flash-high"
    assert acmd[acmd.index("--effort") + 1] == "high"


def test_house_arm_options_fail_closed():
    with pytest.raises(ValueError, match="invalid effort"):
        build_arm("agy", options={"effort": "maximum"})
    with pytest.raises(ValueError, match="positive"):
        build_arm("claude", options={"max_budget_usd": 0})


def test_model_substitution_fails_loudly(monkeypatch, tmp_path):
    stdout = json.dumps({"result": json.dumps(_envelope([_CRYPTO_FINDING])),
                         "model": "claude-opus-4-8", "is_error": False})
    _patch(monkeypatch, stdout)
    res = LlmCliArm("claude", model="claude-mythos-5").run(
        FIX, tmp_path, run_id="r", collected_at="t")
    assert not res.ok and "model_substituted" in res.error
    assert res.coverage["classifier_fallback"] is True


def test_empty_findings_partial_is_coverage_unverified(monkeypatch, tmp_path):
    stdout = json.dumps({"result": json.dumps(_envelope([], completion="partial")),
                         "model": "claude-fable-5", "is_error": False})
    res = _run("claude", monkeypatch, tmp_path, stdout=stdout)
    assert res.findings == []
    assert res.coverage["coverage_unverified"] is True
    # R12: NOT ok. It used to be, so arms that declined every category still
    # counted toward min_arms_ok and a run of only such arms exited 0 = clean.
    assert res.ok is False
    assert "NOT clean" in res.error


def test_empty_findings_complete_is_clean(monkeypatch, tmp_path):
    stdout = json.dumps({"result": json.dumps(_envelope([], completion="complete")),
                         "model": "claude-fable-5", "is_error": False})
    res = _run("claude", monkeypatch, tmp_path, stdout=stdout)
    assert res.ok and res.findings == []
    assert "coverage_unverified" not in res.coverage


def test_codex_reads_last_message_file(monkeypatch, tmp_path):
    env = json.dumps(_envelope([_CRYPTO_FINDING]))
    res = _run("codex", monkeypatch, tmp_path, stdout="{}", last_file_content=env)
    assert res.ok and len(res.findings) == 1
    assert res.findings[0].taxonomy.cwe_family == "crypto"
