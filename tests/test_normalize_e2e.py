"""P2 end-to-end: real S6 scanner SARIF -> Finding -> cluster."""
import json
import pathlib

from security_council import cluster as cl
from security_council import model as m
from security_council.normalize import registry
from security_council.normalize.base import ParseContext

HERE = pathlib.Path(__file__).parent
FIX = HERE / "fixtures" / "seedrepo"
RAW = HERE / "fixtures" / "raw"


def _ctx(source_id, family):
    return ParseContext(repo_root=FIX, scan_root="/src", source_id=source_id,
                        source_kind="scanner", family=family, tool_version="test",
                        collected_at="2026-08-20T00:00:00Z")


def _load(name):
    return json.load(open(RAW / f"{name}.sarif"))


def test_semgrep_sqli_normalizes():
    fs = registry.normalize_sarif(_load("semgrep"), "semgrep", _ctx("semgrep", "semgrep"))
    assert len(fs) == 2
    for f in fs:
        m.assert_invariants(f)
        assert "CWE-89" in f.taxonomy.cwe and f.taxonomy.cwe_family == "injection"
        assert f.locations[0].uri == "app/reports.py"
        assert f.corroboration.deterministic_sources == ["semgrep"]


def test_gitleaks_secret_is_redacted():
    fs = registry.normalize_sarif(_load("gitleaks"), "gitleaks", _ctx("gitleaks", "gitleaks"))
    assert len(fs) >= 1
    for f in fs:
        m.assert_invariants(f)
        assert f.taxonomy.cwe_family == "secrets"
        assert f.locations[0].uri == "app/settings.py"
        assert f.locations[0].snippet is None            # redacted, but hashed
        assert len(f.locations[0].snippet_sha256) == 64


def test_osv_supply_chain():
    fs = registry.normalize_sarif(_load("osv"), "osv-scanner", _ctx("osv-scanner", "osv"))
    assert len(fs) >= 1
    for f in fs:
        m.assert_invariants(f)
        assert f.taxonomy.cwe_family == "supply_chain"
        assert f.package is not None


def test_full_pipeline_normalize_then_cluster():
    findings = []
    findings += registry.normalize_sarif(_load("semgrep"), "semgrep", _ctx("semgrep", "semgrep"))
    findings += registry.normalize_sarif(_load("gitleaks"), "gitleaks", _ctx("gitleaks", "gitleaks"))
    findings += registry.normalize_sarif(_load("osv"), "osv-scanner", _ctx("osv-scanner", "osv"))
    assert len(findings) >= 5
    clusters = cl.cluster_findings(findings)
    assert 1 <= len(clusters) <= len(findings)
    for c in clusters:
        m.assert_invariants(cl.merge_cluster(c))
    # the two semgrep SQLi at reports.py:9 collapse into one injection cluster
    inj = [c for c in clusters if c.representative.taxonomy.cwe_family == "injection"]
    assert inj and any(len(c.members) == 2 for c in inj)


def test_agent_envelope_normalizes():
    env = {
        "schema_version": "sc-agent-finding/1",
        "scan": {"angle": "crypto", "completion": "complete", "files_examined": ["app/crypto_util.py"],
                 "coverage_notes": "", "declined_categories": []},
        "findings": [{
            "local_id": "F1", "title": "MD5 password hash",
            "description": "unsalted md5 for passwords", "cwe": ["CWE-916"], "category": "crypto",
            "severity": "high", "confidence": "high",
            "locations": [{"path": "app/crypto_util.py", "start_line": 6, "end_line": 7,
                           "role": "primary", "symbol": "hash_password", "snippet": "hashlib.md5(pw)"}],
            "data_flow": [], "entry_point": "/api/register",
            "exploit_precondition": "attacker obtains the hash store", "remediation": "use argon2",
            "evidence": [{"path": "app/crypto_util.py", "start_line": 6, "end_line": 7, "claim": "md5"}],
        }],
    }
    ctx = ParseContext(repo_root=FIX, source_id="house", source_kind="agent_cli", family="claude",
                       model_id="claude-fable-5",
                       prompt_sha256=__import__("hashlib").sha256(b"p").hexdigest(),
                       collected_at="2026-08-20T00:00:00Z")
    findings, meta = registry.normalize_envelope(env, ctx)
    assert len(findings) == 1
    f = findings[0]
    m.assert_invariants(f)
    assert f.taxonomy.cwe_family == "crypto" and f.taxonomy.cwe_confidence == "exact"
    assert f.corroboration.agent_sources == ["house"]
    assert meta["completion"] == "complete"
