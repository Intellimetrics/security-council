"""P2 unit tests for the normalization primitives."""
import pathlib

from security_council import model as m
from security_council.normalize import cwe as ncwe
from security_council.normalize import severity as nsev
from security_council.normalize import snippets as nsnip
from security_council.normalize.cwe_table import CWE_BY_SOURCE_RULE
from security_council.normalize.paths import to_repo_relative

FIX = pathlib.Path(__file__).parent / "fixtures" / "seedrepo"


# --- paths ---

def test_path_strips_scan_mount_and_repo_root():
    assert to_repo_relative("/src/app/x.py", repo_root="/repo", scan_root="/src") == "app/x.py"
    assert to_repo_relative("/repo/app/x.py", repo_root="/repo") == "app/x.py"
    assert to_repo_relative("file:///src/a%20b.py", repo_root="/repo", scan_root="/src") == "a b.py"
    assert to_repo_relative("./app/x.py", repo_root="/repo") == "app/x.py"
    # R15: a backslash is a separator only on Windows or in a Windows-shaped
    # path; on POSIX `app\\x.py` is a different file from `app/x.py`, and the
    # scanned repo must not be able to alias one file onto another.
    assert to_repo_relative("C:\\repo\\app\\x.py", repo_root="C:\\repo") == "app/x.py"
    assert to_repo_relative("\\\\srv\\share\\app\\x.py", repo_root="//srv/share") == "app/x.py"
    assert to_repo_relative("app\\x.py", repo_root="/repo") == "app\\x.py"
    # R15b: an absolute path no configured base explains stays absolute, so I1
    # refuses it — it is never made "relative" onto a tree the repo could contain
    from security_council.model import _URI_RE
    for bad in ("C:\\src\\app.py", "\\\\srv\\share\\app.py", "/etc/passwd", "C:/src/app.py"):
        out = to_repo_relative(bad, repo_root="/repo", scan_root="/src")
        assert not _URI_RE.match(out), (bad, out)
    assert to_repo_relative("/etc/passwd", repo_root="/repo") == "/etc/passwd"
    assert to_repo_relative("C:\\src\\app.py", repo_root="/repo") == "C:/src/app.py"
    assert to_repo_relative("/src/app\\x.py", repo_root="/repo", scan_root="/src") == "app\\x.py"


# --- snippets ---

def test_capture_reads_real_lines_and_hashes():
    s = nsnip.capture("app/crypto_util.py", 6, 7, repo_root=FIX)
    assert s is not None and len(s.sha256) == 64 and s.raw_context
    assert "md5" in s.text


def test_capture_missing_file_or_range_is_none():
    assert nsnip.capture("app/nope.py", 1, 1, repo_root=FIX) is None
    assert nsnip.capture("app/crypto_util.py", 99999, 99999, repo_root=FIX) is None


def test_capture_rejects_traversal():
    assert nsnip.capture("../../../etc/passwd", 1, 1, repo_root=FIX) is None


def test_capture_redacts_text_but_keeps_hash():
    s = nsnip.capture("app/settings.py", 2, 2, repo_root=FIX, redact=True)
    assert s is not None and s.text == "" and len(s.sha256) == 64


# --- cwe ---

def test_cwe_exact_from_declared():
    a = ncwe.normalize_cwe(source_id="x", rule_id=None, declared_cwe=["CWE-89"],
                           category=None, title="", description="")
    assert a.cwe == ["CWE-89"] and a.family == "injection" and a.confidence == "exact"


def test_cwe_mapped_from_rule_table():
    a = ncwe.normalize_cwe(source_id="gitleaks", rule_id="aws-access-token", declared_cwe=[],
                           category="secrets", title="", description="")
    assert a.cwe == ["CWE-798"] and a.family == "secrets" and a.confidence == "mapped"


def test_cwe_heuristic_from_rule_then_prose():
    a = ncwe.normalize_cwe(source_id="x", rule_id="py.sql-injection.raw", declared_cwe=[],
                           category=None, title="", description="")
    assert a.cwe == ["CWE-89"] and a.confidence == "heuristic"
    b = ncwe.normalize_cwe(source_id="x", rule_id=None, declared_cwe=[], category=None,
                           title="Weak MD5 hashing", description="uses md5 for passwords")
    assert b.family == "crypto" and b.confidence == "heuristic"


def test_cwe_none_falls_back_to_category_family():
    a = ncwe.normalize_cwe(source_id="x", rule_id=None, declared_cwe=[], category="llm_safety",
                           title="prompt thing", description="nondescript")
    assert a.cwe == ["CWE-noinfo"] and a.family == "llm_safety" and a.confidence == "none"


def test_cwe_crypto_sticky_from_declared():
    a = ncwe.normalize_cwe(source_id="x", rule_id=None, declared_cwe=["CWE-79", "CWE-327"],
                           category=None, title="", description="")
    assert a.family == "crypto"


# --- severity ---

def test_severity_numeric_banding():
    assert nsev.normalize_severity(source_id="s", numeric_severity=9.1).label == "critical"
    assert nsev.normalize_severity(source_id="s", numeric_severity=7.0).label == "high"
    assert nsev.normalize_severity(source_id="s", numeric_severity=4.0).label == "medium"
    assert nsev.normalize_severity(source_id="s", numeric_severity=0.5).label == "low"


def test_severity_semgrep_vocab_and_secret_default():
    assert nsev.normalize_severity(source_id="semgrep", raw_label="ERROR").label == "high"
    assert nsev.normalize_severity(source_id="gitleaks", raw_label=None, cwe_family="secrets").label == "high"
    s = nsev.normalize_severity(source_id="s", raw_label="high")
    assert s.sarif_level == m.SEVERITY_TO_SARIF_LEVEL[s.label]


# --- table integrity ---

def test_cwe_by_source_rule_values_are_valid_and_mapped():
    for (src, rule), cwe in CWE_BY_SOURCE_RULE.items():
        assert m._CWE_RE.match(m.canonical_cwe(cwe)), f"{cwe} malformed"
        assert m.family_for_cwe(cwe) is not None, f"{cwe} not in CWE_TO_FAMILY"


def test_xpath_injection_maps_to_injection_family():
    # R7: CWE-643 joined CWE_TO_FAMILY (its own trust-surface change). It must
    # pool with the other injection CWEs and stay out of the crypto carve-out.
    assert m.family_for_cwe("CWE-643") == "injection"
    assert m.canonical_cwe("CWE-643") not in m.CRYPTO_CWES


def test_backslash_named_posix_file_is_dropped_as_invalid_never_aliased(tmp_path):
    """R15 (reproduced live): a committed file literally named `app\\x.py` used
    to normalize onto `app/x.py` — its findings merged into the other file's
    location (invisible in the report) and read `unchanged` to the baseline.
    Now the uri keeps its backslash, I1 refuses it, the finding is DROPPED and
    counted (partial_coverage → exit 3): degraded, never silently clean."""
    from security_council.normalize import registry
    from security_council.normalize.base import ParseContext
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("a = 1\nb = eval(a)\n")
    (tmp_path / "app\\x.py").write_text("a = 1\nb = eval(a)\n")
    rule = {"id": "r", "properties": {"tags": ["CWE-89: SQL Injection", "security"]}}
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [rule]}},
             "results": [{"ruleId": "r", "level": "error", "message": {"text": "t"},
                          "locations": [{"physicalLocation": {
                              "artifactLocation": {"uri": u},
                              "region": {"startLine": 2, "endLine": 2}}}]}
                         for u in ("/src/app/x.py", "/src/app\\x.py")]}]}
    ctx = ParseContext(repo_root=tmp_path, scan_root="/src", source_id="semgrep",
                       source_kind="scanner", family="semgrep", tool_version="1.0",
                       run_id="r", collected_at="2026-08-27T00:00:00Z")
    out = registry.normalize_sarif(sarif, "semgrep", ctx)
    assert [loc.uri for f in out for loc in f.locations] == ["app/x.py"]
    assert dict(ctx.skipped) == {"invalid:I1": 1}


def test_partial_reason_names_the_drop_kind():
    from security_council.arms.base import ArmResult
    from security_council.orchestrator import _partial_reason
    r = ArmResult(name="semgrep", kind="scanner", family="semgrep", ok=True, exit_code=0,
                  error="", findings=[], coverage={"raw_results": 5, "normalized": 3,
                                                   "skipped": {"invalid:I1": 2}})
    txt = _partial_reason(r)
    assert "2 dropped" in txt and "invalid:I1 ×2" in txt and "backslash" in txt
    r.coverage = {"raw_results": 5, "normalized": 3}          # older arms: no breakdown
    assert "unresolvable location" in _partial_reason(r)


def test_dedicated_adapters_do_not_fold_backslashes():
    """R15b (codex + claude, independently): the codex-security and
    claude-security adapters folded `\\`→`/` before the shared boundary, so the
    `app\\x.py` alias survived through those two arms."""
    from security_council.normalize.sources import claude_security, codex_security
    doc = {"findings": [{"ruleId": "r", "title": "t", "severity": "high",
                         "locations": [{"path": "app\\x.py", "line": 2, "role": "sink"}],
                         "taxonomy": {"cwe": ["CWE-89"]}}]}
    raws = codex_security.parse_findings(doc)
    assert raws and raws[0].path == "app\\x.py"
    sarif = {"runs": [{"tool": {"driver": {"name": "claude-security"}},
                       "results": [{"ruleId": "r", "message": {"text": "t"},
                                    "locations": [{"physicalLocation": {
                                        "artifactLocation": {"uri": "app\\x.py"},
                                        "region": {"startLine": 2}}}]}]}]}
    raws, _ = claude_security.parse_sarif(sarif)
    assert raws and raws[0].path == "app\\x.py"
    from security_council.patches import _rel
    assert _rel("app\\x.py") == "app\\x.py" and _rel("/app/x.py") == "app/x.py"
