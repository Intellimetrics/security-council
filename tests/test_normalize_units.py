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
    assert to_repo_relative("app\\x.py", repo_root="/repo") == "app/x.py"


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
