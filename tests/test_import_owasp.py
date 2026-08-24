"""OWASP Benchmark importer: converter-only parsing, integrity checks, matcher shape.

Fixtures here are SELF-AUTHORED mini-benchmarks that mimic only the *format*
(CSV columns + testcode layout) — no BenchmarkJava (GPL-2.0) content is copied.
"""

import pytest

from security_council.eval import import_owasp as io_
from security_council.eval import metrics

CSV_NAME = "expectedresults-1.2.csv"
HEADER = "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"

ROWS = [
    ("BenchmarkTest00001", "sqli", "true", "89"),
    ("BenchmarkTest00002", "sqli", "false", "89"),
    ("BenchmarkTest00003", "crypto", "true", "327"),
    ("BenchmarkTest00004", "trustbound", "false", "501"),   # unmapped family
]


def write_benchmark(root, rows=ROWS, skip_files=()):
    tc = root / io_.TESTCODE_DIR
    tc.mkdir(parents=True)
    lines = [HEADER]
    for name, cat, real, cwe in rows:
        lines.append(f"{name},{cat},{real},{cwe}\n")
        if name not in skip_files:
            (tc / f"{name}.java").write_text(f"// self-authored fixture {name}\n")
    (root / CSV_NAME).write_text("".join(lines))
    return root


def test_load_cases_parses_labels_cwes_families(tmp_path):
    cases, meta = io_.load_cases(write_benchmark(tmp_path))
    assert [c.id for c in cases] == [r[0] for r in ROWS]
    by_id = {c.id: c for c in cases}
    assert by_id["BenchmarkTest00001"].real is True
    assert by_id["BenchmarkTest00002"].real is False
    assert by_id["BenchmarkTest00001"].cwe == "CWE-89"
    assert by_id["BenchmarkTest00001"].family == "injection"
    assert by_id["BenchmarkTest00003"].family == "crypto"
    assert by_id["BenchmarkTest00004"].family is None          # CWE-501 unmapped
    assert by_id["BenchmarkTest00001"].path == f"{io_.TESTCODE_DIR}/BenchmarkTest00001.java"
    assert meta["corpus"] == io_.CORPUS_NAME
    assert meta["version"] == "1.2"
    assert meta["cases_total"] == 4 and meta["cases_true"] == 2 and meta["cases_false"] == 2
    assert meta["categories"]["sqli"] == {"cwe": "CWE-89", "family": "injection",
                                          "true": 1, "false": 1}
    assert meta["git_sha"] is None                             # tmp dir is not a git repo


def test_missing_test_file_is_fatal(tmp_path):
    write_benchmark(tmp_path, skip_files=("BenchmarkTest00003",))
    with pytest.raises(io_.BenchmarkImportError, match="1 of 4 test files missing"):
        io_.load_cases(tmp_path)


def test_no_csv_and_ambiguous_csv_are_fatal(tmp_path):
    with pytest.raises(io_.BenchmarkImportError, match="no expectedresults"):
        io_.load_cases(tmp_path)
    write_benchmark(tmp_path)
    (tmp_path / "expectedresults-1.1.csv").write_text(HEADER)
    with pytest.raises(io_.BenchmarkImportError, match="ambiguous"):
        io_.load_cases(tmp_path)


def test_empty_csv_is_fatal(tmp_path):
    (tmp_path / CSV_NAME).write_text(HEADER)
    with pytest.raises(io_.BenchmarkImportError, match="no BenchmarkTest rows"):
        io_.load_cases(tmp_path)


def test_ground_truth_shape_feeds_the_eval_matcher(tmp_path):
    from tests.test_cluster import mk
    cases, _ = io_.load_cases(write_benchmark(tmp_path))
    expected = io_.ground_truth(cases)
    assert [r["id"] for r in expected["findings"]] == ["BenchmarkTest00001", "BenchmarkTest00003"]
    assert [r["id"] for r in expected["decoys"]] == ["BenchmarkTest00002", "BenchmarkTest00004"]
    assert "family" not in expected["decoys"][1]               # unmapped stays family-less

    # one matcher for eval gate + calibration: metrics.match consumes this directly
    sqli_true = mk(path=f"{io_.TESTCODE_DIR}/BenchmarkTest00001.java",
                   cwe="CWE-89", family="injection", source_id="semgrep",
                   source_kind="scanner", vendor="semgrep")
    wrong_cwe = mk(path=f"{io_.TESTCODE_DIR}/BenchmarkTest00002.java",
                   cwe="CWE-79", family="xss", source_id="semgrep",
                   source_kind="scanner", vendor="semgrep")
    matches, noise = metrics.match(expected, [sqli_true, wrong_cwe])
    assert matches["BenchmarkTest00001"] == [sqli_true]
    assert matches["BenchmarkTest00002"] == []                 # CWE mismatch -> not a decoy hit
    assert noise == [wrong_cwe]                                # out-of-scope per Benchmark rules
