"""P1 property tests: fingerprints are stable under drift, sensitive to real change."""
from security_council import fingerprint as fp
from security_council.model import PackageRef, _FINGERPRINT_RE

BASE = [
    "def get_order(order_id):",
    "    # load the order",
    '    q = "SELECT * FROM orders WHERE id = ?"',
    "    return db.execute(q, (order_id,)).fetchone()",
]


def test_shapes_match_model_regex():
    assert _FINGERPRINT_RE.match(fp.path_cwe_sink(path="a/b.py", cwe="CWE-89", sink_token="get_order"))
    assert _FINGERPRINT_RE.match(fp.context_hash(BASE))
    assert _FINGERPRINT_RE.match(fp.root_cause(cwe_family="authz", root_symbol="get_order", sink_expr="q"))


def test_context_hash_stable_under_blank_lines_and_reindent():
    drifted = ["", "", *BASE[:1], "", "    " + BASE[1].strip(), *BASE[2:], ""]
    assert fp.context_hash(BASE) == fp.context_hash(drifted)


def test_context_hash_stable_under_comment_reformatting():
    variant = [
        "def get_order(order_id):",
        "    ## LOAD THE ORDER (reworded comment)",
        '    q = "SELECT * FROM orders WHERE id = ?"  # trailing note',
        "    return db.execute(q, (order_id,)).fetchone()",
    ]
    assert fp.context_hash(BASE) == fp.context_hash(variant)


def test_context_hash_ignores_string_literal_value():
    variant = list(BASE)
    variant[2] = '    q = "SELECT * FROM orders WHERE id = 1 AND totally != different"'
    assert fp.context_hash(BASE) == fp.context_hash(variant)


def test_context_hash_ignores_numeric_literal_value():
    a = ["sleep(5)"]
    b = ["sleep(10)"]
    assert fp.context_hash(a) == fp.context_hash(b)


def test_context_hash_changes_on_identifier_change():
    variant = list(BASE)
    variant[3] = "    return db.execute(q, (order_id,)).fetchall()"  # fetchone -> fetchall
    assert fp.context_hash(BASE) != fp.context_hash(variant)


def test_path_cwe_sink_sensitive_to_each_component():
    base = fp.path_cwe_sink(path="app/db.py", cwe="CWE-89", sink_token="run")
    assert base != fp.path_cwe_sink(path="app/other.py", cwe="CWE-89", sink_token="run")
    assert base != fp.path_cwe_sink(path="app/db.py", cwe="CWE-78", sink_token="run")
    assert base != fp.path_cwe_sink(path="app/db.py", cwe="CWE-89", sink_token="exec")


def test_root_cause_package_ignores_version():
    a = PackageRef(purl="pkg:pypi/urllib3@1.24.1", version="1.24.1", advisory_ids=["CVE-2024-37891"])
    b = PackageRef(purl="pkg:pypi/urllib3@2.0.0", version="2.0.0", advisory_ids=["CVE-2024-37891"])
    assert fp.root_cause(cwe_family="supply_chain", root_symbol="", sink_expr="", package=a) == \
           fp.root_cause(cwe_family="supply_chain", root_symbol="", sink_expr="", package=b)
    # different advisory -> different root cause
    c = PackageRef(purl="pkg:pypi/urllib3@1.24.1", advisory_ids=["CVE-2025-66418"])
    assert fp.root_cause(cwe_family="supply_chain", root_symbol="", sink_expr="", package=a) != \
           fp.root_cause(cwe_family="supply_chain", root_symbol="", sink_expr="", package=c)


def test_purl_without_version():
    assert fp.purl_without_version("pkg:pypi/urllib3@1.24.1") == "pkg:pypi/urllib3"
    assert fp.purl_without_version("pkg:npm/@scope/pkg@1.2.3") == "pkg:npm/@scope/pkg"
    assert fp.purl_without_version("pkg:pypi/urllib3") == "pkg:pypi/urllib3"


def test_no_line_numbers_in_any_fingerprint():
    # the hex body is content-addressed; assert the visible fingerprint carries no
    # positional integer beyond the /v1 version tag.
    for f in (fp.path_cwe_sink(path="a.py", cwe="CWE-89", sink_token="s"),
              fp.context_hash(BASE),
              fp.root_cause(cwe_family="x", root_symbol="y", sink_expr="z")):
        algo, _, body = f.partition(":")
        assert algo.endswith("/v1")
        assert all(c in "0123456789abcdef" for c in body)
