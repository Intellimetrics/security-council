"""P0 tests: a valid Finding passes; each invariant I1-I10 fires when tripped."""
import dataclasses
import hashlib

import pytest

from security_council import model as m


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _fp(hexes: tuple[str, str, str] | None = None) -> m.Fingerprints:
    a, b, c = hexes or (_sha256("rc")[:32], _sha256("pcs")[:32], _sha256("ctx")[:32])
    return m.Fingerprints(
        path_cwe_sink=f"pathCweSink/v1:{b}",
        context_hash=f"contextHash/v1:{c}",
        root_cause=f"rootCause/v1:{a}",
    )


def valid_finding(**over) -> m.Finding:
    fp = over.pop("fingerprints", None) or _fp()
    loc = m.CodeLocation(
        uri="app/crypto_util.py", start_line=6, end_line=7, role="primary",
        snippet_sha256=_sha256("md5(pw)"),
    )
    f = m.Finding(
        id=m.finding_id(fp),
        schema_version=m.SCHEMA_VERSION,
        cluster_id=None,
        rule=m.RuleRef(id="sc/crypto/weak-hash", source="house"),
        taxonomy=m.Taxonomy(cwe=["CWE-916"], cwe_family="crypto", cwe_confidence="exact"),
        severity=m.SeverityBlock(label="high", sarif_level="error", security_severity=8.0),
        locations=[loc],
        fingerprints=fp,
        provenance=[m.ProvenanceEntry(
            source_id="house", source_kind="agent_cli", family="claude",
            prompt_sha256=_sha256("prompt"), collected_at="2026-08-20T00:00:00Z",
            model_id="claude-fable-5",
        )],
        corroboration=m.Corroboration(agent_sources=["house"], count=1),
        disposition=m.Disposition(
            state="new", lifecycle="open",
            decided_by=m.DecidedBy(kind="auto", decided_at="2026-08-20T00:00:00Z"),
        ),
        title="Unsalted MD5 password hash",
        description="passwords hashed with unsalted MD5",
    )
    for k, v in over.items():
        setattr(f, k, v)
    return f


def test_valid_finding_passes():
    f = valid_finding()
    assert m.validate_finding(f) == []
    m.assert_invariants(f)  # does not raise


def test_finding_id_is_derived_and_stable():
    fp = _fp()
    assert m.finding_id(fp) == m.finding_id(fp)
    # changing root_cause changes the id
    fp2 = m.Fingerprints(path_cwe_sink=fp.path_cwe_sink,
                         context_hash=fp.context_hash,
                         root_cause="rootCause/v1:" + _sha256("other")[:32])
    assert m.finding_id(fp2) != m.finding_id(fp)


def test_i1_location_uri_must_be_repo_relative():
    f = valid_finding()
    f.locations = [dataclasses.replace(f.locations[0], uri="/abs/app/x.py")]
    assert any(e.startswith("I1") for e in m.validate_finding(f))


def test_i1_snippet_sha256_required():
    f = valid_finding()
    f.locations = [dataclasses.replace(f.locations[0], snippet_sha256="nothex")]
    assert any(e.startswith("I1") for e in m.validate_finding(f))


def test_i2_agent_requires_model_id():
    f = valid_finding()
    f.provenance[0].model_id = None
    assert any(e.startswith("I2") for e in m.validate_finding(f))


def test_i2_scanner_requires_tool_version():
    f = valid_finding()
    f.provenance = [m.ProvenanceEntry(
        source_id="semgrep", source_kind="scanner", family="semgrep",
        prompt_sha256=_sha256("p"), collected_at="t")]  # no tool_version
    f.corroboration = m.Corroboration(deterministic_sources=["semgrep"], count=1)
    assert any(e.startswith("I2") for e in m.validate_finding(f))


def test_i3_fingerprint_must_not_contain_line_numbers_shape():
    f = valid_finding()
    object.__setattr__(f.fingerprints, "context_hash", "contextHash/v1:ZZZ")
    assert any(e.startswith("I3") for e in m.validate_finding(f))


def test_i4_family_must_match_cwe():
    f = valid_finding()
    f.taxonomy.cwe_family = "injection"  # CWE-916 is crypto
    assert any(e.startswith("I4") for e in m.validate_finding(f))


def test_i5_sarif_level_derived_from_label():
    f = valid_finding()
    f.severity.sarif_level = "note"  # label high -> must be error
    assert any(e.startswith("I5") for e in m.validate_finding(f))


def test_i6_suppression_must_be_stamped():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    f.disposition.lifecycle = "suppressed"  # auto but no model_id/prompt/panel/ref/expiry
    errs = m.validate_finding(f)
    assert any(e.startswith("I6") for e in errs)


def test_i7_crypto_never_auto_suppressed():
    f = valid_finding()  # crypto
    f.disposition.lifecycle = "suppressed"
    f.disposition.decided_by = m.DecidedBy(
        kind="auto", decided_at="t", model_id="m", prompt_sha256=_sha256("p"), panel_sha256=_sha256("ps"))
    f.disposition.decision_ref = "ref"
    f.disposition.expires_at = "2026-11-20T00:00:00Z"
    # I6 now satisfied, but I7 must still fire
    errs = m.validate_finding(f)
    assert any(e.startswith("I7") for e in errs)
    assert not any(e.startswith("I6") for e in errs)


def test_i8_corroboration_count_arithmetic():
    f = valid_finding()
    f.corroboration.count = 5  # but only one source
    assert any(e.startswith("I8") for e in m.validate_finding(f))


def test_i9_id_must_match_fingerprints():
    f = valid_finding()
    f.id = "deadbeefdeadbeef"
    assert any(e.startswith("I9") for e in m.validate_finding(f))


def test_i10_no_poc_in_blue_profile():
    f = valid_finding()
    f.validation = m.Validation(verdict="true_positive", confidence=0.9)
    object.__setattr__(f.validation, "poc", {"attempted": True})
    assert any(e.startswith("I10") for e in m.validate_finding(f))


def test_assert_invariants_raises():
    f = valid_finding()
    f.id = "wrong"
    with pytest.raises(m.FindingInvariantError):
        m.assert_invariants(f)


# --- council-review regression tests (guardrail-evasion bypasses) ------------ #

def _auto_suppress(f, *, kind="auto"):
    f.disposition.lifecycle = "suppressed"
    f.disposition.decided_by = m.DecidedBy(
        kind=kind, decided_at="2026-08-20T00:00:00Z", model_id="gpt-5.6-sol",
        prompt_sha256=_sha256("p"), panel_sha256=_sha256("panel"))
    f.disposition.decision_ref = ".security-council/decisions/x.json"
    f.disposition.expires_at = "2026-11-20T00:00:00Z"
    return f


def test_i7_crypto_by_secondary_cwe_cannot_be_auto_suppressed():
    # CWE-601 (other) primary hides CWE-327 (crypto) secondary
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-601", "CWE-327"], cwe_family="other")
    _auto_suppress(f)
    errs = m.validate_finding(f)
    # I4 crypto-stickiness AND I7 must both catch it
    assert any(e.startswith("I4") for e in errs)
    assert any(e.startswith("I7") for e in errs)


def test_i6_i7_unknown_decision_kind_is_failclosed():
    f = valid_finding()  # crypto
    _auto_suppress(f, kind="system")  # not auto/human
    errs = m.validate_finding(f)
    assert any(e.startswith("I6") for e in errs)  # invalid kind
    assert any(e.startswith("I7") for e in errs)  # crypto still guarded


def test_i7_crypto_accepted_risk_also_guarded():
    f = valid_finding()  # crypto
    _auto_suppress(f)
    f.disposition.lifecycle = "accepted_risk"
    assert any(e.startswith("I7") for e in m.validate_finding(f))


def test_i6_weak_attribution_rejected():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    _auto_suppress(f)
    f.disposition.decided_by.panel_sha256 = "x"       # not a sha
    f.disposition.expires_at = "never"                 # not RFC3339
    errs = m.validate_finding(f)
    assert any("panel_sha256" in e for e in errs)
    assert any("expires_at" in e for e in errs)


def test_i11_vex_not_affected_on_open_rejected():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "vulnerable_code_not_in_execute_path"
    # lifecycle still "open"
    assert any(e.startswith("I11") for e in m.validate_finding(f))


def test_i11_sarif_suppression_on_open_rejected():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    f.disposition.sarif_suppression = {"kind": "external", "status": "accepted"}
    assert any(e.startswith("I11") for e in m.validate_finding(f))


def test_i11_not_affected_requires_openvex_justification():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    _auto_suppress(f)  # closed lifecycle satisfies the first I11 clause
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "made_up_reason"
    assert any(e.startswith("I11") for e in m.validate_finding(f))


def test_i12_hallucinated_citation_path_rejected():
    f = valid_finding()
    f.validation = m.Validation(
        verdict="false_positive", confidence=0.1,
        panel=[m.PanelOpinion(
            role="defender", participant="claude", family="claude",
            prompt_sha256=_sha256("p"), verdict="false_positive", rationale="...",
            citations=[m.EvidenceCitation(path="/etc/passwd", start_line=1, end_line=1,
                                          claim="x")])])
    assert any(e.startswith("I12") for e in m.validate_finding(f))


def test_i1_dataflow_location_validated():
    f = valid_finding()
    bad = m.CodeLocation(uri="../secrets.py", start_line=1, end_line=1, role="source",
                         snippet_sha256=_sha256("s"))
    f.data_flow = [m.DataFlowStep(order=1, location=bad, note="source")]
    assert any(e.startswith("I1") for e in m.validate_finding(f))


def test_is_crypto_finding_helper():
    f = valid_finding()
    assert m.is_crypto_finding(f)
    f.taxonomy = m.Taxonomy(cwe=["CWE-79"], cwe_family="xss")
    assert not m.is_crypto_finding(f)
    f.taxonomy = m.Taxonomy(cwe=["CWE-79", "CWE-916"], cwe_family="xss")
    assert m.is_crypto_finding(f)  # crypto by secondary cwe
