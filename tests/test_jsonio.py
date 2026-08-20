"""jsonio: canonical dumps is deterministic and key-order independent."""
from security_council import jsonio
from tests.test_model import valid_finding


def test_dumps_is_deterministic():
    f = valid_finding()
    assert jsonio.dumps(f) == jsonio.dumps(f)


def test_dumps_is_key_order_independent():
    a = {"b": 1, "a": 2, "c": {"z": 1, "y": 2}}
    b = {"c": {"y": 2, "z": 1}, "a": 2, "b": 1}
    assert jsonio.dumps(a) == jsonio.dumps(b)


def test_finding_to_dict_roundtrips_through_json():
    import json
    f = valid_finding()
    d = jsonio.finding_to_dict(f)
    assert json.loads(jsonio.dumps(d)) == d
    assert d["id"] == f.id
    assert d["taxonomy"]["cwe_family"] == "crypto"


def test_finding_from_dict_roundtrips():
    from security_council import jsonio as j
    from tests.test_model import valid_finding
    f = valid_finding()
    rebuilt = j.finding_from_dict(j.to_dict(f))
    assert j.dumps(rebuilt) == j.dumps(f)
    assert rebuilt.fingerprints.root_cause == f.fingerprints.root_cause
    assert rebuilt.taxonomy.cwe_family == "crypto"


def test_finding_from_dict_rejects_invalid():
    import pytest
    from security_council import jsonio as j
    from security_council.model import FindingInvariantError
    from tests.test_model import valid_finding
    d = j.to_dict(valid_finding())
    d["id"] = "tampered"
    with pytest.raises(FindingInvariantError):
        j.finding_from_dict(d)
