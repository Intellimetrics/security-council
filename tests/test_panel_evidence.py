"""R10 — panel evidence rules.

Live runs on 2026-08-25 surfaced that citation "verification" proves only that
a REFERENCE RESOLVES (llm-council checks path-resolves + start_line <= line
count), never that a CLAIM IS SUPPORTED. These tests pin the consequences shut:
a refutation must be evidenced, anchored to the finding's own code, and carried
by more than one vendor family.

Every scenario below was reproduced against the real code before it was fixed.
"""

from __future__ import annotations

from security_council import policy, score
from security_council.validate import panel
from tests.test_validate import _cite, _finding
from tests.test_vendor_validate import _cr

NOW = "2026-08-25T00:00:00Z"
LLM_ONLY = (("house", "agent_cli", "claude"), ("agy", "agent_cli", "google"))

# an existing file, a real line number -> llm-council marks it verified=True,
# and it has NOTHING to do with the finding at app/reports.py:9
IRRELEVANT = {"path": "README.md", "start_line": 1, "end_line": 1,
              "text": "unrelated", "verified": True}
WHOLE_FILE = {"path": "app/reports.py", "start_line": 1, "end_line": 5000,
              "text": "the whole file", "verified": True}


def _judge(f, votes):
    val = panel.synthesize_validation(f, _cr(votes), prompt_sha256="p")
    f.validation = val
    f.disposition.state = panel._state_for(f, val)
    policy.apply_policy([f], config={"auto_suppress": False}, now_iso=NOW)
    return val


# --------------------------------------------------------------------------- #
# the anchor rule
# --------------------------------------------------------------------------- #


def test_irrelevant_citation_cannot_clear_G2():
    """THE BYPASS: a defender citing README.md:1-1 was a "fully verified
    defender", so a SEMGREP-corroborated finding was refuted out of the gate."""
    f = _finding()                                   # semgrep + house sources
    assert f.corroboration.deterministic_sources     # G2 is in scope
    _judge(f, [("claude", "for", "yes", [IRRELEVANT]),
               ("codex", "against", "no", [IRRELEVANT]),
               ("antigravity", "neutral", "no", [IRRELEVANT])])
    assert f.disposition.state == "needs_human"      # was "refuted"
    assert f.disposition.lifecycle == "open"


def test_anchored_refutation_still_works():
    """Guard against over-correction: the panel must keep its actual purpose."""
    f = _finding()
    val = _judge(f, [("claude", "for", "yes", [IRRELEVANT]),
                     ("codex", "against", "no", [_cite()]),
                     ("antigravity", "neutral", "no", [_cite()])])
    assert val.verdict == "false_positive"
    assert f.disposition.state == "refuted"
    assert score._fully_verified_defender(val.panel, f) is True


def test_whole_file_span_does_not_anchor():
    """verify_ref bounds start_line but NOT end_line, so a 1..5000 span
    "verifies" and would otherwise intersect any anchor range."""
    f = _finding()
    _judge(f, [("claude", "for", "yes", [_cite()]),
               ("codex", "against", "no", [WHOLE_FILE]),
               ("antigravity", "neutral", "no", [WHOLE_FILE])])
    assert f.disposition.state == "needs_human"


def test_defender_must_actually_be_refuting_to_clear_G2():
    """_fully_verified_defender gated refutation without requiring the defender
    to be refuting — a defender voting true_positive satisfied it."""
    f = _finding()
    val = _judge(f, [("claude", "for", "yes", [_cite()]),
                     ("codex", "against", "yes", [_cite()]),   # defender AGREES
                     ("antigravity", "neutral", "no", [_cite()])])
    assert score._fully_verified_defender(val.panel, f) is False


# --------------------------------------------------------------------------- #
# evidence asymmetry: cite nothing -> may support, may never refute
# --------------------------------------------------------------------------- #


def test_zero_citation_opinions_cannot_refute():
    f = _finding(sources=LLM_ONLY)                   # no deterministic source: G2 silent
    assert not f.corroboration.deterministic_sources
    val = _judge(f, [("claude", "for", "yes", [_cite()]),
                     ("codex", "against", "no", []),
                     ("antigravity", "neutral", "no", [])])
    assert val.verdict != "false_positive"           # was "false_positive"
    assert f.disposition.state == "needs_human"
    blocked = val.evidence_check["refutation_blocked"]
    assert blocked["voters"] == ["codex", "antigravity"]
    assert blocked["statuses"] == ["unevidenced", "unevidenced"]


def test_zero_citation_opinions_may_still_confirm():
    """The asymmetry is deliberate: confirming is the fail-safe direction."""
    f = _finding()
    val = _judge(f, [("claude", "for", "yes", []),
                     ("antigravity", "neutral", "yes", []),
                     ("codex", "against", "no", [_cite()])])
    assert val.verdict == "true_positive"


def test_unevidenced_refutation_attempt_is_surfaced():
    f = _finding()
    _judge(f, [("claude", "for", "yes", [_cite()]),
               ("codex", "against", "no", []),
               ("antigravity", "neutral", "yes", [_cite()])])
    s = score.score_finding(f)
    assert "unevidenced_refutation_attempt" in s.needs_human_reasons


# --------------------------------------------------------------------------- #
# independence and hallucination
# --------------------------------------------------------------------------- #


def test_refuters_must_span_two_vendor_families():
    """FAMILY_BY_PEER maps antigravity and gemini onto the same "google" family,
    and the FP quorum counted opinions, not families."""
    assert panel.FAMILY_BY_PEER["antigravity"] == panel.FAMILY_BY_PEER["gemini"] == "google"
    f = _finding()
    val = _judge(f, [("claude", "for", "yes", []),
                     ("antigravity", "against", "no", [_cite()]),
                     ("gemini", "neutral", "no", [_cite()])])
    assert val.evidence_check["refuter_families"] == ["google"]
    assert val.verdict != "false_positive"


def test_any_refuter_hallucinating_forces_human_review():
    """defender_hallucinated watched only the defender seat; a prosecutor or
    adjudicator voting false_positive off a fabricated citation was untrapped."""
    f = _finding()
    val = _judge(f, [("claude", "for", "no", [_cite(verified=False)]),   # prosecutor, FP, fake
                     ("codex", "against", "no", [_cite()]),
                     ("antigravity", "neutral", "no", [_cite()])])
    assert val.evidence_check["refuter_hallucinated"] is True
    assert val.verdict == "needs_human"


# --------------------------------------------------------------------------- #
# malformed citations must count against, not vanish
# --------------------------------------------------------------------------- #


def test_malformed_citations_lower_the_pass_rate():
    """They used to be dropped silently, so junk RAISED the rate by shrinking
    the denominator."""
    cites, malformed = panel._citations([
        _cite(),                                              # good
        {"path": "../../etc/passwd", "start_line": 1, "end_line": 1},   # bad path
        {"path": "app/reports.py", "start_line": 0, "end_line": 3},     # bad lines
    ])
    assert len(cites) == 1 and malformed == 2

    op = panel._opinion(_cr([("codex", "against", "no", [
        _cite(),
        {"path": "../../etc/passwd", "start_line": 1, "end_line": 1},
        {"path": "app/reports.py", "start_line": 0, "end_line": 3},
    ])]).results[0], "p")
    assert op.citation_pass_rate == 1 / 3        # was 1/1 == 1.0
    assert op.status == "unreliable"


def test_prose_evidence_is_not_a_malformed_citation():
    """llm-council emits untagged/inferred evidence with no `path`; that is
    commentary, not a broken citation, and must not be penalised."""
    cites, malformed = panel._citations([
        {"text": "inferred: this looks reachable"},
        _cite(),
    ])
    assert len(cites) == 1 and malformed == 0


# --------------------------------------------------------------------------- #
# the flag that had never fired
# --------------------------------------------------------------------------- #


def test_no_cross_file_navigation_is_actually_assigned():
    """It was read by score.py and set nowhere, so the clamp advertised in
    docs/safety-model.md could never trigger."""
    f = _finding()
    f.locations.append(type(f.locations[0])(
        uri="app/routes.py", start_line=3, end_line=3, role="related",
        snippet_sha256=f.locations[0].snippet_sha256, snippet="x"))
    val = _judge(f, [("claude", "for", "yes", [_cite()]),
                     ("codex", "against", "no", [_cite()]),
                     ("antigravity", "neutral", "yes", [_cite()])])
    assert val.no_cross_file_navigation is True
    assert "no_cross_file_navigation" in score.score_finding(f).needs_human_reasons
