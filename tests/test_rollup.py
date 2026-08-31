"""Pattern rollup + representative validation sampling (dogfood items 1-2)."""
from security_council import model as m
from security_council import rollup
from security_council.export import html_export, markdown
from security_council.validate.panel import select_for_validation
from tests.test_cluster import mk
from tests.test_export_markdown import _manifest


def _inst(rule="sc/http", sev="high", family="injection", n=0, path=None):
    f = mk(path=path or f"app/mod{n % 3}/f{n}.py", sev=sev, family=family, sink=f"s{n}")
    f.rule = m.RuleRef(id=rule, source="semgrep")
    return f


def test_groups_form_above_min_count_and_sort_by_weight():
    fs = ([_inst(rule="sc/http", n=i) for i in range(4)]
          + [_inst(rule="sc/sqli", sev="critical", n=10 + i) for i in range(3)]
          + [_inst(rule="sc/rare", n=99)])
    groups = rollup.pattern_groups(fs)
    assert [(g.rule, g.count) for g in groups] == [("sc/http", 4), ("sc/sqli", 3)]
    assert groups[1].highest_severity == "critical"
    assert groups[0].components == ["app"]
    slim = rollup.rollup_json(fs)
    assert slim[0]["rule"] == "sc/http" and len(slim[0]["representative_ids"]) == 3
    assert all("members" not in g for g in slim)


def test_sampling_spreads_the_budget_across_patterns():
    # 5 high instances of one rule + 1 medium of another: a cap of 2 must
    # cross-examine BOTH patterns, not spend twice on the big one
    big = [_inst(rule="sc/http", sev="high", n=i) for i in range(5)]
    other = _inst(rule="sc/sqli", sev="medium", n=9)
    ranked, selected = select_for_validation([*big, other], max_findings=2)
    assert {f.rule.id for f in selected} == {"sc/http", "sc/sqli"}
    # severity still leads: the high pattern's representative goes first
    assert selected[0].rule.id == "sc/http"
    # with no cap every instance is still selected
    _, everyone = select_for_validation([*big, other])
    assert len(everyone) == 6


def test_singletons_degrade_to_plain_severity_order():
    fs = [_inst(rule=f"r{i}", sev=s, n=i)
          for i, s in enumerate(["medium", "critical", "high"])]
    _, selected = select_for_validation(fs)
    assert [f.severity.label for f in selected] == ["critical", "high", "medium"]


def test_reports_render_the_rollup_without_collapsing_instances():
    fs = [_inst(rule="sc/http", n=i) for i in range(3)] + [_inst(rule="sc/one", n=7)]
    mf = _manifest(fs)
    assert mf["patterns"][0]["rule"] == "sc/http"          # manifest carries it
    md = markdown.to_markdown(fs, mf)
    assert "## Recurring patterns" in md
    assert "**Concentration:**" in md and "`sc/http` × 3" in md
    assert "not** one proven root cause" in md
    assert len([ln for ln in md.splitlines() if ln.startswith("| `sc/http` |")]) == 1
    page = html_export.to_html(fs, mf)
    assert "Concentration" in page and "recurring pattern" in page
    assert "<code>sc/http</code>" in page


def test_no_rollup_noise_without_repeats():
    fs = [_inst(rule=f"r{i}", n=i) for i in range(3)]
    mf = _manifest(fs)
    assert mf["patterns"] == []
    md = markdown.to_markdown(fs, mf)
    assert "Recurring patterns" not in md and "Concentration" not in md
