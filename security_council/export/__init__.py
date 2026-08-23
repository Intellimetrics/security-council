"""Exporters. All render from Finding dispositions (D7: one `render_decision`
semantics) — `open_unresolved` is the single rule for what an operator-facing
export may contain: suppressed / accepted-risk / demoted findings are withheld
everywhere (they live in summary.md's appendix and the future VEX lane)."""

from ..model import Finding


def open_unresolved(f: Finding) -> bool:
    return (f.disposition.lifecycle in ("open", "reopened")
            and f.disposition.state != "refuted")
