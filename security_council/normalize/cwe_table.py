"""Static CWE mapping tables for normalization."""

from __future__ import annotations

import re

# (source_id, source_rule_id) -> canonical CWE. Hand-curated; a test asserts every
# value is shaped and present in model.CWE_TO_FAMILY.
CWE_BY_SOURCE_RULE: dict[tuple[str, str], str] = {
    ("semgrep", "python.lang.security.audit.formatted-sql-query.formatted-sql-query"): "CWE-89",
    ("semgrep", "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query"): "CWE-89",
    ("semgrep", "python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit"): "CWE-78",
    ("semgrep", "python.lang.security.audit.dangerous-os-exec.dangerous-os-exec"): "CWE-78",
    ("semgrep", "python.lang.security.audit.md5-used-as-password.md5-used-as-password"): "CWE-327",
    ("gitleaks", "aws-access-token"): "CWE-798",
    ("gitleaks", "generic-api-key"): "CWE-798",
    ("gitleaks", "private-key"): "CWE-798",
}

# Ordered heuristic rules over a rule id or prose: (compiled regex, CWE).
_HEURISTICS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sql[\s._-]*inject|sqli|raw[\s._-]*query", re.I), "CWE-89"),
    (re.compile(r"command[\s._-]*inject|os[\s._-]*(system|exec)|shell[\s._=]*true|subprocess", re.I), "CWE-78"),
    (re.compile(r"path[\s._-]*travers|zip[\s._-]*slip|directory[\s._-]*travers", re.I), "CWE-22"),
    (re.compile(r"\bssrf\b|server[\s._-]*side[\s._-]*request", re.I), "CWE-918"),
    (re.compile(r"deserial|pickle|yaml[\s._.]*load|unmarshal", re.I), "CWE-502"),
    (re.compile(r"hardcod.*(secret|key|password|credential)|aws[\s._-]*access|api[\s._-]*key", re.I), "CWE-798"),
    (re.compile(r"\bmd5\b|\bsha1\b|weak[\s._-]*(hash|cipher|crypto)|ecb\b|insecure[\s._-]*hash", re.I), "CWE-327"),
    (re.compile(r"insecure[\s._-]*random|math[/.]random|predictable[\s._-]*random", re.I), "CWE-338"),
    (re.compile(r"\bxss\b|cross[\s._-]*site[\s._-]*script|innerhtml|dangerouslysetinnerhtml", re.I), "CWE-79"),
    (re.compile(r"\bidor\b|broken[\s._-]*object|missing[\s._-]*(authz|authorization|access[\s._-]*control)", re.I), "CWE-639"),
    (re.compile(r"open[\s._-]*redirect", re.I), "CWE-601"),
    (re.compile(r"redos|catastrophic[\s._-]*backtrack|regex[\s._-]*(dos|inject)", re.I), "CWE-1333"),
    (re.compile(r"vuln.*dep|outdated[\s._-]*(package|dependency)|known[\s._-]*vulnerab", re.I), "CWE-1395"),
]


def heuristic_cwe(text: str) -> str | None:
    for rx, cwe in _HEURISTICS:
        if rx.search(text or ""):
            return cwe
    return None
