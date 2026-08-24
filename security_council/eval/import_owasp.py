"""OWASP Benchmark (Java) ground-truth importer — converter-only, never vendored.

BenchmarkJava is GPL-2.0 and this repo is proprietary/source-available, so no
Benchmark file may be copied into this tree (plan's "vendoring vs converter-only"
question, resolved by the license review). The user clones the benchmark
themselves (``git clone https://github.com/OWASP-Benchmark/BenchmarkJava``) and
this module reads that checkout at runtime. Scorecard numbers and fitted
calibration derived from running our pipeline over it are our own data.

The converter emits the same EXPECTED-shaped ground-truth dict the eval matcher
(`eval.metrics.match`) already consumes — real cases become ``findings`` rows,
fake cases become ``decoys``, both carrying their CWE — so the calibration lane
and the eval gate share one matcher. That reproduces Benchmark's own scoring
convention: a reported finding counts for a test case only when its CWE matches
the case's category (exact CWE first, then our family fallback); anything else
in the file is out-of-scope noise, excluded from labeling.
"""

from __future__ import annotations

import csv
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..model import canonical_cwe
from ..normalize.cwe import family_for_cwe

CORPUS_NAME = "owasp-benchmark-java"
TESTCODE_DIR = "src/main/java/org/owasp/benchmark/testcode"
_CSV_GLOB = "expectedresults-*.csv"
_VERSION_RE = re.compile(r"expectedresults-(.+)\.csv$")


class BenchmarkImportError(ValueError):
    """The checkout is not a usable BenchmarkJava tree (message says why)."""


@dataclass(frozen=True)
class BenchmarkCase:
    id: str            # BenchmarkTestNNNNN
    path: str          # checkout-relative .java path (matches finding location URIs)
    category: str      # benchmark category (cmdi, sqli, weakrand, ...)
    cwe: str           # canonical "CWE-n"
    family: str | None  # our cwe_family, or None when unmapped
    real: bool         # true vulnerability vs safe decoy variant


def find_expected_csv(checkout: Path) -> Path:
    found = sorted(checkout.glob(_CSV_GLOB))
    if not found:
        raise BenchmarkImportError(
            f"no {_CSV_GLOB} under {checkout} — is this a BenchmarkJava checkout?")
    if len(found) > 1:
        names = ", ".join(p.name for p in found)
        raise BenchmarkImportError(
            f"ambiguous ground truth: {len(found)} expected-results files ({names})")
    return found[0]


def _git_sha(checkout: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
    except OSError:
        return None
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else None


def load_cases(checkout: str | Path) -> tuple[list[BenchmarkCase], dict]:
    """Parse the checkout's expected-results CSV into cases + corpus metadata.

    Strict on integrity: every case's test file must exist in the checkout — a
    partial tree would silently mislabel scan results as misses."""
    root = Path(checkout)
    csv_path = find_expected_csv(root)
    version_m = _VERSION_RE.search(csv_path.name)
    cases: list[BenchmarkCase] = []
    missing: list[str] = []
    with open(csv_path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 4 or not row[0].strip().startswith("BenchmarkTest"):
                continue   # header / comment / blank
            name, category = row[0].strip(), row[1].strip()
            real = row[2].strip().lower() == "true"
            cwe = canonical_cwe(f"CWE-{row[3].strip()}")
            path = f"{TESTCODE_DIR}/{name}.java"
            if not (root / path).is_file():
                missing.append(path)
                continue
            cases.append(BenchmarkCase(id=name, path=path, category=category,
                                       cwe=cwe, family=family_for_cwe(cwe), real=real))
    if missing:
        raise BenchmarkImportError(
            f"{len(missing)} of {len(missing) + len(cases)} test files missing from "
            f"{root} (first: {missing[0]}) — partial checkout would mislabel results")
    if not cases:
        raise BenchmarkImportError(f"{csv_path.name} contains no BenchmarkTest rows")
    categories: dict[str, dict] = {}
    for c in cases:
        cat = categories.setdefault(
            c.category, {"cwe": c.cwe, "family": c.family, "true": 0, "false": 0})
        cat["true" if c.real else "false"] += 1
    meta = {
        "corpus": CORPUS_NAME,
        "version": version_m.group(1) if version_m else "unknown",
        "csv": csv_path.name,
        "git_sha": _git_sha(root),
        "cases_total": len(cases),
        "cases_true": sum(1 for c in cases if c.real),
        "cases_false": sum(1 for c in cases if not c.real),
        "categories": categories,
    }
    return cases, meta


def ground_truth(cases: list[BenchmarkCase]) -> dict:
    """EXPECTED-shaped dict for `eval.metrics.match`: real -> findings,
    fake -> decoys. Both carry cwe (+family when mapped) so the matcher applies
    the exact-CWE-then-family rule to decoys too — Benchmark's convention."""
    def row(c: BenchmarkCase) -> dict:
        r = {"id": c.id, "path": c.path, "cwe": c.cwe, "category": c.category}
        if c.family:
            r["family"] = c.family
        return r
    return {"findings": [row(c) for c in cases if c.real],
            "decoys": [row(c) for c in cases if not c.real]}
