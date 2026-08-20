"""Serialization for the finding model.

`dumps` is the canonical, byte-stable encoding used for golden files, the
decision store, and fingerprint inputs — sorted keys, compact separators, no
ASCII escaping. `to_dict` is a plain recursive dataclass dump. `finding_from_dict`
(reconstruction) is added alongside the normalizer, which is its first consumer.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from .model import Finding


def to_dict(obj: Any) -> Any:
    """Recursively convert a dataclass (or nested structure) to plain dicts/lists."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


def dumps(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact, UTF-8. Byte-stable for goldens."""
    return json.dumps(
        to_dict(obj),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def finding_to_dict(f: Finding) -> dict:
    """Public alias for the Finding -> dict path (adds schema_version at top)."""
    d = to_dict(f)
    d.setdefault("schema_version", f.schema_version)
    return d
