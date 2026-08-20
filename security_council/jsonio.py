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


# --------------------------------------------------------------------------- #
# Reconstruction (dict -> Finding), the ingress side of the boundary
# --------------------------------------------------------------------------- #

import dataclasses as _dc  # noqa: E402
import typing as _t  # noqa: E402

from .model import assert_invariants as _assert_invariants  # noqa: E402

_HINTS: dict = {}


def _hints(cls):
    if cls not in _HINTS:
        _HINTS[cls] = _t.get_type_hints(cls)
    return _HINTS[cls]


def _build(tp, data):
    if data is None:
        return None
    origin = _t.get_origin(tp)
    if _dc.is_dataclass(tp) and isinstance(tp, type) and isinstance(data, dict):
        hints = _hints(tp)
        kw = {f.name: _build(hints.get(f.name, object), data[f.name])
              for f in _dc.fields(tp) if f.name in data}
        return tp(**kw)
    if origin is list and isinstance(data, list):
        args = _t.get_args(tp)
        elem = args[0] if args else object
        return [_build(elem, x) for x in data]
    if origin is _t.Union:
        for a in _t.get_args(tp):
            if a is type(None):
                continue
            if _dc.is_dataclass(a) and isinstance(data, dict):
                return _build(a, data)
        return data
    return data


def finding_from_dict(d: dict) -> Finding:
    """Reconstruct a Finding and assert its invariants (fail-closed at ingress)."""
    f = _build(Finding, d)
    _assert_invariants(f)
    return f
