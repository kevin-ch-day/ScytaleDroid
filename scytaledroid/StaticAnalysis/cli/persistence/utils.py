"""Shared helper functions for CLI persistence pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import is_dataclass
from typing import Any

from scytaledroid.Database.db_queries.canonical import schema as canonical_schema


def require_canonical_schema() -> None:
    """Hard-fail when canonical schema is unavailable."""

    if not canonical_schema.ensure_all():
        raise RuntimeError("DB schema is outdated; run migrations to use canonical schema.")


def truncate(value: str | None, limit: int) -> str | None:
    """Trim ``value`` to at most *limit* characters, preserving None."""

    if value is None:
        return None
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        inner = text[1:-1].strip()
        if inner:
            text = inner
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def coerce_mapping(obj: Any) -> dict[str, Any]:
    """Best-effort conversion of ``obj`` into a plain dict."""

    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    if hasattr(obj, "__slots__"):
        data: dict[str, Any] = {}
        for attr in getattr(obj, "__slots__", ()):  # type: ignore[attr-defined]
            if attr.startswith("_"):
                continue
            try:
                value = getattr(obj, attr)
            except Exception:
                continue
            if callable(value):
                continue
            data[attr] = value
        return data
    if is_dataclass(obj):
        try:
            return {k: getattr(obj, k) for k in obj.__dataclass_fields__}  # type: ignore[attr-defined]
        except Exception:
            return {}
    data: dict[str, Any] = {}
    for attr in dir(obj):
        if attr.startswith("_"):
            continue
        try:
            value = getattr(obj, attr)
        except Exception:
            continue
        if callable(value):
            continue
        data[attr] = value
    return data


_SEVERITY_CANONICAL = {
    "critical": "High",
    "high": "High",
    "p0": "High",
    "medium": "Medium",
    "med": "Medium",
    "p1": "Medium",
    "low": "Low",
    "p2": "Low",
    "info": "Info",
    "information": "Info",
    "note": "Info",
    "p3": "Low",
    "p4": "Info",
}


def normalise_severity_token(value: object | None) -> str | None:
    """Map a freeform severity token to ``High/Medium/Low/Info``."""

    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    mapped = _SEVERITY_CANONICAL.get(text)
    if mapped:
        return mapped
    if text and text[0] in _SEVERITY_CANONICAL:
        return _SEVERITY_CANONICAL.get(text[0])
    return None


def canonical_severity_counts(counter: Mapping[str, int]) -> dict[str, int]:
    """Return canonical totals for ``High/Medium/Low/Info``."""

    return {
        "High": int(counter.get("High", 0)),
        "Medium": int(counter.get("Medium", 0)),
        "Low": int(counter.get("Low", 0)),
        "Info": int(counter.get("Info", 0)),
    }


def safe_int(value: object) -> int | None:
    """Convert ``value`` to int when possible, otherwise ``None``."""

    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first_text(*values: object | None) -> str | None:
    """Return the first non-empty string representation from ``values``."""

    for value in values:
        if value is None:
            continue
        try:
            text = str(value).strip()
        except Exception:
            continue
        if text:
            return text
    return None