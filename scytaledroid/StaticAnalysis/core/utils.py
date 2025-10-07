"""Utility helpers shared across the static analysis pipeline."""

from __future__ import annotations

from dataclasses import fields
from typing import Mapping, Optional, Type


def subset(source: object, model: Type) -> dict[str, object]:
    """Return mapping of dataclass field names in *model* from *source*."""

    if not isinstance(source, Mapping):
        return {}

    try:
        names = {field.name for field in fields(model)}
    except TypeError:
        return {}

    return {name: source.get(name) for name in names}


def coerce_bool(value: Optional[str]) -> Optional[bool]:
    """Best-effort conversion of string values to booleans."""

    if value is None:
        return None

    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def coerce_optional_str(value: object) -> Optional[str]:
    """Return a trimmed string representation or ``None`` when empty."""

    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


__all__ = ["subset", "coerce_bool", "coerce_optional_str"]
