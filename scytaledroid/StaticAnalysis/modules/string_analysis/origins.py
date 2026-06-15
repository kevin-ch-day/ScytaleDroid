"""Origin-type normalization helpers for string analysis."""

from __future__ import annotations

from collections.abc import Collection

_CANONICAL_ORIGIN_TYPE_MAP = {
    "code": "code",
    "dex": "code",
    "resource": "resource",
    "res": "resource",
    "raw": "raw",
    "asset": "asset",
    "native": "native",
    "rn_bundle": "rn_bundle",
}


def canonical_origin_type(origin_type: str | None) -> str:
    """Return the canonical origin label used by the string pipeline."""

    lowered = str(origin_type or "").strip().lower()
    if not lowered:
        return "unknown"
    return _CANONICAL_ORIGIN_TYPE_MAP.get(lowered, lowered)


def is_code_origin(origin_type: str | None) -> bool:
    """Return ``True`` when *origin_type* represents code strings."""

    return canonical_origin_type(origin_type) == "code"


def is_resource_origin(origin_type: str | None) -> bool:
    """Return ``True`` when *origin_type* represents Android resource content."""

    return canonical_origin_type(origin_type) in {"resource", "raw"}


def origin_matches(
    origin_type: str | None,
    allowed_origin_types: Collection[str] | None,
) -> bool:
    """Return whether *origin_type* should match *allowed_origin_types*."""

    if allowed_origin_types is None:
        return True

    allowed = {canonical_origin_type(value) for value in allowed_origin_types}
    candidate = canonical_origin_type(origin_type)
    if candidate in allowed:
        return True

    if candidate == "raw" and "resource" in allowed:
        return True
    return False


__all__ = [
    "canonical_origin_type",
    "is_code_origin",
    "is_resource_origin",
    "origin_matches",
]
