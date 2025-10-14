from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class PermissionMeta:
    """Normalised representation of a framework permission entry."""

    name: str
    short: str
    protection: Optional[str]
    protection_raw: Optional[str]
    protection_tokens: Sequence[str]
    added_api: Optional[int]
    added_version: Optional[str]
    deprecated_api: Optional[int]
    deprecated_note: Optional[str]
    hard_restricted: bool
    soft_restricted: bool
    system_only: bool
    restricted_note: Optional[str]
    system_only_note: Optional[str]
    constant_value: Optional[str]
    summary: str
    doc_url: str
    api_references: Sequence[str]
    group: Optional[str] = None


def normalise_protection(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = "".join(ch.lower() for ch in str(raw))
    aliases = {
        "dangerous": "dangerous",
        "normal": "normal",
        "signatureorsystem": "signatureOrSystem",
        "signature": "signature",
        "development": "development",
        "installer": "installer",
        "instant": "instant",
        "appop": "appop",
        "system": "system",
        "internal": "internal",
        "oem": "oem",
        "preinstalled": "preinstalled",
        "privileged": "privileged",
    }
    for key, value in aliases.items():
        if key in s:
            return value
    return None


def split_protection_tokens(raw: Optional[str]) -> list[str]:
    """Return a normalised list of protection tokens from a raw string.

    Example: "signature|privileged|development" -> ["signature", "privileged", "development"]
    """
    if not raw:
        return []
    tokens: list[str] = []
    for part in str(raw).replace(" ", "").split("|"):
        part = part.strip().lower()
        if part:
            tokens.append(part)
    # Deduplicate preserving order
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
