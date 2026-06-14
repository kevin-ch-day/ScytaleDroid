"""Canonical package identity helpers shared across device/static/dynamic flows."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from hashlib import sha256
from typing import Any


def normalize_hex_digest(value: object, *, expected_len: int = 64) -> str | None:
    """Return a normalized lowercase hex digest or ``None``."""

    text = str(value or "").strip().lower().replace(":", "")
    if len(text) != expected_len:
        return None
    if re.fullmatch(rf"[0-9a-f]{{{expected_len}}}", text) is None:
        return None
    return text


def decode_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            decoded = json.loads(text)
        except Exception:
            return None
        if isinstance(decoded, Mapping):
            return decoded
    return None


def extract_embedded_mapping(
    container: Mapping[str, object] | None,
    *,
    key: str = "extras",
) -> Mapping[str, object] | None:
    if not container:
        return None
    return decode_mapping(container.get(key))


def resolve_hex_digest(
    container: Mapping[str, object] | None,
    *field_names: str,
    extras_key: str = "extras",
) -> str | None:
    if container:
        for name in field_names:
            direct = normalize_hex_digest(container.get(name))
            if direct:
                return direct
    extras = extract_embedded_mapping(container, key=extras_key)
    if extras:
        for name in field_names:
            embedded = normalize_hex_digest(extras.get(name))
            if embedded:
                return embedded
    return None


def resolve_text_field(
    container: Mapping[str, object] | None,
    *field_names: str,
    extras_key: str = "extras",
) -> str | None:
    if container:
        for name in field_names:
            text = str(container.get(name) or "").strip()
            if text:
                return text
    extras = extract_embedded_mapping(container, key=extras_key)
    if extras:
        for name in field_names:
            text = str(extras.get(name) or "").strip()
            if text:
                return text
    return None


def extract_signer_digests(package_dump: str) -> list[str]:
    digests: set[str] = set()
    for line in package_dump.splitlines():
        low = line.lower()
        if ("sha-256" not in low) and ("sha256" not in low) and ("sign" not in low):
            continue
        for match in re.finditer(r"([0-9A-Fa-f:]{64,95})", line):
            normalized = normalize_hex_digest(match.group(1))
            if normalized:
                digests.add(normalized)
    return sorted(digests)


def compute_signer_set_hash(digests: Iterable[object]) -> str | None:
    normalized = sorted(
        {
            value
            for value in (normalize_hex_digest(item) for item in digests)
            if value
        }
    )
    if not normalized:
        return None
    payload = "|".join(normalized).encode("utf-8")
    return sha256(payload).hexdigest()


def compute_split_membership_hash(paths: Iterable[object]) -> str | None:
    normalized = sorted(str(path).strip() for path in paths if str(path).strip())
    if not normalized:
        return None
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def first_nonempty_text(*values: Any) -> str | None:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return None


__all__ = [
    "compute_signer_set_hash",
    "compute_split_membership_hash",
    "decode_mapping",
    "extract_embedded_mapping",
    "extract_signer_digests",
    "first_nonempty_text",
    "normalize_hex_digest",
    "resolve_text_field",
    "resolve_hex_digest",
]
