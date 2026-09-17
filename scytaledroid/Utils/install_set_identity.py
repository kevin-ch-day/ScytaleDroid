"""Versioned, portable APK install-set identity helpers.

The digest identifies member composition only.  Package/version and local
``apk_set_id`` remain build context and database references respectively.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any

V1 = "v1"
V2 = "v2"


def _value(member: Any, name: str, default: str = "") -> str:
    value = member.get(name, default) if isinstance(member, Mapping) else getattr(member, name, default)
    return str(value or default)


def _v1_ordered(members: Sequence[Any]) -> list[Any]:
    """Preserve the historical writer ordering and JSON representation byte-for-byte."""
    base = [member for member in members if _value(member, "role") == "base"]
    splits = sorted((member for member in members if _value(member, "role") != "base"), key=lambda item: _value(item, "split_name"))
    return base + splits


def canonical_member_manifest(members: Sequence[Any]) -> list[dict[str, str]]:
    """Return a v2 canonical role/split/hash manifest without local metadata."""
    manifest: list[dict[str, str]] = []
    for member in members:
        role = _value(member, "role").strip().lower()
        role = "base" if role == "base" else "split"
        manifest.append(
            {
                "role": role,
                "split_name": _value(member, "split_name").strip().lower(),
                "sha256": _value(member, "sha256").strip().lower(),
            }
        )
    return sorted(manifest, key=lambda item: (item["role"], item["split_name"], item["sha256"]))


def compute_artifact_set_hash(members: Sequence[Any], *, version: str = V1) -> str:
    """Compute the requested versioned digest; no paths, IDs, or timestamps enter it."""
    if version == V1:
        # Deliberately retain default json.dumps separators and ensure_ascii behavior.
        return sha256(json.dumps([_value(member, "sha256") for member in _v1_ordered(members)]).encode("utf-8")).hexdigest()
    if version == V2:
        payload = json.dumps(canonical_member_manifest(members), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return sha256(payload.encode("utf-8")).hexdigest()
    raise ValueError(f"unsupported artifact_set_hash version: {version}")


def portable_set_identity(*, artifact_set_hash_version: str | None, artifact_set_hash: str | None) -> dict[str, str] | None:
    """Return the portable identity only when both version and digest are present."""
    version = str(artifact_set_hash_version or "").strip()
    digest = str(artifact_set_hash or "").strip().lower()
    return {"artifact_set_hash_version": version, "artifact_set_hash": digest} if version and digest else None
