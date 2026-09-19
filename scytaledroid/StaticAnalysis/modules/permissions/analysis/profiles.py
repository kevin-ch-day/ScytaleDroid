"""Profile builder for manifest permissions with DB-aware protection mapping."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass

from .tokens import (
    classify_flagged_normal,
    is_custom_permission,
    is_scored_flagged_normal,
    is_special_access,
    normalize_tokens,
    score_permission,
    tokens_from_db,
)


@dataclass(frozen=True)
class PermissionProfile:
    name: str
    protection_label: str
    protection_tokens: tuple[str, ...]
    permission_group: str | None
    description: str | None
    is_runtime_dangerous: bool
    is_signature: bool
    is_privileged: bool
    is_special_access: bool
    severity: int
    flagged_normal_class: str | None
    is_scored_flagged_normal: bool


def build_profiles(
    declared: Iterable[str],
    details: Mapping[str, Sequence[object]],
    dangerous_declared: Iterable[str],
    *,
    db_protections: Mapping[str, str | None] | None = None,
    permission_catalog: object | None = None,
) -> MutableMapping[str, PermissionProfile]:
    dangerous_set = set(dangerous_declared)
    profiles: MutableMapping[str, PermissionProfile] = {}
    db_protections = db_protections or {}

    def _extract_group(detail_entry: Sequence[object]) -> str | None:
        for entry in detail_entry:
            if isinstance(entry, str) and entry.startswith("android.permission-group."):
                return entry.rsplit(".", 1)[-1]
        return None

    def _extract_description(detail_entry: Sequence[object]) -> str | None:
        for entry in detail_entry:
            if not isinstance(entry, str):
                continue
            candidate = entry.strip()
            if not candidate:
                continue
            if candidate.startswith("android.permission-group."):
                continue
            if candidate.startswith("android.permission"):
                continue
            return candidate
        return None

    for name in declared:
        detail_entry = details.get(name, ())
        short = name.split(".")[-1].upper()
        tokens = normalize_tokens(detail_entry)
        db_value = None
        if db_protections:
            db_value = db_protections.get(name)
            if db_value in (None, ""):
                db_value = db_protections.get(short)
        db_tokens = tokens_from_db(db_value) if db_value is not None else None
        if db_tokens:
            tokens = db_tokens
        is_runtime = "dangerous" in tokens or name in dangerous_set
        is_signature = any(token.startswith("signature") for token in tokens)
        is_privileged = "privileged" in tokens
        is_special = is_special_access(tokens)
        group = _extract_group(detail_entry)
        description = _extract_description(detail_entry)
        descriptor = None
        if permission_catalog is not None:
            try:
                describe = getattr(permission_catalog, "describe", None)
                descriptor = describe(name) if callable(describe) else None
            except Exception:
                descriptor = None
        if not group and descriptor is not None:
            group = getattr(descriptor, "permission_group", None)
        background_permission = (
            getattr(descriptor, "background_permission", None) if descriptor is not None else None
        )
        authority_class = (
            getattr(descriptor, "authority_class", None) if descriptor is not None else None
        )
        feature_dependency = (
            getattr(descriptor, "feature_dependency", None) if descriptor is not None else None
        )
        is_custom = is_custom_permission(name)
        severity = score_permission(
            tokens,
            is_custom=is_custom,
            name=name,
            permission_group=group,
            background_permission=background_permission,
            authority_class=authority_class,
            feature_dependency=feature_dependency,
        )
        flagged_normal_class = classify_flagged_normal(
            name,
            tokens=tokens,
            severity=severity,
            is_runtime_dangerous=is_runtime,
            is_signature=is_signature,
            is_privileged=is_privileged,
            is_special_access=is_special,
            is_custom=is_custom,
        )
        profiles[name] = PermissionProfile(
            name=name,
            protection_label="|".join(tokens) if tokens else "unknown",
            protection_tokens=tokens,
            permission_group=group,
            description=description,
            is_runtime_dangerous=is_runtime,
            is_signature=is_signature,
            is_privileged=is_privileged,
            is_special_access=is_special,
            severity=severity,
            flagged_normal_class=flagged_normal_class,
            is_scored_flagged_normal=is_scored_flagged_normal(flagged_normal_class),
        )
    return profiles


__all__ = ["PermissionProfile", "build_profiles"]
