"""Permission profiling orchestrator.

This module assembles a PermissionAnalysis from multiple small helpers:
 - analysis.db:     DB-backed protection lookups (optional)
 - analysis.tokens: Protection token parsing and scoring
 - analysis.profiles: Build PermissionProfile entries
 - analysis.evidence: Manifest evidence pointers
 - analysis.summarize: Summary/notes strings

Public API remains stable: ``build_permission_analysis`` returns a
PermissionAnalysis suitable for detectors and reporting.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Sequence

from scytaledroid.StaticAnalysis.core.context import DetectorContext
from scytaledroid.StaticAnalysis.core.findings import EvidencePointer

from .analysis.db import fetch_framework_protections
from .analysis.tokens import normalize_tokens, tokenise_protection, is_special_access, is_custom_permission, score_tokens
from .analysis.profiles import PermissionProfile, build_profiles
from .analysis.evidence import index_manifest_permissions, collect_evidence
from .analysis.summarize import format_summary, build_notes


@dataclass(frozen=True)
class PermissionAnalysis:
    """Structured payload returned by the permission profiling helpers."""

    summary: str
    metrics: Mapping[str, object]
    evidence: tuple[EvidencePointer, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class _PermissionProfile(PermissionProfile):  # Back-compat alias
    pass


def build_permission_analysis(context: DetectorContext) -> PermissionAnalysis:
    declared = tuple(sorted(context.permissions.declared))
    custom_declared = set(context.permissions.custom)
    dangerous_declared = set(context.permissions.dangerous)

    permission_details = _safe_permission_details(context)
    db_map = fetch_framework_protections(
        [name.split(".")[-1].upper() for name in declared if name.startswith("android.")]
    )
    protection_profiles = build_profiles(
        declared, permission_details, dangerous_declared, db_protections=db_map
    )

    level_counts = Counter(
        profile.protection_label for profile in protection_profiles.values()
    )
    dangerous_permissions = {
        name
        for name, profile in protection_profiles.items()
        if profile.is_runtime_dangerous
    }
    signature_permissions = {
        name
        for name, profile in protection_profiles.items()
        if profile.is_signature
    }
    privileged_permissions = {
        name
        for name, profile in protection_profiles.items()
        if profile.is_privileged
    }
    manifest_nodes = index_manifest_permissions(context.manifest_root)
    evidence = collect_evidence(
        profile_severities={k: v.severity for k, v in protection_profiles.items()},
        manifest_nodes=manifest_nodes,
        apk_path=context.apk_path,
    )

    token_histogram = _build_token_histogram(protection_profiles)
    group_summary = _group_permissions(protection_profiles)
    special_permissions = {
        name
        for name, profile in protection_profiles.items()
        if profile.is_special_access
    }
    notes = tuple(
        note
        for note in build_notes(
            total=len(declared),
            dangerous=len(dangerous_permissions),
            signature=len(signature_permissions),
            privileged=len(privileged_permissions),
            special_access=len(special_permissions),
        )
        if note
    )

    summary = format_summary(
        total=len(declared),
        dangerous=len(dangerous_permissions),
        signature=len(signature_permissions),
        custom=len(custom_declared),
    )

    metrics = _build_metrics(
        total=len(declared),
        dangerous=dangerous_permissions,
        signature=signature_permissions,
        privileged=privileged_permissions,
        custom=custom_declared,
        level_counts=level_counts,
        token_histogram=token_histogram,
        group_summary=group_summary,
        special_permissions=special_permissions,
        profiles=protection_profiles,
        summary=summary,
    )

    return PermissionAnalysis(
        summary=summary,
        metrics=metrics,
        evidence=evidence,
        notes=notes,
    )


def _safe_permission_details(context: DetectorContext) -> Mapping[str, Sequence[object]]:
    try:
        return context.apk.get_details_permissions() or {}
    except (KeyError, AttributeError):
        return {}


def _build_protection_profiles(
    declared: Iterable[str],
    details: Mapping[str, Sequence[object]],
    dangerous_declared: Iterable[str],
) -> MutableMapping[str, _PermissionProfile]:
    dangerous_set = set(dangerous_declared)
    profiles: MutableMapping[str, _PermissionProfile] = {}
    for name in declared:
        detail_entry = details.get(name, ())
        tokens = _normalise_protection_tokens(detail_entry)
        is_runtime = "dangerous" in tokens or name in dangerous_set
        is_signature = any(token.startswith("signature") for token in tokens)
        is_privileged = "privileged" in tokens
        is_special = _is_special_access(tokens)
        group = _extract_permission_group(detail_entry)
        description = _extract_permission_description(detail_entry)
        severity = _score_tokens(tokens, is_custom=_is_custom_permission(name))
        profiles[name] = _PermissionProfile(
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
        )
    return profiles


def _normalise_protection_tokens(detail_entry: Sequence[object]) -> tuple[str, ...]:  # Back-compat
    return normalize_tokens(detail_entry)


def _extract_permission_group(detail_entry: Sequence[object]) -> str | None:
    for entry in detail_entry:
        if isinstance(entry, str) and entry.startswith("android.permission-group."):
            return entry.rsplit(".", 1)[-1]
    return None


def _extract_permission_description(detail_entry: Sequence[object]) -> str | None:
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


def _score_tokens(tokens: Sequence[str], *, is_custom: bool) -> int:  # Back-compat
    return score_tokens(tokens, is_custom=is_custom)


def _is_custom_permission(name: str) -> bool:  # Back-compat
    return is_custom_permission(name)


def _index_manifest_permissions(manifest_root):  # Back-compat
    return index_manifest_permissions(manifest_root)


def _collect_evidence(*, profiles, manifest_nodes, apk_path, limit=2):  # Back-compat
    profile_sev = {k: v.severity for k, v in profiles.items()}
    return collect_evidence(profile_severities=profile_sev, manifest_nodes=manifest_nodes, apk_path=apk_path, limit=limit)


def _manifest_pointer(*args, **kwargs):  # Back-compat shim
    from .analysis.evidence import manifest_pointer
    return manifest_pointer(*args, **kwargs)


def _format_summary(*, total: int, dangerous: int, signature: int, custom: int) -> str:  # Back-compat
    return format_summary(total=total, dangerous=dangerous, signature=signature, custom=custom)


def _build_metrics(
    *,
    total: int,
    dangerous: Iterable[str],
    signature: Iterable[str],
    privileged: Iterable[str],
    custom: Iterable[str],
    level_counts: Counter,
    token_histogram: Mapping[str, int],
    group_summary: Mapping[str, Sequence[str]],
    special_permissions: Iterable[str],
    profiles: Mapping[str, _PermissionProfile],
    summary: str,
) -> Mapping[str, object]:
    dangerous_set = set(dangerous)
    signature_set = set(signature)
    privileged_set = set(privileged)
    custom_set = set(custom)
    special_set = set(special_permissions)

    top_permissions = [
        {
            "name": profile.name,
            "protection": profile.protection_label,
            "group": profile.permission_group,
            "severity": profile.severity,
        }
        for profile in sorted(
            profiles.values(),
            key=lambda profile: (-profile.severity, profile.name),
        )
        if profile.severity > 0
    ]

    metrics: dict[str, object] = {
        "summary": summary,
        "total_declared": total,
        "dangerous_total": len(dangerous_set),
        "signature_total": len(signature_set),
        "privileged_total": len(privileged_set),
        "custom_total": len(custom_set),
        "special_access_total": len(special_set),
        "protection_counts": {
            level: level_counts[level]
            for level in sorted(level_counts.keys())
        },
        "protection_tokens": {
            token: token_histogram[token]
            for token in sorted(token_histogram.keys())
        },
        "dangerous_permissions": sorted(dangerous_set),
        "signature_permissions": sorted(signature_set),
        "privileged_permissions": sorted(privileged_set),
    }
    if custom_set:
        metrics["custom_permissions"] = sorted(custom_set)
    if special_set:
        metrics["special_access_permissions"] = sorted(special_set)
    if group_summary:
        metrics["permission_groups"] = {
            group: sorted(names) for group, names in sorted(group_summary.items())
        }
    if top_permissions:
        metrics["top_permissions"] = top_permissions
    metrics["permission_profiles"] = {
        name: {
            "name": profile.name,
            "protection": profile.protection_label,
            "tokens": profile.protection_tokens,
            "group": profile.permission_group,
            "description": profile.description,
            "is_runtime_dangerous": profile.is_runtime_dangerous,
            "is_signature": profile.is_signature,
            "is_privileged": profile.is_privileged,
            "is_special_access": profile.is_special_access,
            "is_custom": _is_custom_permission(name),
            "severity": profile.severity,
        }
        for name, profile in profiles.items()
    }
    return metrics


def _build_token_histogram(profiles: Mapping[str, _PermissionProfile]) -> Counter[str]:
    tokens = Counter()
    for profile in profiles.values():
        tokens.update(profile.protection_tokens)
    return tokens


def _group_permissions(profiles: Mapping[str, _PermissionProfile]) -> Mapping[str, list[str]]:
    groups: MutableMapping[str, list[str]] = defaultdict(list)
    for profile in profiles.values():
        if not profile.permission_group:
            continue
        groups[profile.permission_group].append(profile.name)
    return groups


def _build_notes(*, total: int, dangerous: int, signature: int, privileged: int, special_access: int) -> list[str]:  # Back-compat
    return build_notes(total=total, dangerous=dangerous, signature=signature, privileged=privileged, special_access=special_access)


__all__ = ["PermissionAnalysis", "build_permission_analysis"]
