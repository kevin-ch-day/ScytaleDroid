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
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass

from scytaledroid.StaticAnalysis.core.context import DetectorContext
from scytaledroid.StaticAnalysis.core.findings import EvidencePointer

from .analysis.db import fetch_framework_protections
from .analysis.evidence import collect_evidence, index_manifest_permissions
from .analysis.name_patterns import is_background_sensitive_name, is_health_permission_name
from .analysis.profiles import PermissionProfile, build_profiles
from .analysis.summarize import build_notes, format_summary
from .analysis.tokens import (
    is_custom_permission,
    is_special_access,
    normalize_tokens,
    score_permission,
)


@dataclass(frozen=True)
class PermissionAnalysis:
    """Structured payload returned by the permission profiling helpers."""

    summary: str
    metrics: Mapping[str, object]
    evidence: tuple[EvidencePointer, ...]
    notes: tuple[str, ...]


def _infer_permission_source(permission: str) -> str:
    if permission.startswith("android."):
        return "framework"
    if permission.startswith("com.google.android.gms."):
        return "play_services"
    namespace = permission.split(".", 1)[0] if "." in permission else permission
    return namespace or "custom"


def build_permission_analysis(context: DetectorContext) -> PermissionAnalysis:
    declared = tuple(sorted(context.permissions.declared))
    custom_declared = set(context.permissions.custom)
    dangerous_declared = set(context.permissions.dangerous)

    permission_details = _safe_permission_details(context)
    db_map: dict[str, str | None] = {}
    catalog = getattr(context, "permission_catalog", None)
    if catalog is not None:
        for name in declared:
            try:
                descriptor = catalog.describe(name)
            except Exception:
                descriptor = None
            if descriptor is not None and descriptor.protection:
                db_map[name] = "|".join(descriptor.protection)
    unresolved_shorts = _unresolved_android_framework_shorts(declared, db_map)
    if unresolved_shorts:
        short_map = fetch_framework_protections(unresolved_shorts)
        for short, value in (short_map or {}).items():
            if short not in db_map and value:
                db_map[short] = value
    protection_profiles = build_profiles(
        declared,
        permission_details,
        dangerous_declared,
        db_protections=db_map,
        permission_catalog=catalog,
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
    declared_tags = {
        name: entries[0][1]
        for name, entries in manifest_nodes.items()
        if entries
    }
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
        catalog_snapshot=context.permissions.catalog_snapshot,
        protection_levels=context.permissions.protection_levels,
        declared_map=declared_tags,
        permission_catalog=context.permission_catalog,
    )
    health_total = int(metrics.get("health_sensitive_total") or 0)
    background_total = int(metrics.get("background_sensitive_total") or 0)
    catalog_matched = int(metrics.get("catalog_matched_total") or 0)
    if health_total or background_total:
        metrics["summary"] = format_summary(
            total=len(declared),
            dangerous=len(dangerous_permissions),
            signature=len(signature_permissions),
            custom=len(custom_declared),
            health=health_total,
            background=background_total,
        )
        summary = str(metrics["summary"])
    notes = tuple(
        note
        for note in build_notes(
            total=len(declared),
            dangerous=len(dangerous_permissions),
            signature=len(signature_permissions),
            privileged=len(privileged_permissions),
            special_access=len(special_permissions),
            health=health_total,
            background=background_total,
            catalog_matched=catalog_matched,
        )
        if note
    )

    return PermissionAnalysis(
        summary=summary,
        metrics=metrics,
        evidence=evidence,
        notes=notes,
    )


def _unresolved_android_framework_shorts(
    declared: Iterable[str],
    db_map: Mapping[str, object],
) -> list[str]:
    """Return AOSP short names still missing after in-memory catalog fill."""

    return [
        name.split(".")[-1].upper()
        for name in declared
        if isinstance(name, str) and name.startswith("android.") and name not in db_map
    ]


def _safe_permission_details(context: DetectorContext) -> Mapping[str, Sequence[object]]:
    try:
        return context.apk.get_details_permissions() or {}
    except (KeyError, AttributeError):
        return {}


def _build_protection_profiles(
    declared: Iterable[str],
    details: Mapping[str, Sequence[object]],
    dangerous_declared: Iterable[str],
) -> MutableMapping[str, PermissionProfile]:
    dangerous_set = set(dangerous_declared)
    profiles: MutableMapping[str, PermissionProfile] = {}
    for name in declared:
        detail_entry = details.get(name, ())
        tokens = normalize_tokens(detail_entry)
        is_runtime = "dangerous" in tokens or name in dangerous_set
        is_signature = any(token.startswith("signature") for token in tokens)
        is_privileged = "privileged" in tokens
        is_special = is_special_access(tokens)
        group = _extract_permission_group(detail_entry)
        description = _extract_permission_description(detail_entry)
        severity = score_permission(tokens, is_custom=is_custom_permission(name), name=name)
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
        )
    return profiles


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
    profiles: Mapping[str, PermissionProfile],
    summary: str,
    catalog_snapshot: Mapping[str, Mapping[str, object]],
    protection_levels: Mapping[str, Sequence[str]],
    declared_map: Mapping[str, str],
    permission_catalog,
) -> Mapping[str, object]:
    dangerous_set = set(dangerous)
    signature_set = set(signature)
    privileged_set = set(privileged)
    custom_set = set(custom)
    special_set = set(special_permissions)
    catalog_snapshot = catalog_snapshot or {}
    protection_levels = protection_levels or {}
    declared_map = declared_map or {}
    flagged_normals_scored: set[str] = set()
    flagged_normals_all: set[str] = set()
    flagged_normal_classes: dict[str, set[str]] = {
        "noisy_normal": set(),
        "noteworthy_normal": set(),
        "special_risk_normal": set(),
    }

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
    overlay_group_map: dict[str, list[str]] = defaultdict(list)
    profile_payload: dict[str, dict[str, object]] = {}
    for name, profile in profiles.items():
        catalog_meta = catalog_snapshot.get(name, {})
        guard_strength = None
        catalog_source = None
        if isinstance(catalog_meta, Mapping):
            guard_strength = catalog_meta.get("guard_strength")
            catalog_source = catalog_meta.get("source")
        if permission_catalog:
            try:
                descriptor = permission_catalog.describe(name)
            except Exception:
                descriptor = None
            if descriptor is not None:
                if catalog_source is None:
                    catalog_source = descriptor.source
                if guard_strength is None:
                    guard_strength = descriptor.guard_strength()
        else:
            descriptor = None

        protection_entry = protection_levels.get(name)
        if isinstance(protection_entry, (list, tuple)):
            protection_listing = [token for token in protection_entry if token]
        elif protection_entry:
            protection_listing = [protection_entry]
        else:
            protection_listing = []

        declared_in = declared_map.get(name)
        source = _infer_permission_source(name)
        is_custom = is_custom_permission(name)
        flagged_normal_class = profile.flagged_normal_class
        is_flagged_normal = bool(profile.is_scored_flagged_normal)
        if flagged_normal_class:
            flagged_normals_all.add(name)
            flagged_normal_classes.setdefault(flagged_normal_class, set()).add(name)
        if is_flagged_normal:
            flagged_normals_scored.add(name)

        group = profile.permission_group
        if not group and descriptor is not None:
            group = descriptor.permission_group
        background_permission = None
        if descriptor is not None:
            background_permission = descriptor.background_permission
        authority_class = None
        if descriptor is not None:
            authority_class = descriptor.authority_class
        feature_dependency = None
        if descriptor is not None:
            feature_dependency = descriptor.feature_dependency

        profile_payload[name] = {
            "name": profile.name,
            "protection": profile.protection_label,
            "tokens": profile.protection_tokens,
            "group": group,
            "description": profile.description,
            "is_runtime_dangerous": profile.is_runtime_dangerous,
            "is_signature": profile.is_signature,
            "is_privileged": profile.is_privileged,
            "is_special_access": profile.is_special_access,
            "is_custom": is_custom,
            "severity": profile.severity,
            "guard_strength": guard_strength,
            "catalog_source": catalog_source,
            "protection_levels": protection_listing,
            "declared_in": declared_in,
            "source": source,
            "flagged_normal_class": flagged_normal_class,
            "is_scored_flagged_normal": is_flagged_normal,
            "is_flagged_normal": is_flagged_normal,
        }
        if background_permission:
            profile_payload[name]["background_permission"] = background_permission
        if authority_class:
            profile_payload[name]["authority_class"] = authority_class
        if feature_dependency:
            profile_payload[name]["feature_dependency"] = feature_dependency
        if group:
            overlay_group_map[str(group)].append(name)

    combined_groups = dict(group_summary or {})
    for group_name, names in overlay_group_map.items():
        existing = set(combined_groups.get(group_name, ()))
        existing.update(names)
        combined_groups[group_name] = sorted(existing)
    if combined_groups:
        metrics["permission_groups"] = {
            group: sorted(names) for group, names in sorted(combined_groups.items())
        }
    top_permissions = [
        {
            "name": payload["name"],
            "protection": payload["protection"],
            "group": payload.get("group"),
            "severity": payload["severity"],
        }
        for payload in sorted(
            profile_payload.values(),
            key=lambda item: (-int(item.get("severity") or 0), str(item.get("name") or "")),
        )
        if int(payload.get("severity") or 0) > 0
    ]
    if top_permissions:
        metrics["top_permissions"] = top_permissions

    metrics["permission_profiles"] = profile_payload
    metrics["flagged_normal_total"] = len(flagged_normals_scored)
    metrics["flagged_normal_all_total"] = len(flagged_normals_all)
    metrics["flagged_normal_class_counts"] = {
        key: len(value) for key, value in flagged_normal_classes.items() if value
    }
    if flagged_normals_scored:
        metrics["flagged_normal_permissions"] = sorted(flagged_normals_scored)
    if flagged_normals_all:
        metrics["flagged_normal_all_permissions"] = sorted(flagged_normals_all)
    for key, value in flagged_normal_classes.items():
        if value:
            metrics[f"{key}_permissions"] = sorted(value)

    catalog_matched: list[str] = []
    background_names: list[str] = []
    health_names: list[str] = []
    feature_names: list[str] = []
    unmatched_android: list[str] = []
    authority_counts: Counter[str] = Counter()
    for name, payload in profile_payload.items():
        lowered = str(name).lower()
        if payload.get("catalog_source"):
            catalog_matched.append(name)
        elif lowered.startswith("android."):
            unmatched_android.append(name)
        if payload.get("background_permission") or is_background_sensitive_name(name):
            background_names.append(name)
        group = str(payload.get("group") or "")
        if group.upper() == "HEALTH" or is_health_permission_name(name):
            health_names.append(name)
        if payload.get("feature_dependency"):
            feature_names.append(name)
        authority = payload.get("authority_class")
        if authority:
            authority_counts[str(authority)] += 1
    metrics["catalog_matched_total"] = len(catalog_matched)
    metrics["background_sensitive_total"] = len(background_names)
    metrics["health_sensitive_total"] = len(health_names)
    metrics["feature_dependent_total"] = len(feature_names)
    if catalog_matched:
        metrics["catalog_matched_permissions"] = sorted(catalog_matched)
    if background_names:
        metrics["background_sensitive_permissions"] = sorted(background_names)
    if health_names:
        metrics["health_sensitive_permissions"] = sorted(health_names)
    if feature_names:
        metrics["feature_dependent_permissions"] = sorted(feature_names)
    if unmatched_android:
        metrics["catalog_unmatched_android_permissions"] = sorted(unmatched_android)
        metrics["catalog_unmatched_android_total"] = len(unmatched_android)
    if authority_counts:
        metrics["authority_class_counts"] = {
            key: authority_counts[key] for key in sorted(authority_counts)
        }
    return metrics


def _build_token_histogram(profiles: Mapping[str, PermissionProfile]) -> Counter[str]:
    tokens = Counter()
    for profile in profiles.values():
        tokens.update(profile.protection_tokens)
    return tokens


def _group_permissions(profiles: Mapping[str, PermissionProfile]) -> Mapping[str, list[str]]:
    groups: MutableMapping[str, list[str]] = defaultdict(list)
    for profile in profiles.values():
        if not profile.permission_group:
            continue
        groups[profile.permission_group].append(profile.name)
    return groups


__all__ = ["PermissionAnalysis", "build_permission_analysis"]
