"""Helpers for profiling manifest permissions and surfacing risk clusters."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.context import DetectorContext
from scytaledroid.StaticAnalysis.core.findings import EvidencePointer

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_PERMISSION_TAGS: tuple[str, ...] = (
    "uses-permission",
    "uses-permission-sdk-23",
    "uses-permission-sdk-m",
)


@dataclass(frozen=True)
class PermissionAnalysis:
    """Structured payload returned by the permission profiling helpers."""

    summary: str
    metrics: Mapping[str, object]
    evidence: tuple[EvidencePointer, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class _PermissionProfile:
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


def build_permission_analysis(context: DetectorContext) -> PermissionAnalysis:
    declared = tuple(sorted(context.permissions.declared))
    custom_declared = set(context.permissions.custom)
    dangerous_declared = set(context.permissions.dangerous)

    permission_details = _safe_permission_details(context)
    protection_profiles = _build_protection_profiles(
        declared, permission_details, dangerous_declared
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
    manifest_nodes = _index_manifest_permissions(context.manifest_root)
    evidence = _collect_evidence(
        profiles=protection_profiles,
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
        for note in _build_notes(
            total=len(declared),
            dangerous=len(dangerous_permissions),
            signature=len(signature_permissions),
            privileged=len(privileged_permissions),
            special_access=len(special_permissions),
        )
        if note
    )

    summary = _format_summary(
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


def _normalise_protection_tokens(detail_entry: Sequence[object]) -> tuple[str, ...]:
    if not detail_entry:
        return ("normal",)
    raw = detail_entry[0] if detail_entry else None
    tokens = _tokenise_protection(raw)
    if not tokens:
        return ("normal",)
    return tuple(sorted(tokens))


def _tokenise_protection(raw: object) -> set[str]:
    tokens: set[str] = set()
    if raw is None:
        return tokens
    if isinstance(raw, (list, tuple, set)):
        for entry in raw:
            tokens.update(_tokenise_protection(entry))
        return tokens
    text = str(raw).lower()
    for delimiter in ("|", "/", ","):
        text = text.replace(delimiter, " ")
    for part in text.split():
        cleaned = part.strip()
        if cleaned:
            tokens.add(cleaned)
    return tokens


_SPECIAL_ACCESS_TOKENS = frozenset({"appop", "preinstalled", "development"})
_TOKEN_WEIGHTS = {
    "dangerous": 60,
    "signature": 80,
    "privileged": 70,
    "development": 40,
    "installer": 35,
    "appop": 45,
    "preinstalled": 30,
    "oem": 25,
}


def _is_special_access(tokens: Sequence[str]) -> bool:
    return any(token in _SPECIAL_ACCESS_TOKENS for token in tokens)


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


def _score_tokens(tokens: Sequence[str], *, is_custom: bool) -> int:
    score = 0
    for token in tokens:
        score += _TOKEN_WEIGHTS.get(token, 0)
    if "signature" in tokens and "privileged" in tokens:
        score += 20
    if "dangerous" in tokens and "appop" in tokens:
        score += 15
    if is_custom:
        score += 25
    return score


def _is_custom_permission(name: str) -> bool:
    return not name.startswith("android.permission.")


def _index_manifest_permissions(
    manifest_root: ElementTree.Element,
) -> Mapping[str, Sequence[tuple[ElementTree.Element, str, int]]]:
    counters: MutableMapping[str, int] = defaultdict(int)
    mapping: MutableMapping[str, list[tuple[ElementTree.Element, str, int]]] = defaultdict(list)

    for element in manifest_root.iter():
        tag = element.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag not in _PERMISSION_TAGS:
            continue
        permission_name = element.get(f"{_ANDROID_NS}name")
        if not permission_name:
            continue
        counters[tag] += 1
        mapping[permission_name].append((element, tag, counters[tag]))

    return {name: tuple(entries) for name, entries in mapping.items()}


def _collect_evidence(
    *,
    profiles: Mapping[str, _PermissionProfile],
    manifest_nodes: Mapping[str, Sequence[tuple[ElementTree.Element, str, int]]],
    apk_path: Path,
    limit: int = 2,
) -> tuple[EvidencePointer, ...]:
    ranked = sorted(
        (profile.severity, name) for name, profile in profiles.items()
    )
    ranked = [item for item in ranked if item[0] > 0]
    ranked.sort(key=lambda item: (-item[0], item[1]))

    pointers: list[EvidencePointer] = []
    for _, permission_name in ranked:
        nodes = manifest_nodes.get(permission_name)
        if not nodes:
            continue
        element, tag, index = nodes[0]
        pointer = _manifest_pointer(apk_path, element, tag, index, permission_name)
        pointers.append(pointer)
        if len(pointers) >= limit:
            break
    return tuple(pointers)


def _manifest_pointer(
    apk_path: Path,
    element: ElementTree.Element,
    tag: str,
    index: int,
    permission_name: str,
) -> EvidencePointer:
    location = (
        f"{apk_path.resolve().as_posix()}!AndroidManifest.xml:/manifest/{tag}[{index}]"
    )
    digest = hashlib.sha256(ElementTree.tostring(element, encoding="utf-8")).hexdigest()
    return EvidencePointer(
        location=location,
        hash_short=f"#h:{digest[:8]}",
        description=permission_name,
        extra={"tag": tag},
    )


def _format_summary(*, total: int, dangerous: int, signature: int, custom: int) -> str:
    if total == 0:
        return "No manifest permissions declared"
    parts = [f"Declared {total}"]
    parts.append(f"dangerous {dangerous}")
    parts.append(f"signature {signature}")
    parts.append(f"custom {custom}")
    return ", ".join(parts)


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


def _build_token_histogram(
    profiles: Mapping[str, _PermissionProfile]
) -> Counter[str]:
    tokens = Counter()
    for profile in profiles.values():
        tokens.update(profile.protection_tokens)
    return tokens


def _group_permissions(
    profiles: Mapping[str, _PermissionProfile]
) -> Mapping[str, list[str]]:
    groups: MutableMapping[str, list[str]] = defaultdict(list)
    for profile in profiles.values():
        if not profile.permission_group:
            continue
        groups[profile.permission_group].append(profile.name)
    return groups


def _build_notes(
    *,
    total: int,
    dangerous: int,
    signature: int,
    privileged: int,
    special_access: int,
) -> list[str]:
    notes: list[str] = []
    if total == 0:
        return notes
    if dangerous:
        notes.append(f"Contains {dangerous} runtime dangerous permission(s)")
    if signature:
        notes.append(f"Includes {signature} signature level permission(s)")
    if privileged:
        notes.append(f"Declares {privileged} privileged permission(s)")
    if special_access:
        notes.append("Requests permissions gated by special access workflows")
    return notes


__all__ = ["PermissionAnalysis", "build_permission_analysis"]
