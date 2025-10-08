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

from .rules import GROUP_RULES, SENSITIVITY_WEIGHTS, SPECIAL_ACCESS_PERMISSIONS

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
    is_runtime_dangerous: bool
    is_signature: bool
    is_privileged: bool
    is_special_access: bool


_DEFAULT_PROFILE = _PermissionProfile(
    name="",
    protection_label="normal",
    protection_tokens=("normal",),
    is_runtime_dangerous=False,
    is_signature=False,
    is_privileged=False,
    is_special_access=False,
)


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
    special_access = {
        name
        for name, profile in protection_profiles.items()
        if profile.is_special_access
    }

    manifest_nodes = _index_manifest_permissions(context.manifest_root)
    evidence = _collect_evidence(
        declared_names=protection_profiles.keys(),
        dangerous=dangerous_permissions,
        special=special_access,
        manifest_nodes=manifest_nodes,
        apk_path=context.apk_path,
    )

    group_hits = _detect_group_hits(declared, protection_profiles)
    notes = tuple(_format_group_notes(group_hits))

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
        special=special_access,
        level_counts=level_counts,
        group_hits=group_hits,
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
        is_special = name in SPECIAL_ACCESS_PERMISSIONS
        profiles[name] = _PermissionProfile(
            name=name,
            protection_label="|".join(tokens) if tokens else "unknown",
            protection_tokens=tokens,
            is_runtime_dangerous=is_runtime,
            is_signature=is_signature,
            is_privileged=is_privileged,
            is_special_access=is_special,
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
    declared_names: Iterable[str],
    dangerous: Iterable[str],
    special: Iterable[str],
    manifest_nodes: Mapping[str, Sequence[tuple[ElementTree.Element, str, int]]],
    apk_path: Path,
    limit: int = 2,
) -> tuple[EvidencePointer, ...]:
    ranked: list[tuple[int, str]] = []
    dangerous_set = set(dangerous)
    special_set = set(special)
    for name in declared_names:
        weight = SENSITIVITY_WEIGHTS.get(name, 10)
        if name in dangerous_set:
            weight += 40
        if name in special_set:
            weight += 30
        if weight <= 10:
            continue
        ranked.append((weight, name))

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


def _detect_group_hits(
    declared: Sequence[str],
    profiles: Mapping[str, _PermissionProfile],
) -> Mapping[str, Sequence[str]]:
    declared_set = set(declared)
    hits: MutableMapping[str, list[str]] = {}
    for rule in GROUP_RULES:
        matching = sorted(declared_set.intersection(rule.members))
        if len(matching) < rule.threshold:
            continue
        qualifies = False
        for name in matching:
            profile = profiles.get(name, _DEFAULT_PROFILE)
            if profile.is_runtime_dangerous or profile.is_special_access:
                qualifies = True
                break
        if not qualifies:
            continue
        hits[rule.key] = matching
    return hits


def _format_group_notes(group_hits: Mapping[str, Sequence[str]]) -> list[str]:
    notes: list[str] = []
    for rule in GROUP_RULES:
        matches = group_hits.get(rule.key)
        if not matches:
            continue
        note = f"{rule.title}: {', '.join(matches)}"
        notes.append(note)
    return notes


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
    special: Iterable[str],
    level_counts: Counter,
    group_hits: Mapping[str, Sequence[str]],
    summary: str,
) -> Mapping[str, object]:
    dangerous_set = set(dangerous)
    signature_set = set(signature)
    privileged_set = set(privileged)
    custom_set = set(custom)
    special_set = set(special)

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
        "dangerous_permissions": sorted(dangerous_set),
        "special_access_permissions": sorted(special_set),
        "signature_permissions": sorted(signature_set),
        "privileged_permissions": sorted(privileged_set),
    }
    if group_hits:
        metrics["notable_groups"] = {
            key: list(value) for key, value in sorted(group_hits.items())
        }
    if custom_set:
        metrics["custom_permissions"] = sorted(custom_set)
    return metrics


__all__ = ["PermissionAnalysis", "build_permission_analysis"]
