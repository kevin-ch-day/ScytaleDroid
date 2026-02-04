"""Manifest evidence collectors for permission analysis."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.findings import EvidencePointer

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
PERMISSION_TAGS: tuple[str, ...] = (
    "uses-permission",
    "uses-permission-sdk-23",
    "uses-permission-sdk-m",
)


def index_manifest_permissions(
    manifest_root: ElementTree.Element,
) -> Mapping[str, Sequence[tuple[ElementTree.Element, str, int]]]:
    counters: MutableMapping[str, int] = defaultdict(int)
    mapping: MutableMapping[str, list[tuple[ElementTree.Element, str, int]]] = defaultdict(list)

    for element in manifest_root.iter():
        tag = element.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag not in PERMISSION_TAGS:
            continue
        permission_name = element.get(f"{ANDROID_NS}name")
        if not permission_name:
            continue
        counters[tag] += 1
        mapping[permission_name].append((element, tag, counters[tag]))

    return {name: tuple(entries) for name, entries in mapping.items()}


def manifest_pointer(
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


def collect_evidence(
    *,
    profile_severities: Mapping[str, int],
    manifest_nodes: Mapping[str, Sequence[tuple[ElementTree.Element, str, int]]],
    apk_path: Path,
    limit: int = 2,
) -> tuple[EvidencePointer, ...]:
    ranked = sorted(
        ((sev, name) for name, sev in profile_severities.items() if sev > 0),
        key=lambda item: (-item[0], item[1]),
    )

    pointers: list[EvidencePointer] = []
    for _, permission_name in ranked:
        nodes = manifest_nodes.get(permission_name)
        if not nodes:
            continue
        element, tag, index = nodes[0]
        pointer = manifest_pointer(apk_path, element, tag, index, permission_name)
        pointers.append(pointer)
        if len(pointers) >= limit:
            break
    return tuple(pointers)


__all__ = [
    "index_manifest_permissions",
    "collect_evidence",
    "manifest_pointer",
]