"""Lightweight Android permission catalog helpers for static analysis."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence
from xml.etree import ElementTree

import yaml

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass(frozen=True)
class PermissionDescriptor:
    """Metadata captured for a single Android permission."""

    name: str
    protection: tuple[str, ...]
    source: str = "catalog"
    deprecated_api: Optional[int] = None
    added_api: Optional[int] = None

    def base_level(self) -> Optional[str]:
        for token in self.protection:
            lowered = token.lower()
            if lowered in {
                "normal",
                "dangerous",
                "signature",
                "signatureorsystem",
                "signatureorinstaller",
                "privileged",
                "installer",
            }:
                return lowered
        return None

    def guard_strength(self) -> str:
        """Return the guard strength bucket for the descriptor."""

        level = self.base_level()
        if level is None:
            return "unknown"
        if level in {"signature", "signatureorsystem", "signatureorinstaller", "privileged", "installer"}:
            return "signature"
        if level == "dangerous":
            return "dangerous"
        return "weak"


class PermissionCatalog:
    """In-memory lookup table for Android permission metadata."""

    def __init__(self, *, entries: Mapping[str, PermissionDescriptor], version: str) -> None:
        self._entries = {name.lower(): descriptor for name, descriptor in entries.items()}
        self.version = version

    def describe(self, name: str) -> Optional[PermissionDescriptor]:
        return self._entries.get(name.lower())

    def guard_strength(self, name: str) -> str:
        descriptor = self.describe(name)
        if descriptor is None:
            return "unknown"
        return descriptor.guard_strength()

    def to_snapshot(self, names: Iterable[str]) -> Mapping[str, Mapping[str, object]]:
        snapshot: MutableMapping[str, Mapping[str, object]] = {}
        for name in names:
            descriptor = self.describe(name)
            if descriptor is None:
                continue
            snapshot[name] = {
                "protection": descriptor.protection,
                "guard_strength": descriptor.guard_strength(),
                "source": descriptor.source,
                "added_api": descriptor.added_api,
                "deprecated_api": descriptor.deprecated_api,
            }
        return snapshot


def _load_yaml_catalog(path: Path) -> Mapping[str, PermissionDescriptor]:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, list):
        raise ValueError("framework_permissions.yaml must be a list")

    entries: MutableMapping[str, PermissionDescriptor] = {}
    for item in data:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("perm_name") or "").strip()
        if not name:
            continue
        protection_raw = item.get("protection") or item.get("protection_raw") or ""
        if isinstance(protection_raw, str):
            tokens = tuple(
                token.strip().lower()
                for token in protection_raw.split("|")
                if token and token.strip()
            )
        elif isinstance(protection_raw, Sequence):
            tokens = tuple(str(token).strip().lower() for token in protection_raw if token)
        else:
            tokens = tuple()
        entries[name] = PermissionDescriptor(
            name=name,
            protection=tokens,
            source=str(item.get("source") or "catalog"),
            added_api=_coerce_int(item.get("added_api")),
            deprecated_api=_coerce_int(item.get("deprecated_api")),
        )
    return entries


def _coerce_int(value: object) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _default_catalog_paths() -> tuple[Path, ...]:
    local = Path("config/framework_permissions.yaml")
    packaged = Path(__file__).parent.joinpath("data", "framework_permissions.yaml")
    candidates = []
    if packaged.exists():
        candidates.append(packaged)
    if local.exists():
        candidates.append(local)
    return tuple(candidates)


@lru_cache(maxsize=1)
def load_permission_catalog() -> PermissionCatalog:
    """Load the framework permission catalog from YAML sources."""

    for path in _default_catalog_paths():
        try:
            entries = _load_yaml_catalog(path)
        except Exception:
            continue
        if entries:
            version = path.stat().st_mtime_ns if path.exists() else 0
            return PermissionCatalog(entries=entries, version=str(version))
    # Fallback to empty catalog so lookups still succeed deterministically.
    return PermissionCatalog(entries={}, version="0")


def build_catalog_from_permissions_xml(xml_path: Path) -> PermissionCatalog:
    """Construct a catalog from ``platform.xml`` style permission manifests."""

    contents = xml_path.read_bytes()
    root = ElementTree.fromstring(contents)
    entries: MutableMapping[str, PermissionDescriptor] = {}
    for element in root.findall("permission"):
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue
        raw_level = (element.get(f"{_ANDROID_NS}protectionLevel") or "").strip()
        tokens = tuple(
            token.strip().lower()
            for token in raw_level.split("|")
            if token.strip()
        )
        entries[name] = PermissionDescriptor(
            name=name,
            protection=tokens,
            source="platform_xml",
        )
    return PermissionCatalog(entries=entries, version=str(xml_path.stat().st_mtime_ns))


def classify_permission(
    name: Optional[str],
    *,
    manifest_levels: Mapping[str, Sequence[str]] | None = None,
    catalog: PermissionCatalog | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Resolve guard strength for *name* using manifest + catalog metadata."""

    if not name:
        return "none", tuple()

    lookup_name = name.strip()
    manifest_tokens: Sequence[str] = ()
    if manifest_levels and lookup_name in manifest_levels:
        manifest_tokens = tuple(
            token.lower() for token in manifest_levels[lookup_name] if token
        )
    if manifest_tokens:
        descriptor = PermissionDescriptor(name=lookup_name, protection=tuple(manifest_tokens))
    else:
        catalog = catalog or load_permission_catalog()
        descriptor = catalog.describe(lookup_name) if catalog else None

    if descriptor is None:
        return "unknown", tuple()
    strength = descriptor.guard_strength()
    return strength, descriptor.protection


__all__ = [
    "PermissionCatalog",
    "PermissionDescriptor",
    "build_catalog_from_permissions_xml",
    "classify_permission",
    "load_permission_catalog",
]

