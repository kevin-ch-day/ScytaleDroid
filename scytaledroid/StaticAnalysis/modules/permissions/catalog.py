"""Lightweight Android permission catalog helpers for static analysis."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from xml.etree import ElementTree

import yaml


def _normalise_tokens(raw: object) -> tuple[str, ...]:
    if isinstance(raw, str):
        return tuple(token.strip().lower() for token in raw.split("|") if token and token.strip())
    if isinstance(raw, Sequence):
        return tuple(str(token).strip().lower() for token in raw if token)
    return tuple()


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_SHADOW_MODE_ENV = "SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE"
_SHADOW_MODES = frozenset({"LEGACY_ONLY", "COMPARE_ONLY"})


@dataclass(frozen=True)
class PermissionDescriptor:
    """Metadata captured for a single Android permission."""

    name: str
    protection: tuple[str, ...]
    source: str = "catalog"
    deprecated_api: int | None = None
    added_api: int | None = None
    declaration_state: str = "UNSPECIFIED"
    applicability_state: str = "UNSPECIFIED"
    protection_state: str = "UNSPECIFIED"

    def base_level(self) -> str | None:
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
        if level in {
            "signature",
            "signatureorsystem",
            "signatureorinstaller",
            "privileged",
            "installer",
        }:
            return "signature"
        if level == "dangerous":
            return "dangerous"
        return "weak"


class PermissionCatalog:
    """In-memory lookup table for Android permission metadata."""

    def __init__(
        self,
        *,
        entries: Mapping[str, PermissionDescriptor],
        version: str,
        case_sensitive: bool = False,
    ) -> None:
        self._case_sensitive = case_sensitive
        self._entries = {
            name if case_sensitive else name.lower(): descriptor
            for name, descriptor in entries.items()
        }
        self.version = version

    def describe(self, name: str) -> PermissionDescriptor | None:
        key = name if self._case_sensitive else name.lower()
        return self._entries.get(key)

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
                "declaration_state": descriptor.declaration_state,
                "applicability_state": descriptor.applicability_state,
                "protection_state": descriptor.protection_state,
            }
        return snapshot


def _load_yaml_catalog(
    path: Path, *, origin: str | None = None
) -> Mapping[str, PermissionDescriptor]:
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
        tokens = _normalise_tokens(protection_raw)
        entries[name] = PermissionDescriptor(
            name=name,
            protection=tokens,
            source=str(item.get("source") or origin or "catalog"),
            added_api=_coerce_int(item.get("added_api")),
            deprecated_api=_coerce_int(item.get("deprecated_api")),
        )
    return entries


def _load_db_catalog() -> tuple[Mapping[str, PermissionDescriptor], str]:
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_q
    except Exception:
        return {}, "0"

    try:
        rows = intel_q.fetch_v1_permission_catalog_rows()
    except Exception:
        return {}, "v1-unavailable" if intel_q.is_permission_intel_configured() else "0"
    if not rows:
        return {}, "0"

    entries: MutableMapping[str, PermissionDescriptor] = {}
    for row in rows:
        if not row:
            continue
        name = str(row.get("canonical_permission") or "").strip()
        if not name:
            continue
        protection_state = str(row.get("protection_state") or "UNKNOWN_UNSPECIFIED")
        tokens = (
            tuple()
            if protection_state.startswith("UNKNOWN_")
            else _normalise_tokens(row.get("compatibility_protection_expression"))
        )
        entries[name] = PermissionDescriptor(
            name=name,
            protection=tokens,
            source="permission_intel_v1_1_shadow",
            added_api=_coerce_int(row.get("accepted_platform_release")),
            deprecated_api=None,
            declaration_state=str(row.get("declaration_state") or "UNKNOWN"),
            applicability_state=str(row.get("applicability_state") or "UNKNOWN"),
            protection_state=protection_state,
        )

    version = str(len(entries))
    return entries, version


def _coerce_int(value: object) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _iter_yaml_files(directory: Path) -> Iterable[Path]:
    if not directory.exists() or not directory.is_dir():
        return ()
    files = []
    for pattern in ("*.yaml", "*.yml"):
        files.extend(sorted(directory.glob(pattern)))
    return tuple(files)


def _default_catalog_paths() -> tuple[Path, ...]:
    packaged = Path(__file__).parent.joinpath("data", "framework_permissions.yaml")
    config_file = Path("config/framework_permissions.yaml")
    config_dir = Path("config/permissions.d")
    data_file = Path("data/config/framework_permissions.yaml")
    data_dir = Path("data/config/permissions.d")

    candidates: list[Path] = []
    if packaged.exists():
        candidates.append(packaged)
    if config_file.exists():
        candidates.append(config_file)
    candidates.extend(_iter_yaml_files(config_dir))
    if data_file.exists():
        candidates.append(data_file)
    candidates.extend(_iter_yaml_files(data_dir))
    return tuple(candidates)


@lru_cache(maxsize=1)
def load_permission_catalog() -> PermissionCatalog:
    """Load the authoritative legacy framework-permission catalog.

    Candidate Permission Intel v1 data is deliberately excluded from this path.
    Call :func:`load_permission_catalog_shadow` for an isolated comparison.
    """

    for path in _default_catalog_paths():
        try:
            origin = path.stem
            entries = _load_yaml_catalog(path, origin=f"fallback_non_authoritative:{origin}")
        except Exception:
            continue
        if entries:
            version = path.stat().st_mtime_ns if path.exists() else 0
            return PermissionCatalog(entries=entries, version=str(version))
    # Fallback to empty catalog so lookups still succeed deterministically.
    return PermissionCatalog(entries={}, version="0")


def load_permission_catalog_shadow() -> PermissionCatalog | None:
    """Return an isolated candidate catalog only in explicit comparison mode.

    The returned object is never substituted into :func:`load_permission_catalog`.
    Callers performing diagnostics must compare it explicitly with the legacy
    result. Candidate absence or read failure is represented by ``None``.
    """

    mode = os.getenv(_SHADOW_MODE_ENV, "LEGACY_ONLY").strip().upper()
    if mode not in _SHADOW_MODES:
        allowed = ", ".join(sorted(_SHADOW_MODES))
        raise ValueError(f"{_SHADOW_MODE_ENV} must be one of: {allowed}")
    if mode == "LEGACY_ONLY":
        return None

    entries, version = _load_db_catalog()
    if not entries:
        return None
    return PermissionCatalog(entries=entries, version=version, case_sensitive=True)


def discover_catalog_paths() -> tuple[Path, ...]:
    """Expose catalog search paths for tooling/refresh helpers."""
    return _default_catalog_paths()


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
        tokens = tuple(token.strip().lower() for token in raw_level.split("|") if token.strip())
        entries[name] = PermissionDescriptor(
            name=name,
            protection=tokens,
            source="platform_xml",
        )
    return PermissionCatalog(
        entries=entries,
        version=str(xml_path.stat().st_mtime_ns),
        case_sensitive=True,
    )


def classify_permission(
    name: str | None,
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
        manifest_tokens = tuple(token.lower() for token in manifest_levels[lookup_name] if token)
    if manifest_tokens:
        descriptor = PermissionDescriptor(name=lookup_name, protection=tuple(manifest_tokens))
    else:
        catalog = catalog or load_permission_catalog()
        descriptor = catalog.describe(lookup_name) if catalog else None

    if descriptor is None:
        return "unknown", tuple()
    strength = descriptor.guard_strength()
    try:
        from .guard_policy import apply_guard_policy

        strength = apply_guard_policy(lookup_name, strength)
    except Exception:
        pass
    return strength, descriptor.protection


__all__ = [
    "PermissionCatalog",
    "PermissionDescriptor",
    "build_catalog_from_permissions_xml",
    "classify_permission",
    "load_permission_catalog",
    "load_permission_catalog_shadow",
    "discover_catalog_paths",
]
