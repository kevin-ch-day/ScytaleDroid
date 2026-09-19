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
    permission_group: str | None = None
    background_permission: str | None = None
    authority_class: str | None = None
    feature_dependency: str | None = None

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
                "internal",
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
            "internal",
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
                "permission_group": descriptor.permission_group,
                "background_permission": descriptor.background_permission,
                "authority_class": descriptor.authority_class,
                "feature_dependency": descriptor.feature_dependency,
            }
        return snapshot

    def merge_protection_levels(
        self,
        names: Iterable[str],
        existing: Mapping[str, Sequence[str]] | None = None,
    ) -> dict[str, tuple[str, ...]]:
        """Keep APK-declared levels and fill gaps from this catalog."""

        merged: dict[str, tuple[str, ...]] = {}
        for name, levels in (existing or {}).items():
            key = str(name or "").strip()
            tokens = tuple(str(token).strip().lower() for token in levels if token)
            if key and tokens:
                merged[key] = tokens
        for name in names:
            key = str(name or "").strip()
            if not key or key in merged:
                continue
            descriptor = self.describe(key)
            if descriptor is None or not descriptor.protection:
                continue
            merged[key] = descriptor.protection
        return merged


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


def _canonical_permission_group(value: object) -> str | None:
    """Match APK group shorts; drop v1 UNDEFINED placeholders."""

    text = str(value or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered.startswith("android.permission-group."):
        text = text.rsplit(".", 1)[-1]
    if text.upper() == "UNDEFINED":
        return None
    return text


def _descriptor_from_v1_row(row: Mapping[str, object]) -> PermissionDescriptor | None:
    name = str(row.get("canonical_permission") or "").strip()
    if not name:
        return None
    protection_state = str(row.get("protection_state") or "UNSPECIFIED")
    protection_expr = row.get("compatibility_protection_expression") or row.get("protection_base")
    tokens = (
        tuple()
        if protection_state.startswith("UNKNOWN_")
        else _normalise_tokens(protection_expr)
    )
    group = _canonical_permission_group(row.get("permission_group"))
    background = str(row.get("background_permission") or "").strip() or None
    authority = str(row.get("authority_class") or "").strip() or None
    feature = str(row.get("feature_dependency") or "").strip() or None
    return PermissionDescriptor(
        name=name,
        protection=tokens,
        source="permission_intel_v1",
        added_api=_coerce_int(row.get("accepted_platform_release")),
        deprecated_api=None,
        declaration_state=str(
            row.get("declaration_state") or row.get("lifecycle") or "UNSPECIFIED"
        ),
        applicability_state=str(row.get("applicability_state") or "UNSPECIFIED"),
        protection_state=protection_state,
        permission_group=group,
        background_permission=background,
        authority_class=authority,
        feature_dependency=feature,
    )


def _load_db_catalog() -> tuple[Mapping[str, PermissionDescriptor], str]:
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_q
    except Exception:
        return {}, "0"

    if not intel_q.is_permission_intel_configured():
        return {}, "0"

    entries: MutableMapping[str, PermissionDescriptor] = {}
    present: set[str] = set()

    def _add(descriptor: PermissionDescriptor) -> None:
        key = descriptor.name.casefold()
        if not key or key in present:
            return
        present.add(key)
        entries[descriptor.name] = descriptor

    try:
        for row in intel_q.fetch_v1_permission_catalog_rows() or []:
            if not row:
                continue
            descriptor = _descriptor_from_v1_row(row)
            if descriptor is not None:
                _add(descriptor)
    except Exception:
        pass

    try:
        for row in intel_q.fetch_aosp_permission_catalog_rows() or []:
            if not row:
                continue
            name = str(row[0] or "").strip()
            protection = str(row[1] or "").strip()
            if not name or not protection:
                continue
            _add(
                PermissionDescriptor(
                    name=name,
                    protection=_normalise_tokens(protection),
                    source="permission_intel_aosp_dict",
                    added_api=_coerce_int(row[2] if len(row) > 2 else None),
                    deprecated_api=_coerce_int(row[3] if len(row) > 3 else None),
                )
            )
    except Exception:
        pass

    try:
        for row in intel_q.fetch_oem_permission_catalog_rows() or []:
            if not row:
                continue
            name = str(row[0] or "").strip()
            protection = str(row[1] or "").strip()
            if not name or not protection:
                continue
            _add(
                PermissionDescriptor(
                    name=name,
                    protection=_normalise_tokens(protection),
                    source="permission_intel_oem_dict",
                )
            )
    except Exception:
        pass

    if not entries:
        return {}, "0"
    return entries, str(len(entries))


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
    """Load the analysis catalog: deployed Permission Intel v1, then YAML.

    YAML is the offline fallback when Permission Intel is unset, unreachable,
    or the accepted v1 projection is empty. Call
    :func:`load_permission_catalog_shadow` for an isolated COMPARE_ONLY read.
    """

    db_entries, db_version = _load_db_catalog()
    if db_entries:
        return PermissionCatalog(entries=db_entries, version=db_version)
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
    """Return an isolated deployed-v1 catalog only in explicit comparison mode.

    COMPARE_ONLY is a diagnostic read. Analysis already prefers the same
    deployed v1 projection through :func:`load_permission_catalog` when PI is
    reachable; this helper never writes and never enables PI mutation.
    Candidate absence or read failure is represented by ``None``.
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
