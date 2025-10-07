"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence
from xml.etree import ElementTree

from androguard.core.apk import APK

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes, normalise_local_path


class StaticAnalysisError(Exception):
    """Raised when an APK cannot be processed."""


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass(frozen=True)
class ManifestSummary:
    """Key manifest attributes extracted from the APK."""

    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    compile_sdk: Optional[str] = None
    app_label: Optional[str] = None
    main_activity: Optional[str] = None

    def to_dict(self) -> MutableMapping[str, Optional[str]]:
        return asdict(self)


@dataclass(frozen=True)
class ComponentSummary:
    """Lists of Android components declared by the application."""

    activities: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    receivers: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()

    def to_dict(self) -> MutableMapping[str, Iterable[str]]:
        return asdict(self)

    def total(self) -> int:
        return sum(len(collection) for collection in self.to_dict().values())


@dataclass(frozen=True)
class PermissionSummary:
    """Permissions declared by the APK."""

    declared: tuple[str, ...] = ()
    dangerous: tuple[str, ...] = ()
    custom: tuple[str, ...] = ()

    def to_dict(self) -> MutableMapping[str, Iterable[str]]:
        return asdict(self)


@dataclass(frozen=True)
class ManifestFlags:
    """Notable manifest booleans converted to python primitives."""

    uses_cleartext_traffic: Optional[bool] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None

    def to_dict(self) -> MutableMapping[str, Optional[bool]]:
        return asdict(self)


@dataclass(frozen=True)
class StaticAnalysisReport:
    """Static analysis artefact captured for an APK."""

    file_path: str
    relative_path: Optional[str]
    file_name: str
    file_size: int
    hashes: Mapping[str, str]
    manifest: ManifestSummary = field(default_factory=ManifestSummary)
    manifest_flags: ManifestFlags = field(default_factory=ManifestFlags)
    permissions: PermissionSummary = field(default_factory=PermissionSummary)
    components: ComponentSummary = field(default_factory=ComponentSummary)
    exported_components: ComponentSummary = field(default_factory=ComponentSummary)
    features: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, object]:
        """Serialise the report to primitives for JSON storage."""

        payload = {
            "file_path": self.file_path,
            "relative_path": self.relative_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "hashes": dict(self.hashes),
            "manifest": self.manifest.to_dict(),
            "manifest_flags": self.manifest_flags.to_dict(),
            "permissions": self.permissions.to_dict(),
            "components": self.components.to_dict(),
            "exported_components": self.exported_components.to_dict(),
            "features": list(self.features),
            "libraries": list(self.libraries),
            "signatures": list(self.signatures),
            "metadata": dict(self.metadata),
            "generated_at": self.generated_at,
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "StaticAnalysisReport":
        """Reconstruct a report from its dictionary representation."""

        manifest = ManifestSummary(**_subset(payload.get("manifest", {}), ManifestSummary))
        flags = ManifestFlags(**_subset(payload.get("manifest_flags", {}), ManifestFlags))
        permissions = PermissionSummary(
            **{
                "declared": tuple(payload.get("permissions", {}).get("declared", ())),
                "dangerous": tuple(payload.get("permissions", {}).get("dangerous", ())),
                "custom": tuple(payload.get("permissions", {}).get("custom", ())),
            }
        )
        components = ComponentSummary(
            **{
                "activities": tuple(payload.get("components", {}).get("activities", ())),
                "services": tuple(payload.get("components", {}).get("services", ())),
                "receivers": tuple(payload.get("components", {}).get("receivers", ())),
                "providers": tuple(payload.get("components", {}).get("providers", ())),
            }
        )
        exported = ComponentSummary(
            **{
                "activities": tuple(
                    payload.get("exported_components", {}).get("activities", ())
                ),
                "services": tuple(
                    payload.get("exported_components", {}).get("services", ())
                ),
                "receivers": tuple(
                    payload.get("exported_components", {}).get("receivers", ())
                ),
                "providers": tuple(
                    payload.get("exported_components", {}).get("providers", ())
                ),
            }
        )

        metadata_raw = payload.get("metadata")
        metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}

        return cls(
            file_path=str(payload.get("file_path") or ""),
            relative_path=payload.get("relative_path") or None,
            file_name=str(payload.get("file_name") or Path(payload.get("file_path") or "").name),
            file_size=int(payload.get("file_size") or 0),
            hashes={str(k): str(v) for k, v in dict(payload.get("hashes", {})).items()},
            manifest=manifest,
            manifest_flags=flags,
            permissions=permissions,
            components=components,
            exported_components=exported,
            features=tuple(payload.get("features", ())),
            libraries=tuple(payload.get("libraries", ())),
            signatures=tuple(payload.get("signatures", ())),
            metadata=metadata,
            generated_at=str(payload.get("generated_at") or datetime.now(timezone.utc).isoformat()),
        )


def _subset(source: object, model: type) -> dict[str, object]:
    """Return mapping of dataclass field names in *model* from *source*."""

    if not isinstance(source, Mapping):
        return {}
    fields = {field.name for field in model.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    return {name: source.get(name) for name in fields}


def _coerce_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _collect_dangerous_permissions(
    permission_details: Mapping[str, Sequence[object]]
) -> tuple[str, ...]:
    """Return the subset of permissions marked as dangerous by Androguard."""

    dangerous: set[str] = set()
    for name, detail in permission_details.items():
        if not detail:
            continue
        protection_level = detail[0]
        if not isinstance(protection_level, str):
            continue
        if "dangerous" in protection_level.lower():
            dangerous.add(name)
    return tuple(sorted(dangerous))


def _load_manifest_root(apk: APK) -> ElementTree.Element:
    """Return the parsed AndroidManifest root element."""

    try:
        manifest_xml = apk.get_android_manifest_xml()
    except Exception as exc:  # pragma: no cover - defensive, androguard handles parsing
        raise StaticAnalysisError(f"Unable to parse AndroidManifest.xml: {exc}") from exc

    try:
        return ElementTree.fromstring(manifest_xml)
    except ElementTree.ParseError as exc:
        raise StaticAnalysisError(f"Malformed AndroidManifest.xml: {exc}") from exc


def _build_manifest_flags(root: ElementTree.Element) -> ManifestFlags:
    """Extract notable booleans from the manifest tree."""

    application = root.find("application")
    if application is None:
        return ManifestFlags()

    return ManifestFlags(
        uses_cleartext_traffic=_coerce_bool(application.get(f"{_ANDROID_NS}usesCleartextTraffic")),
        debuggable=_coerce_bool(application.get(f"{_ANDROID_NS}debuggable")),
        allow_backup=_coerce_bool(application.get(f"{_ANDROID_NS}allowBackup")),
    )


def _extract_compile_sdk(root: ElementTree.Element) -> Optional[str]:
    """Best-effort extraction of compile SDK metadata from the manifest."""

    value = root.get(f"{_ANDROID_NS}compileSdkVersion") or root.get("platformBuildVersionCode")
    if value:
        return str(value)
    return None


def _resolve_relative_path(apk_path: Path, storage_root: Optional[Path]) -> Optional[str]:
    if storage_root is None:
        root = Path(app_config.DATA_DIR).resolve()
        apk_resolved = apk_path.resolve()
        if apk_resolved.is_relative_to(root):
            storage_root = root
        else:
            storage_root = None

    if storage_root is None:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None

    try:
        return apk_path.resolve().relative_to(storage_root.resolve()).as_posix()
    except ValueError:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None


def analyze_apk(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
) -> StaticAnalysisReport:
    """Run lightweight static analysis on *apk_path* and return a report."""

    if not apk_path.exists():
        raise StaticAnalysisError(f"APK not found: {apk_path}")

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    manifest_root = _load_manifest_root(apk)
    flags = _build_manifest_flags(manifest_root)
    compile_sdk = _extract_compile_sdk(manifest_root)

    hashes = compute_hashes(apk_path)
    manifest = ManifestSummary(
        package_name=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        compile_sdk=compile_sdk,
        app_label=apk.get_app_name(),
        main_activity=apk.get_main_activity(),
    )

    declared_permissions = tuple(sorted(apk.get_permissions()))
    permission_details = apk.get_details_permissions()
    dangerous = _collect_dangerous_permissions(permission_details)
    custom_permissions = tuple(sorted(apk.get_declared_permissions()))

    permissions = PermissionSummary(
        declared=declared_permissions,
        dangerous=dangerous,
        custom=custom_permissions,
    )

    components = ComponentSummary(
        activities=tuple(sorted(apk.get_activities())),
        services=tuple(sorted(apk.get_services())),
        receivers=tuple(sorted(apk.get_receivers())),
        providers=tuple(sorted(apk.get_providers())),
    )
    exported = ComponentSummary(
        activities=tuple(sorted(apk.get_exported_activities())),
        services=tuple(sorted(apk.get_exported_services())),
        receivers=tuple(sorted(apk.get_exported_receivers())),
        providers=tuple(sorted(apk.get_exported_content_providers())),
    )

    features = tuple(sorted(apk.get_features()))
    libraries = tuple(sorted(apk.get_libraries()))
    signatures = tuple(sorted(apk.get_signature_names()))

    report_metadata: Mapping[str, object] = metadata or {}

    relative = _resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size

    return StaticAnalysisReport(
        file_path=str(apk_path.resolve()),
        relative_path=relative,
        file_name=apk_path.name,
        file_size=file_size,
        hashes=hashes,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
    )


__all__ = [
    "StaticAnalysisError",
    "StaticAnalysisReport",
    "ManifestSummary",
    "ManifestFlags",
    "PermissionSummary",
    "ComponentSummary",
    "analyze_apk",
]
