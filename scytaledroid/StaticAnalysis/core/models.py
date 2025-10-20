"""Data models used by the static analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence

from .findings import DetectorResult, Finding
from .utils import coerce_optional_str, subset


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
    protection_levels: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    custom_definitions: Mapping[str, Mapping[str, object]] = field(
        default_factory=dict
    )
    catalog_snapshot: Mapping[str, Mapping[str, object]] = field(
        default_factory=dict
    )

    def to_dict(self) -> MutableMapping[str, object]:
        return {
            "declared": tuple(self.declared),
            "dangerous": tuple(self.dangerous),
            "custom": tuple(self.custom),
            "protection_levels": {
                str(name): tuple(levels)
                for name, levels in self.protection_levels.items()
            },
            "custom_definitions": {
                str(name): dict(definition)
                for name, definition in self.custom_definitions.items()
            },
            "catalog_snapshot": {
                str(name): dict(metadata)
                for name, metadata in self.catalog_snapshot.items()
            },
        }


@dataclass(frozen=True)
class ManifestFlags:
    """Notable manifest booleans converted to python primitives."""

    uses_cleartext_traffic: Optional[bool] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None
    request_legacy_external_storage: Optional[bool] = None
    full_backup_content: Optional[str] = None
    network_security_config: Optional[str] = None

    def to_dict(self) -> MutableMapping[str, object]:
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
    scan_profile: Optional[str] = None
    analysis_version: str = "2.0.0-alpha"
    findings: tuple[Finding, ...] = ()
    detector_metrics: Mapping[str, object] = field(default_factory=dict)
    detector_results: tuple[DetectorResult, ...] = field(
        default_factory=tuple, repr=False, compare=False
    )
    analysis_matrices: Mapping[str, object] = field(default_factory=dict)
    analysis_indicators: Mapping[str, float] = field(default_factory=dict)
    workload_profile: Mapping[str, object] = field(default_factory=dict)
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
            "scan_profile": self.scan_profile,
            "analysis_version": self.analysis_version,
            "findings": [finding.to_dict() for finding in self.findings],
            "detector_metrics": dict(self.detector_metrics),
            "detector_results": [
                result.to_dict() for result in self.detector_results
            ],
            "analysis_matrices": dict(self.analysis_matrices),
            "analysis_indicators": dict(self.analysis_indicators),
            "workload_profile": dict(self.workload_profile),
            "generated_at": self.generated_at,
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "StaticAnalysisReport":
        """Reconstruct a report from its dictionary representation."""

        manifest = ManifestSummary(**subset(payload.get("manifest", {}), ManifestSummary))
        flags = ManifestFlags(**subset(payload.get("manifest_flags", {}), ManifestFlags))
        permissions_payload = payload.get("permissions", {})
        protection_levels_payload = (
            permissions_payload.get("protection_levels")
            if isinstance(permissions_payload, Mapping)
            else {}
        )
        custom_defs_payload = (
            permissions_payload.get("custom_definitions")
            if isinstance(permissions_payload, Mapping)
            else {}
        )
        catalog_snapshot_payload = (
            permissions_payload.get("catalog_snapshot")
            if isinstance(permissions_payload, Mapping)
            else {}
        )
        permissions = PermissionSummary(
            **{
                "declared": tuple(permissions_payload.get("declared", ())),
                "dangerous": tuple(permissions_payload.get("dangerous", ())),
                "custom": tuple(permissions_payload.get("custom", ())),
                "protection_levels": {
                    str(name): tuple(levels)
                    for name, levels in dict(protection_levels_payload).items()
                }
                if isinstance(protection_levels_payload, Mapping)
                else {},
                "custom_definitions": {
                    str(name): dict(definition)
                    for name, definition in dict(custom_defs_payload).items()
                    if isinstance(definition, Mapping)
                }
                if isinstance(custom_defs_payload, Mapping)
                else {},
                "catalog_snapshot": {
                    str(name): dict(metadata)
                    for name, metadata in dict(catalog_snapshot_payload).items()
                    if isinstance(metadata, Mapping)
                }
                if isinstance(catalog_snapshot_payload, Mapping)
                else {},
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

        findings_payload = payload.get("findings")
        findings: tuple[Finding, ...]
        if isinstance(findings_payload, Sequence) and not isinstance(
            findings_payload, (str, bytes)
        ):
            findings = tuple(
                Finding.from_dict(entry)
                for entry in findings_payload
                if isinstance(entry, Mapping)
            )
        else:
            findings = tuple()

        detector_metrics_payload = payload.get("detector_metrics")
        detector_metrics = (
            {str(k): v for k, v in dict(detector_metrics_payload).items()}
            if isinstance(detector_metrics_payload, Mapping)
            else {}
        )

        detector_results_payload = payload.get("detector_results")
        detector_results: tuple[DetectorResult, ...]
        if isinstance(detector_results_payload, Sequence) and not isinstance(
            detector_results_payload, (str, bytes)
        ):
            detector_results = tuple(
                DetectorResult.from_dict(entry)
                for entry in detector_results_payload
                if isinstance(entry, Mapping)
            )
        else:
            detector_results = tuple()

        matrices_payload = payload.get("analysis_matrices")
        if isinstance(matrices_payload, Mapping):
            analysis_matrices = {
                str(name): value for name, value in matrices_payload.items()
            }
        else:
            analysis_matrices = {}

        indicators_payload = payload.get("analysis_indicators")
        if isinstance(indicators_payload, Mapping):
            analysis_indicators = {
                str(name): float(value)
                for name, value in indicators_payload.items()
                if isinstance(value, (int, float))
            }
        else:
            analysis_indicators = {}

        workload_payload = payload.get("workload_profile")
        if isinstance(workload_payload, Mapping):
            workload_profile = dict(workload_payload)
        else:
            workload_profile = {}

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
            scan_profile=coerce_optional_str(payload.get("scan_profile")),
            analysis_version=str(payload.get("analysis_version") or "2.0.0-alpha"),
            findings=findings,
            detector_metrics=detector_metrics,
            detector_results=detector_results,
            analysis_matrices=analysis_matrices,
            analysis_indicators=analysis_indicators,
            workload_profile=workload_profile,
            generated_at=str(
                payload.get("generated_at") or datetime.now(timezone.utc).isoformat()
            ),
        )


__all__ = [
    "ManifestSummary",
    "ComponentSummary",
    "PermissionSummary",
    "ManifestFlags",
    "StaticAnalysisReport",
]
