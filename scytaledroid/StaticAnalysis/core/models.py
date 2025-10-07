"""Data models used by the static analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence

from .findings import Finding
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

    def to_dict(self) -> MutableMapping[str, Iterable[str]]:
        return asdict(self)


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
            "generated_at": self.generated_at,
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "StaticAnalysisReport":
        """Reconstruct a report from its dictionary representation."""

        manifest = ManifestSummary(**subset(payload.get("manifest", {}), ManifestSummary))
        flags = ManifestFlags(**subset(payload.get("manifest_flags", {}), ManifestFlags))
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
