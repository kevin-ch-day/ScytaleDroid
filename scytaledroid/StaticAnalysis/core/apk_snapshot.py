"""Utilities for loading APK metadata prior to detector execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence, TYPE_CHECKING
from xml.etree import ElementTree

from androguard.core.apk import APK

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes
from scytaledroid.Utils.LoggingUtils.logging_engine import (
    configure_third_party_loggers,
)

from .context import AnalysisConfig, DetectorContext
from .context_builders import (
    build_detector_context,
    collect_dangerous_permissions,
    derive_run_id,
    resolve_relative_path,
)
from .errors import StaticAnalysisError
from .manifest_utils import (
    build_manifest_flags,
    collect_exported_components,
    extract_compile_sdk,
    load_manifest_root,
)
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
)
from ..modules import build_string_index
from ..modules.network_security import extract_network_security_policy

if TYPE_CHECKING:  # pragma: no cover - typing only imports
    from ..modules.network_security.models import NetworkSecurityPolicy
    from ..modules.string_analysis.extractor import StringIndex


try:  # pragma: no cover - optional dependency metadata
    import androguard
except Exception:  # pragma: no cover - best-effort metadata only
    androguard = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ApkSnapshot:
    """A cached view of APK-derived metadata used by the detector pipeline."""

    apk_path: Path
    apk: APK
    manifest_root: ElementTree.Element
    manifest: ManifestSummary
    manifest_flags: ManifestFlags
    permissions: PermissionSummary
    components: ComponentSummary
    exported_components: ComponentSummary
    features: tuple[str, ...]
    libraries: tuple[str, ...]
    signatures: tuple[str, ...]
    metadata: Mapping[str, object]
    hashes: Mapping[str, str]
    relative_path: Optional[str]
    file_size: int
    network_security_policy: Optional["NetworkSecurityPolicy"]
    string_index: Optional["StringIndex"]
    config: AnalysisConfig

    def build_context(self) -> DetectorContext:
        """Return a :class:`DetectorContext` suitable for detector execution."""

        return build_detector_context(
            apk_path=self.apk_path,
            apk=self.apk,
            manifest_root=self.manifest_root,
            manifest=self.manifest,
            manifest_flags=self.manifest_flags,
            permissions=self.permissions,
            components=self.components,
            exported=self.exported_components,
            features=self.features,
            libraries=self.libraries,
            signatures=self.signatures,
            metadata=self.metadata,
            hashes=self.hashes,
            config=self.config,
            string_index=self.string_index,
            network_security_policy=self.network_security_policy,
        )


def build_apk_snapshot(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> ApkSnapshot:
    """Load an APK and derive the metadata required for static analysis."""

    if not apk_path.exists():
        raise StaticAnalysisError(f"APK not found: {apk_path}")

    analysis_config = config or AnalysisConfig()
    report_metadata: dict[str, object] = dict(metadata or {})

    hashes = compute_hashes(apk_path)
    apk_sha256 = hashes.get("sha256", "")
    run_id = derive_run_id(apk_sha256, analysis_config)
    report_metadata.setdefault("run_id", run_id)

    log_path = configure_third_party_loggers(
        verbosity=analysis_config.verbosity,
        run_id=run_id,
        debug_dir=str(Path(app_config.LOGS_DIR).resolve()),
    )
    if log_path is not None:
        report_metadata["androguard_log_path"] = str(log_path)

    try:
        apk = APK(str(apk_path))
    except Exception as exc:  # pragma: no cover - third party parsing errors
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    report_metadata.setdefault("toolchain", _resolve_toolchain_versions())

    manifest_root = load_manifest_root(apk)
    flags = build_manifest_flags(manifest_root)
    compile_sdk = extract_compile_sdk(manifest_root)
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
    try:
        permission_details = apk.get_details_permissions()
    except KeyError:
        permission_details = {}
    dangerous = collect_dangerous_permissions(permission_details)
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
    exported = collect_exported_components(manifest_root)

    features = tuple(sorted(apk.get_features()))
    libraries = tuple(sorted(apk.get_libraries()))
    signatures = tuple(sorted(apk.get_signature_names()))

    relative = resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size
    network_security_policy = extract_network_security_policy(
        apk,
        manifest_reference=flags.network_security_config,
    )

    string_index = (
        build_string_index(apk) if analysis_config.enable_string_index else None
    )

    return ApkSnapshot(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
        hashes=hashes,
        relative_path=relative,
        file_size=file_size,
        network_security_policy=network_security_policy,
        string_index=string_index,
        config=analysis_config,
    )


def _resolve_toolchain_versions() -> Mapping[str, str]:
    versions = {"androguard": "—", "aapt2": "—", "apksigner": "—"}

    if androguard is not None:
        version = getattr(androguard, "__version__", None)
        if isinstance(version, str) and version.strip():
            versions["androguard"] = version

    for cli_name, args in ("aapt2", ["version"]), ("apksigner", ["--version"]):
        version = _probe_cli_version(cli_name, args)
        if version:
            versions[cli_name] = version

    return versions


def _probe_cli_version(binary: str, args: Sequence[str]) -> Optional[str]:
    """Return the CLI version output if the binary is available."""

    from shutil import which
    import subprocess

    if which(binary) is None:
        return None

    try:
        completed = subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:  # pragma: no cover - CLI probing is best effort
        return None

    output = completed.stdout.strip() or completed.stderr.strip()
    return output.splitlines()[0].strip() if output else None


__all__ = ["ApkSnapshot", "build_apk_snapshot"]
