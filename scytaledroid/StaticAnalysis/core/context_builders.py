"""Helper functions for constructing detector contexts and metadata."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, TYPE_CHECKING
from xml.etree import ElementTree

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import normalise_local_path

from .context import AnalysisConfig, DetectorContext
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
)

if TYPE_CHECKING:  # pragma: no cover - typing aid without runtime import
    from scytaledroid.StaticAnalysis._androguard import APK  # noqa: F401
    from ..modules.string_analysis.extractor import StringIndex  # noqa: F401
    from ..modules.network_security.models import NetworkSecurityPolicy  # noqa: F401
    from ..modules.permissions import PermissionCatalog  # noqa: F401


_DEF_SEVERITY_TOKEN = "dangerous"


def _safe_str(value: object) -> str:
    """Return a string representation safe for join operations."""

    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return str(value)


def _safe_join(parts: Iterable[object]) -> str:
    """Join *parts* ensuring each component is represented as a string."""

    return "|".join(_safe_str(part) for part in parts)


def derive_run_id(apk_sha256: str, config: AnalysisConfig) -> str:
    """Return a deterministic identifier for debug log artefacts."""

    detector_list = ",".join(sorted(config.enabled_detectors or ()))
    seed = _safe_join(
        (
            apk_sha256 or "unknown",
            config.profile,
            config.verbosity,
            config.persistence_mode,
            config.analysis_version,
            detector_list,
        )
    )
    return sha256(seed.encode("utf-8")).hexdigest()[:12]


def resolve_relative_path(apk_path: Path, storage_root: Optional[Path]) -> Optional[str]:
    """Resolve *apk_path* relative to *storage_root* if possible."""

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


def collect_dangerous_permissions(
    permission_details: Mapping[str, Sequence[object]],
) -> tuple[str, ...]:
    """Return the subset of permissions marked as dangerous by Androguard."""

    dangerous: set[str] = set()
    for name, detail in permission_details.items():
        if not detail:
            continue
        protection_level = detail[0]
        if not isinstance(protection_level, str):
            continue
        if _DEF_SEVERITY_TOKEN in protection_level.lower():
            dangerous.add(name)
    return tuple(sorted(dangerous))


def build_detector_context(
    *,
    apk_path: Path,
    apk: "APK",
    manifest_root: ElementTree.Element,
    manifest: ManifestSummary,
    manifest_flags: ManifestFlags,
    permissions: PermissionSummary,
    components: ComponentSummary,
    exported: ComponentSummary,
    features: Sequence[str],
    libraries: Sequence[str],
    signatures: Sequence[str],
    metadata: Mapping[str, object],
    hashes: Mapping[str, str],
    config: AnalysisConfig,
    string_index: Optional["StringIndex"],
    network_security_policy: Optional["NetworkSecurityPolicy"],
    permission_catalog: Optional["PermissionCatalog"],
) -> DetectorContext:
    """Build a detector context shared across all pipeline stages."""

    return DetectorContext(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest_summary=manifest,
        manifest_flags=manifest_flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=tuple(features),
        libraries=tuple(libraries),
        signatures=tuple(signatures),
        metadata=metadata,
        hashes=hashes,
        string_index=string_index,
        network_security_policy=network_security_policy,
        permission_catalog=permission_catalog,
        config=config,
    )


__all__ = [
    "build_detector_context",
    "collect_dangerous_permissions",
    "derive_run_id",
    "resolve_relative_path",
]
