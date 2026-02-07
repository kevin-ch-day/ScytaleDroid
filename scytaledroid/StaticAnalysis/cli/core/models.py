"""Shared data models for static analysis CLI modules."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ...core import StaticAnalysisReport
from ...core.repository import ArtifactGroup
from ...session import make_session_stamp


@dataclass(frozen=True)
class ScopeSelection:
    """Represents the scope of a static-analysis run."""

    scope: str
    label: str
    groups: tuple[ArtifactGroup, ...]


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


def _default_https_risk() -> bool:
    return _env_flag("SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK", False)


def _default_permission_refresh() -> bool:
    # Default to enabled so permission audits and matrices populate automatically.
    return _env_flag("SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT", True)


def _default_run_signature_version() -> str:
    return os.getenv("SCYTALEDROID_RUN_SIGNATURE_VERSION") or "v1"


def _default_persistence_ready() -> bool:
    return _env_flag("SCYTALEDROID_PERSISTENCE_READY", True)


def _default_paper_grade_requested() -> bool:
    return _env_flag("SCYTALEDROID_PAPER_GRADE", True)


def _default_strict_persistence() -> bool:
    return _env_flag("SCYTALEDROID_STRICT_PERSISTENCE", False)


def _default_run_map_overwrite() -> bool:
    return _env_flag("SCYTALEDROID_RUN_MAP_OVERWRITE", False)


def _default_show_splits() -> bool:
    return _env_flag("SCYTALEDROID_STATIC_SHOW_SPLITS", False)

def _default_scan_splits() -> bool:
    # Default to scanning split artifacts in interactive mode. Batch dataset runs can override.
    return _env_flag("SCYTALEDROID_STATIC_SCAN_SPLITS", True)


def _default_long_string_length() -> int:
    try:
        value = int(os.getenv("SCYTALEDROID_STRINGS_LONG_STRING_LENGTH", "256").strip())
        return value if value > 0 else 256
    except Exception:
        return 256


def _default_low_entropy_threshold() -> float:
    try:
        value = float(os.getenv("SCYTALEDROID_STRINGS_LOW_ENTROPY_THRESHOLD", "3.2").strip())
        return value if value > 0 else 3.2
    except Exception:
        return 3.2


def _default_string_debug() -> bool:
    return _env_flag("SCYTALEDROID_STRINGS_DEBUG", False)


def _default_skip_resources_on_warn() -> bool:
    return _env_flag("SCYTALEDROID_STRINGS_SKIP_RES_ON_ARSC_WARN", False)


def _default_perm_snapshot_compact() -> bool | None:
    value = os.getenv("SCYTALEDROID_PERM_SNAPSHOT_COMPACT")
    if value is None:
        return None
    return value.strip().lower() not in {"0", "false", "no"}


def _default_progress_every() -> int:
    try:
        value = int(os.getenv("SCYTALEDROID_STATIC_PROGRESS_EVERY", "5").strip())
        return value if value > 0 else 5
    except Exception:
        return 5


@dataclass(frozen=True)
class RunParameters:
    """User-facing configuration for an analysis run."""

    profile: str
    scope: str
    scope_label: str
    analysis_version: str = field(
        default_factory=lambda: os.getenv("SCYTALEDROID_PIPELINE_VERSION") or "2.0.0-alpha"
    )
    catalog_versions: str | None = field(
        default_factory=lambda: os.getenv("SCYTALEDROID_CATALOG_VERSIONS")
    )
    config_hash: str | None = field(
        default_factory=lambda: os.getenv("SCYTALEDROID_CONFIG_HASH")
    )
    study_tag: str | None = field(
        default_factory=lambda: os.getenv("SCYTALEDROID_STUDY_TAG")
    )
    run_signature_version: str = field(default_factory=_default_run_signature_version)
    persistence_ready: bool = field(default_factory=_default_persistence_ready)
    paper_grade_requested: bool = field(default_factory=_default_paper_grade_requested)
    strict_persistence: bool = field(default_factory=_default_strict_persistence)
    run_map_overwrite: bool = field(default_factory=_default_run_map_overwrite)
    show_split_summaries: bool = field(default_factory=_default_show_splits)
    scan_splits: bool = field(default_factory=_default_scan_splits)
    progress_every: int = field(default_factory=_default_progress_every)
    selected_tests: tuple[str, ...] = tuple()
    evidence_lines: int = 2
    finding_limit: int = 25
    secrets_entropy: float = 4.8
    secrets_hits_per_bucket: int = 40
    secrets_scope: str = "both"
    strings_mode: str = "both"
    string_max_samples: int = 2
    string_min_entropy: float = 4.8
    string_cleartext_only: bool = False
    string_include_https_risk: bool = field(default_factory=_default_https_risk)
    string_long_string_length: int = field(default_factory=_default_long_string_length)
    string_low_entropy_threshold: float = field(default_factory=_default_low_entropy_threshold)
    string_debug: bool = field(default_factory=_default_string_debug)
    string_skip_resources_on_warn: bool = field(default_factory=_default_skip_resources_on_warn)
    workers: str = "auto"
    reuse_cache: bool = False
    log_level: str = "info"
    trace_detectors: tuple[str, ...] = tuple()
    dry_run: bool = False
    session_stamp: str | None = field(default_factory=make_session_stamp)
    verbose_output: bool = False
    artifact_detail: bool = False
    permission_snapshot_refresh: bool = field(default_factory=_default_permission_refresh)
    perm_snapshot_compact: bool | None = field(default_factory=_default_perm_snapshot_compact)
    session_label: str | None = None
    canonical_action: str | None = None

    @property
    def profile_label(self) -> str:
        return {
            "metadata": "Metadata",
            "permissions": "Permission analysis",
            "lightweight": "Lightweight",
            "full": "Full",
            "split": "Split-APK composition",
            "custom": "Custom",
        }.get(self.profile, self.profile.title())

    @property
    def secrets_scope_canonical(self) -> str:
        mapping = {
            "resources": "resources-only",
            "resources-only": "resources-only",
            "dex": "dex-only",
            "dex-only": "dex-only",
            "both": "both",
        }
        return mapping.get((self.secrets_scope or "").lower(), "both")

    @property
    def secrets_scope_label(self) -> str:
        token = self.secrets_scope_canonical
        return {
            "resources-only": "Resources only",
            "dex-only": "DEX only",
            "both": "Resources + DEX",
        }.get(token, "Resources + DEX")


@dataclass
class ArtifactOutcome:
    label: str
    report: StaticAnalysisReport
    severity: Counter[str]
    duration_seconds: float
    saved_path: str | None
    started_at: datetime
    finished_at: datetime
    metadata: Mapping[str, object] | None = None


@dataclass
class AppRunResult:
    package_name: str
    category: str
    artifacts: list[ArtifactOutcome] = field(default_factory=list)
    signer: str | None = None
    static_run_id: int | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    discovered_artifacts: int = 0
    executed_artifacts: int = 0
    persisted_artifacts: int = 0
    failed_artifacts: int = 0
    persistence_skipped: int = 0
    duration_seconds: float = 0.0
    identity_valid: bool | None = None
    identity_error_reason: str | None = None
    base_apk_sha256: str | None = None
    artifact_set_hash: str | None = None
    run_signature: str | None = None
    run_signature_version: str | None = None
    dynamic_plan_path: str | None = None

    def severity_totals(self) -> Counter[str]:
        totals: Counter[str] = Counter()
        for artifact in self.artifacts:
            totals.update(artifact.severity)
        return totals

    def base_artifact_outcome(self) -> ArtifactOutcome | None:
        from ..views.view_sections import extract_integrity_profiles  # localized import

        for artifact in self.artifacts:
            _, _, artifact_profile, _ = extract_integrity_profiles(artifact.report)
            role = str((artifact_profile or {}).get("role") or "").lower()
            if role == "base":
                return artifact
        return self.artifacts[0] if self.artifacts else None

    def base_report(self) -> StaticAnalysisReport | None:
        base_artifact = self.base_artifact_outcome()
        return base_artifact.report if base_artifact else None


@dataclass
class RunOutcome:
    results: list[AppRunResult]
    started_at: datetime
    finished_at: datetime
    scope: ScopeSelection
    base_dir: Path
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    persistence_failed: bool = False
    canonical_failed: bool = False
    paper_grade_status: str = "ok"
    audit_notes: list[dict[str, str]] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str | None = None
    abort_signal: str | None = None
    completed_artifacts: int = 0
    total_artifacts: int = 0
    dry_run_skipped: int = 0

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


__all__ = ["ScopeSelection", "RunParameters", "ArtifactOutcome", "AppRunResult", "RunOutcome"]
