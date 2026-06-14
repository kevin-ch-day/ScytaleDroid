"""Data carriers for static persistence orchestration."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    static_run_id: int | None = None
    runtime_findings: int = 0
    persisted_findings: int = 0
    findings_capped_total: int = 0
    findings_capped_by_detector: dict[str, int] = field(default_factory=dict)
    baseline_written: bool = False
    string_samples_persisted: int = 0
    persistence_failed: bool = False
    canonical_failed: bool = False
    compat_export_failed: bool = False
    compat_export_stage: str | None = None
    compat_run_created: bool = False
    persistence_retry_count: int = 0
    persistence_db_disconnect: bool = False
    persistence_exception_class: str | None = None
    persistence_exception_message: str | None = None
    persistence_sql_errno: int | None = None
    persistence_sqlstate: str | None = None
    persistence_failing_table: str | None = None
    persistence_writer: str | None = None
    persistence_transaction_state: str | None = None
    persistence_failure_stage: str | None = None
    static_handoff_hash: str | None = None
    errors: list[str] = field(default_factory=list)
    #: Non-fatal persistence notes (e.g. duplicate permission rows skipped); echoed in audit JSON.
    persistence_warnings: list[dict[str, str]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)


@dataclass(slots=True)
class _PersistenceRunContext:
    display_name: str
    version_name: str | None
    min_sdk: int | None
    target_sdk: int | None
    version_code: int | None
    profile_token: str | None
    category_token: str | None
    scenario_id_token: str | None
    device_serial_token: str | None
    manifest_sha: str | None
    base_apk_sha256: str | None
    artifact_set_hash: str | None
    apk_set_id: int | None
    run_signature: str | None
    run_signature_version: str | None
    identity_valid: object
    identity_error_reason: str | None
    config_hash: str | None
    pipeline_version: str | None
    catalog_versions: str | None
    study_tag: str | None
    analysis_version: str | None
    harvest_manifest_path: str | None
    harvest_capture_status: str | None
    harvest_persistence_status: str | None
    harvest_research_status: str | None
    harvest_matches_planned_artifacts: object
    harvest_observed_hashes_complete: object
    harvest_non_canonical_reason_list: list[str]
    research_usable: object


@dataclass(slots=True)
class _PersistenceMetricsContext:
    metrics_payload: dict[str, tuple[object | None, str | None]]
    exported_totals: dict[str, float]
    flagged_normal_metric: float
    weak_guard_metric: float
    rule_cov_pct: float
    base_cov_pct: float
    bte_cov_pct: float
    preview_cov_pct: float
    path_cov_pct: float


@dataclass(slots=True)
class _PreparedFindingsPersistenceContext:
    finding_rows: list[dict[str, Any]]
    canonical_finding_rows: list[dict[str, object]]
    correlation_rows: list[dict[str, object]]
    control_summary: list[tuple[str, Mapping[str, Any]]]
    control_entry_count: int
    total_findings: int
    persisted_totals: Counter[str]
    downgraded_high: int
    capped_by_detector: Counter[str]
    taxonomy_counter: Counter[str]
    rule_assigned: int
    base_vector_count: int
    bte_vector_count: int
    preview_assigned: int
    path_assigned: int
    missing_masvs: int


@dataclass(slots=True)
class _TransactionBootstrapResult:
    run_id: int | None
    static_run_id: int | None
    created_run_id: bool
    created_static_run_id: bool


@dataclass(slots=True)
class _PersistenceStageContext:
    base_report: object
    string_data: Mapping[str, object]
    package_for_run: str
    session_stamp: str
    scope_label: str
    metadata_map: Mapping[str, object]
    baseline_payload: Mapping[str, object]
    metrics_bundle: object
    manifest_obj: object | None


@dataclass(slots=True)
class _FindingPreparationAccumulator:
    severity_counter: Counter[str] = field(default_factory=Counter)
    downgraded_high: int = 0
    persisted_by_detector: Counter[str] = field(default_factory=Counter)
    capped_by_detector: Counter[str] = field(default_factory=Counter)
    taxonomy_counter: Counter[str] = field(default_factory=Counter)
    finding_rows: list[dict[str, Any]] = field(default_factory=list)
    canonical_finding_rows: list[dict[str, object]] = field(default_factory=list)
    control_entries: list[tuple[str, Mapping[str, Any]]] = field(default_factory=list)
    correlation_rows: list[dict[str, object]] = field(default_factory=list)
    total_findings: int = 0
    rule_assigned: int = 0
    base_vector_count: int = 0
    bte_vector_count: int = 0
    preview_assigned: int = 0
    path_assigned: int = 0


@dataclass(slots=True)
class _PreparedFindingPayload:
    detector_id: str
    module_id: str | None
    severity: str
    evidence_payload: str
    evidence_path: str | None
    evidence_offset: str | None
    evidence_preview: str | None
    rule_id: str | None
    masvs_area: str | None
    masvs_control_id: str | None
    base_vector: str | None
    base_score_c: str | None
    bt_vector: str | None
    bt_score_c: str | None
    be_vector: str | None
    be_score_c: str | None
    bte_vector: str | None
    bte_score_c: str | None
    profile_meta: Mapping[str, Any] | None
    base_meta: Mapping[str, Any] | None
    metrics_map: Mapping[str, object] | None
