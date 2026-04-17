"""High-level static analysis run persistence pipeline."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_engine
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session
from scytaledroid.Database.db_func.static_analysis.persistence_failures import (
    record_static_persistence_failure,
)
from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit

from ...core.findings import Badge, Finding
from ...core.models import StaticAnalysisReport
from ..core.cvss_v4 import apply_profiles
from ..core.masvs_mapper import rule_to_area, summarise_controls
from ..core.rule_ids import derive_rule_id
from ..reports.evidence_report import normalize_evidence
from . import assembly as _assembly
from . import manifest_writer as _manifest_writer
from . import run_writers as _run_writers
from .dep_export import export_dep_json
from .finalization_flow import StaticRunFinalizationCallbacks, finalize_persisted_static_run
from .findings_writer import (
    compute_cvss_base,
    derive_masvs_tag,
    extract_rule_hint,
    persist_findings,
    persist_masvs_controls,
)
from .metrics_writer import compute_metrics_bundle, write_buckets, write_contributors, write_metrics
from .permission_matrix import persist_permission_matrix
from .permission_risk import persist_permission_risk
from .run_envelope import prepare_run_envelope
from .contracts import normalize_run_status
from .static_handoff import build_static_handoff, persist_static_handoff
from .static_sections import (
    coerce_severity_counts,
    persist_static_sections,
    persist_storage_surface_data,
)
from .stage_writers import (
    persist_metrics_and_sections_stage as _stage_persist_metrics_and_sections,
    persist_permission_and_storage_stage as _stage_persist_permission_and_storage,
)
from .transaction_flow import (
    PersistenceRetryPolicy,
    PersistenceTransactionCallbacks,
    execute_persistence_transaction,
)
from .utils import (
    canonical_decimal_text,
    canonical_severity_counts,
    first_text,
    normalise_severity_token,
    require_canonical_schema,
    safe_int,
    truncate,
)

_JWT_LIKE_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def _redact_secret_like_text(text: str) -> str:
    if not text:
        return text
    redacted = _JWT_LIKE_RE.sub("[REDACTED:JWT]", text)
    redacted = _AWS_KEY_RE.sub("[REDACTED:AWS_KEY]", redacted)
    return redacted


def _redact_finding_evidence_payload(evidence_payload: str) -> str:
    if not evidence_payload:
        return evidence_payload
    try:
        parsed = json.loads(evidence_payload)
    except Exception:
        return _redact_secret_like_text(evidence_payload)
    if isinstance(parsed, dict):
        detail = parsed.get("detail")
        if isinstance(detail, str):
            parsed["detail"] = _redact_secret_like_text(detail)
    try:
        return json.dumps(parsed, ensure_ascii=False, default=str)
    except Exception:
        return _redact_secret_like_text(evidence_payload)


def _normalize_datetime_value(value: str | None) -> str | None:
    return _run_writers._normalize_datetime_value(value)


def _severity_band_from_badge(badge: Badge) -> str:
    return _assembly.severity_band_from_badge(badge)


def _score_from_finding(finding: Finding) -> int:
    return _assembly.score_from_finding(finding)


def _correlation_rows_from_result(
    result: object,
    *,
    static_run_id: int,
    package_name: str,
) -> list[dict[str, object]]:
    return _assembly.correlation_rows_from_result(
        result,
        static_run_id=static_run_id,
        package_name=package_name,
    )


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    static_run_id: int | None = None
    runtime_findings: int = 0
    persisted_findings: int = 0
    baseline_written: bool = False
    string_samples_persisted: int = 0
    persistence_failed: bool = False
    canonical_failed: bool = False
    persistence_retry_count: int = 0
    persistence_db_disconnect: bool = False
    persistence_exception_class: str | None = None
    persistence_transaction_state: str | None = None
    persistence_failure_stage: str | None = None
    static_handoff_hash: str | None = None
    errors: list[str] = field(default_factory=list)

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
    run_id: int
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


def _build_persistence_run_context(
    *,
    base_report,
    manifest_obj: object | None,
    metadata_map: Mapping[str, object],
    baseline_payload: Mapping[str, object],
    package_for_run: str,
) -> _PersistenceRunContext:
    display_name = getattr(manifest_obj, "app_label", None) or package_for_run
    version_name = getattr(manifest_obj, "version_name", None) if manifest_obj else None
    min_sdk = safe_int(
        getattr(manifest_obj, "min_sdk", None)
        or getattr(manifest_obj, "min_sdk_version", None)
    )
    target_sdk = safe_int(getattr(manifest_obj, "target_sdk", None))
    try:
        version_code = safe_int(getattr(manifest_obj, "version_code", None)) if manifest_obj else None
    except Exception:
        version_code = None
    profile_token = first_text(
        metadata_map.get("scan_profile") if isinstance(metadata_map, Mapping) else None,
        metadata_map.get("run_profile") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("scan_profile") if isinstance(baseline_payload, Mapping) else None,
        baseline_payload.get("profile") if isinstance(baseline_payload, Mapping) else None,
        "Full",
    )
    category_token = first_text(
        metadata_map.get("category") if isinstance(metadata_map, Mapping) else None,
        metadata_map.get("category_name") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("category") if isinstance(baseline_payload, Mapping) else None,
        baseline_payload.get("category_name") if isinstance(baseline_payload, Mapping) else None,
    )
    scenario_id_token = first_text(
        metadata_map.get("scenario_id") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("scenario_id") if isinstance(baseline_payload, Mapping) else None,
        "static_default",
    )
    device_serial_token = first_text(
        metadata_map.get("device_serial") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("device_serial") if isinstance(baseline_payload, Mapping) else None,
    )
    manifest_sha = None
    base_apk_sha256 = None
    artifact_set_hash = None
    run_signature = None
    run_signature_version = None
    identity_valid = None
    identity_error_reason = None
    if isinstance(metadata_map, Mapping):
        manifest_sha = first_text(
            metadata_map.get("artifact_manifest_sha256"),
            metadata_map.get("manifest_sha256"),
        )
        base_apk_sha256 = first_text(metadata_map.get("base_apk_sha256"))
        artifact_set_hash = first_text(metadata_map.get("artifact_set_hash"))
        run_signature = first_text(metadata_map.get("run_signature"))
        run_signature_version = first_text(metadata_map.get("run_signature_version"))
        identity_valid = metadata_map.get("identity_valid")
        identity_error_reason = first_text(metadata_map.get("identity_error_reason"))
    if not manifest_sha:
        try:
            manifest_sha = first_text(getattr(base_report, "hashes", {}).get("sha256"))
        except Exception:
            manifest_sha = None
    config_hash = first_text(
        metadata_map.get("config_hash") if isinstance(metadata_map, Mapping) else None,
    )
    pipeline_version = first_text(
        metadata_map.get("pipeline_version") if isinstance(metadata_map, Mapping) else None,
    )
    catalog_versions = first_text(
        metadata_map.get("catalog_versions") if isinstance(metadata_map, Mapping) else None,
    )
    study_tag = first_text(
        metadata_map.get("study_tag") if isinstance(metadata_map, Mapping) else None,
    )
    analysis_version = first_text(getattr(base_report, "analysis_version", None))
    harvest_manifest_path = first_text(
        metadata_map.get("harvest_manifest_path") if isinstance(metadata_map, Mapping) else None,
    )
    harvest_capture_status = first_text(
        metadata_map.get("harvest_capture_status") if isinstance(metadata_map, Mapping) else None,
    )
    harvest_persistence_status = first_text(
        metadata_map.get("harvest_persistence_status") if isinstance(metadata_map, Mapping) else None,
    )
    harvest_research_status = first_text(
        metadata_map.get("harvest_research_status") if isinstance(metadata_map, Mapping) else None,
    )
    harvest_matches_planned_artifacts = (
        metadata_map.get("harvest_matches_planned_artifacts")
        if isinstance(metadata_map, Mapping)
        else None
    )
    harvest_observed_hashes_complete = (
        metadata_map.get("harvest_observed_hashes_complete")
        if isinstance(metadata_map, Mapping)
        else None
    )
    harvest_non_canonical_reasons = (
        metadata_map.get("harvest_non_canonical_reasons")
        if isinstance(metadata_map, Mapping)
        else None
    )
    if isinstance(harvest_non_canonical_reasons, Sequence) and not isinstance(
        harvest_non_canonical_reasons,
        (str, bytes),
    ):
        harvest_non_canonical_reason_list = [str(item) for item in harvest_non_canonical_reasons if str(item).strip()]
    else:
        harvest_non_canonical_reason_list = []
    research_usable = metadata_map.get("research_usable") if isinstance(metadata_map, Mapping) else None
    return _PersistenceRunContext(
        display_name=display_name,
        version_name=version_name,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        version_code=version_code,
        profile_token=profile_token,
        category_token=category_token,
        scenario_id_token=scenario_id_token,
        device_serial_token=device_serial_token,
        manifest_sha=manifest_sha,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
        analysis_version=analysis_version,
        harvest_manifest_path=harvest_manifest_path,
        harvest_capture_status=harvest_capture_status,
        harvest_persistence_status=harvest_persistence_status,
        harvest_research_status=harvest_research_status,
        harvest_matches_planned_artifacts=harvest_matches_planned_artifacts,
        harvest_observed_hashes_complete=harvest_observed_hashes_complete,
        harvest_non_canonical_reason_list=harvest_non_canonical_reason_list,
        research_usable=research_usable,
    )


def _build_persistence_metrics_context(
    *,
    base_report,
    metrics_bundle,
    code_http_hosts: int,
    asset_http_hosts: int,
    total_findings: int,
    persisted_finding_count: int,
    downgraded_high: int,
    capped_by_detector: Counter[str],
    taxonomy_counter: Counter[str],
    rule_assigned: int,
    base_vector_count: int,
    bte_vector_count: int,
    preview_assigned: int,
    path_assigned: int,
) -> _PersistenceMetricsContext:
    perm_detail_map: Mapping[str, object] = (
        metrics_bundle.permission_detail
        if isinstance(metrics_bundle.permission_detail, Mapping)
        else {}
    )
    flagged_normal_metric = float(perm_detail_map.get("flagged_normal_count", 0) or 0)
    weak_guard_metric = float(perm_detail_map.get("weak_guard_count", 0) or 0)

    exported = getattr(base_report, "exported_components", None)
    exported_totals = {
        "exports.total": float(getattr(exported, "total", lambda: 0)()) if exported else 0.0,
        "exports.activities": float(len(getattr(exported, "activities", []) or [])) if exported else 0.0,
        "exports.services": float(len(getattr(exported, "services", []) or [])) if exported else 0.0,
        "exports.receivers": float(len(getattr(exported, "receivers", []) or [])) if exported else 0.0,
        "exports.providers": float(len(getattr(exported, "providers", []) or [])) if exported else 0.0,
    }

    metrics_payload: dict[str, tuple[object | None, str | None]] = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "permissions.dangerous_count": (float(getattr(metrics_bundle, "dangerous_permissions", 0)), None),
        "permissions.signature_count": (float(getattr(metrics_bundle, "signature_permissions", 0)), None),
        "permissions.oem_count": (float(getattr(metrics_bundle, "oem_permissions", 0)), None),
        "permissions.flagged_normal_count": (flagged_normal_metric, None),
        "permissions.weak_guard_count": (weak_guard_metric, None),
        "permissions.risk_score": (float(getattr(metrics_bundle, "permission_score", 0.0)), None),
        "permissions.risk_grade": (None, getattr(metrics_bundle, "permission_grade", "")),
        "findings.total": (float(total_findings), None),
        "findings.persisted_total": (float(persisted_finding_count), None),
        "findings.capped_total": (float(int(sum(capped_by_detector.values()))), None),
        "findings.cap_per_detector_default": (float(_finding_cap_for_detector("__default__")), None),
    }
    for key, value in exported_totals.items():
        metrics_payload[key] = (value, None)
    if downgraded_high:
        metrics_payload["findings.high_downgraded"] = (float(downgraded_high), None)
    for detector_id, dropped in sorted(capped_by_detector.items()):
        metrics_payload[f"findings.capped.{detector_id}"] = (float(dropped), None)
    for label in ("RISK", "FINDING", "INFO"):
        metrics_payload[f"findings.taxonomy.{label.lower()}"] = (float(taxonomy_counter.get(label, 0)), None)
    rule_cov_pct = (float(rule_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    base_cov_pct = (float(base_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    bte_cov_pct = (float(bte_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    preview_cov_pct = (float(preview_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    path_cov_pct = (float(path_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    metrics_payload["findings.ruleid_coverage_pct"] = (rule_cov_pct, None)
    metrics_payload["findings.preview_coverage_pct"] = (preview_cov_pct, None)
    metrics_payload["findings.path_coverage_pct"] = (path_cov_pct, None)
    metrics_payload["cvss.base_vector_coverage_pct"] = (base_cov_pct, None)
    metrics_payload["cvss.bte_vector_coverage_pct"] = (bte_cov_pct, None)
    return _PersistenceMetricsContext(
        metrics_payload=metrics_payload,
        exported_totals=exported_totals,
        flagged_normal_metric=flagged_normal_metric,
        weak_guard_metric=weak_guard_metric,
        rule_cov_pct=rule_cov_pct,
        base_cov_pct=base_cov_pct,
        bte_cov_pct=bte_cov_pct,
        preview_cov_pct=preview_cov_pct,
        path_cov_pct=path_cov_pct,
    )


def _collect_detector_correlation_rows(
    *,
    result: object,
    detector_id: str,
    static_run_id: int | None,
    package_for_run: str,
    accumulator: _FindingPreparationAccumulator,
) -> None:
    if detector_id == "correlation_engine" and static_run_id:
        accumulator.correlation_rows.extend(
            _correlation_rows_from_result(
                result,
                static_run_id=static_run_id,
                package_name=package_for_run,
            )
        )


def _append_prepared_finding_rows(
    *,
    finding: object,
    payload: _PreparedFindingPayload,
    accumulator: _FindingPreparationAccumulator,
) -> None:
    meta_combined: dict[str, Any] = {}
    if payload.base_meta:
        meta_combined.update(payload.base_meta)
    if payload.profile_meta:
        meta_combined.update(payload.profile_meta)
    accumulator.finding_rows.append(
        {
            "severity": payload.severity,
            "masvs": payload.masvs_area,
            "cvss": truncate(payload.base_vector, 128),
            "kind": payload.detector_id,
            "module_id": payload.module_id,
            "evidence": truncate(payload.evidence_payload, 512),
            "evidence_path": truncate(payload.evidence_path, 512),
            "evidence_offset": truncate(payload.evidence_offset, 64),
            "evidence_preview": truncate(payload.evidence_preview, 256),
            "rule_id": payload.rule_id,
            "cvss_v40_b_vector": payload.base_vector,
            "cvss_v40_b_score": payload.base_score_c,
            "cvss_v40_bt_vector": payload.bt_vector,
            "cvss_v40_bt_score": payload.bt_score_c,
            "cvss_v40_be_vector": payload.be_vector,
            "cvss_v40_be_score": payload.be_score_c,
            "cvss_v40_bte_vector": payload.bte_vector,
            "cvss_v40_bte_score": payload.bte_score_c,
            "cvss_v40_meta": (
                json.dumps(meta_combined, ensure_ascii=False, default=str) if meta_combined else None
            ),
        }
    )
    status_value = str(
        getattr(getattr(finding, "status", None), "value", getattr(finding, "status", None)) or ""
    ).upper()
    tags_value = getattr(finding, "tags", None)
    tags_json = None
    if isinstance(tags_value, Sequence) and not isinstance(tags_value, (str, bytes)):
        tags_json = json.dumps([str(tag) for tag in tags_value], ensure_ascii=False)
    evidence_refs_payload = None
    if isinstance(payload.metrics_map, Mapping):
        hashes_payload = payload.metrics_map.get("hashes") or payload.metrics_map.get("evidence_refs")
        if hashes_payload is not None:
            evidence_refs_payload = json.dumps(hashes_payload, ensure_ascii=False, default=str)
    accumulator.canonical_finding_rows.append(
        {
            "finding_id": truncate(first_text(getattr(finding, "finding_id", None), payload.rule_id), 128),
            "status": truncate(status_value, 32),
            "severity": truncate(payload.severity, 32),
            "category": truncate(payload.masvs_area, 64),
            "title": truncate(
                first_text(getattr(finding, "title", None), payload.evidence_preview, payload.detector_id),
                512,
            ),
            "tags": tags_json,
            "evidence": payload.evidence_payload,
            "fix": truncate(first_text(getattr(finding, "remediate", None)), 2048),
            "rule_id": truncate(payload.rule_id, 128),
            "cvss_score": payload.base_score_c,
            "masvs_control": truncate(payload.masvs_area, 32),
            "detector": truncate(payload.detector_id, 64),
            "module": truncate(payload.module_id, 64),
            "evidence_refs": evidence_refs_payload,
        }
    )


def _build_findings_persistence_context(
    *,
    accumulator: _FindingPreparationAccumulator,
    baseline_counts: Counter[str],
) -> _PreparedFindingsPersistenceContext:
    control_summary = summarise_controls(accumulator.control_entries)
    missing_masvs = sum(1 for row in accumulator.finding_rows if not row.get("masvs"))
    if accumulator.severity_counter:
        severity_counts = canonical_severity_counts(accumulator.severity_counter)
        persisted_totals = Counter(severity_counts)
    else:
        persisted_totals = Counter(baseline_counts)

    return _PreparedFindingsPersistenceContext(
        finding_rows=accumulator.finding_rows,
        canonical_finding_rows=accumulator.canonical_finding_rows,
        correlation_rows=accumulator.correlation_rows,
        control_summary=control_summary,
        control_entry_count=len(accumulator.control_entries),
        total_findings=accumulator.total_findings,
        persisted_totals=persisted_totals,
        downgraded_high=accumulator.downgraded_high,
        capped_by_detector=accumulator.capped_by_detector,
        taxonomy_counter=accumulator.taxonomy_counter,
        rule_assigned=accumulator.rule_assigned,
        base_vector_count=accumulator.base_vector_count,
        bte_vector_count=accumulator.bte_vector_count,
        preview_assigned=accumulator.preview_assigned,
        path_assigned=accumulator.path_assigned,
        missing_masvs=missing_masvs,
    )


def _prepare_findings_persistence_context(
    *,
    base_report,
    package_for_run: str,
    static_run_id: int | None,
    envelope,
    baseline_counts: Counter[str],
    canonical_cvss_score,
) -> _PreparedFindingsPersistenceContext:
    accumulator = _FindingPreparationAccumulator()

    for result in (base_report.detector_results or ()):  # type: ignore[attr-defined]
        detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
        detector_cap = _finding_cap_for_detector(detector_id)
        module_id_val = getattr(result, "module_id", None)
        module_id = str(module_id_val) if module_id_val not in (None, "") else None
        result_metrics = getattr(result, "metrics", None)
        policy_gate = bool(result_metrics.get("policy_gate", False)) if isinstance(result_metrics, Mapping) else False
        _collect_detector_correlation_rows(
            result=result,
            detector_id=detector_id,
            static_run_id=static_run_id,
            package_for_run=package_for_run,
            accumulator=accumulator,
        )
        for f in result.findings:
            accumulator.total_findings += 1
            detector_sev = normalise_severity_token(getattr(f, "severity", None))
            if detector_sev is None:
                detector_sev = normalise_severity_token(getattr(f, "severity_label", None))
            metrics_map = getattr(f, "metrics", None)
            if isinstance(metrics_map, Mapping):
                detector_sev = detector_sev or normalise_severity_token(metrics_map.get("severity"))
                detector_sev = detector_sev or normalise_severity_token(metrics_map.get("severity_level"))
            gate_value = getattr(getattr(f, "severity_gate", None), "value", None)
            gate_sev = normalise_severity_token(gate_value)
            sev = detector_sev or gate_sev or "Info"
            if detector_sev == "High" and sev != "High":
                accumulator.downgraded_high += 1
            accumulator.severity_counter[sev] += 1
            if accumulator.persisted_by_detector[detector_id] >= detector_cap:
                accumulator.capped_by_detector[detector_id] += 1
                continue
            evidence = normalize_evidence(
                f.evidence,
                detail_hint=getattr(f, "detail", None)
                or getattr(f, "headline", None)
                or getattr(f, "summary", None)
                or getattr(f, "because", None),
                path_hint=getattr(f, "path", None),
                offset_hint=getattr(f, "offset", None),
            )
            evidence_payload = _redact_finding_evidence_payload(
                json.dumps(evidence.as_payload(), ensure_ascii=False, default=str)
            )
            evidence_path = evidence.path
            evidence_offset = evidence.offset
            evidence_preview = evidence.detail
            if evidence_preview:
                accumulator.preview_assigned += 1
            if evidence_path:
                accumulator.path_assigned += 1
            rule_id = derive_rule_id(
                detector_id,
                module_id,
                evidence_path,
                evidence_preview,
                rule_id_hint=extract_rule_hint(f),
            )
            if rule_id:
                accumulator.rule_assigned += 1
            masvs_area = derive_masvs_tag(f, rule_id, lookup_rule_area=rule_to_area)
            base_vector, base_score, base_meta = compute_cvss_base(rule_id)
            if base_vector:
                accumulator.base_vector_count += 1
            bt_vector, bt_score, be_vector, be_score, bte_vector, bte_score, profile_meta = apply_profiles(
                base_vector,
                envelope.threat_profile,
                envelope.env_profile,
            )
            base_score_c = canonical_cvss_score(base_score, field="cvss.base_score")
            bt_score_c = canonical_cvss_score(bt_score, field="cvss.bt_score")
            be_score_c = canonical_cvss_score(be_score, field="cvss.be_score")
            bte_score_c = canonical_cvss_score(bte_score, field="cvss.bte_score")
            if bte_vector:
                accumulator.bte_vector_count += 1
            taxonomy = _taxonomy_label(
                severity=sev,
                detector_status=getattr(result, "status", Badge.INFO),
                policy_gate=policy_gate,
            )
            accumulator.taxonomy_counter[taxonomy] += 1
            _append_prepared_finding_rows(
                finding=f,
                payload=_PreparedFindingPayload(
                    detector_id=detector_id,
                    module_id=module_id,
                    severity=sev,
                    evidence_payload=evidence_payload,
                    evidence_path=evidence_path,
                    evidence_offset=evidence_offset,
                    evidence_preview=evidence_preview,
                    rule_id=rule_id,
                    masvs_area=masvs_area,
                    base_vector=base_vector,
                    base_score_c=base_score_c,
                    bt_vector=bt_vector,
                    bt_score_c=bt_score_c,
                    be_vector=be_vector,
                    be_score_c=be_score_c,
                    bte_vector=bte_vector,
                    bte_score_c=bte_score_c,
                    profile_meta=profile_meta,
                    base_meta=base_meta,
                    metrics_map=metrics_map if isinstance(metrics_map, Mapping) else None,
                ),
                accumulator=accumulator,
            )
            accumulator.persisted_by_detector[detector_id] += 1
            accumulator.control_entries.extend(getattr(result, "masvs_coverage", []))

    return _build_findings_persistence_context(
        accumulator=accumulator,
        baseline_counts=baseline_counts,
    )


def _bootstrap_persistence_transaction(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context: _PersistenceStageContext,
    run_context: _PersistenceRunContext,
    envelope,
    finding_totals: Mapping[str, int],
    cached_schema_version: str,
    raise_db_error,
) -> _TransactionBootstrapResult:
    created_run_id = False
    created_static_run_id = False
    if run_id is None:
        try:
            run_id = _dw.create_run(
                package=stage_context.package_for_run,
                app_label=run_context.display_name,
                version_code=run_context.version_code,
                version_name=run_context.version_name,
                target_sdk=run_context.target_sdk,
                session_stamp=stage_context.session_stamp,
                threat_profile=envelope.threat_profile,
                env_profile=envelope.env_profile,
            )
        except Exception as exc:
            raise_db_error("run.create", f"{exc.__class__.__name__}:{exc}")
        if run_id is None:
            raise_db_error("run.create", "returned_null")
        created_run_id = True

    if static_run_id is None:
        app_version_id = _ensure_app_version(
            package_for_run=stage_context.package_for_run,
            display_name=run_context.display_name,
            version_name=run_context.version_name,
            version_code=run_context.version_code,
            min_sdk=run_context.min_sdk,
            target_sdk=run_context.target_sdk,
        )
        if app_version_id is None:
            raise_db_error("static_run.create", "app_version_unresolved")
        static_run_id = _create_static_run(
            app_version_id=app_version_id,
            session_stamp=stage_context.session_stamp,
            session_label=stage_context.session_stamp,
            scope_label=stage_context.scope_label,
            category=run_context.category_token,
            profile=run_context.profile_token,
            profile_key=run_context.profile_token,
            scenario_id=run_context.scenario_id_token,
            device_serial=run_context.device_serial_token,
            tool_semver=app_config.APP_VERSION,
            tool_git_commit=get_git_commit(),
            schema_version=cached_schema_version,
            findings_total=int(finding_totals.get("total", 0) or 0),
            run_started_utc=None,
            status="STARTED",
            sha256=run_context.base_apk_sha256 or run_context.manifest_sha,
            base_apk_sha256=run_context.base_apk_sha256,
            artifact_set_hash=run_context.artifact_set_hash,
            run_signature=run_context.run_signature,
            run_signature_version=run_context.run_signature_version,
            identity_valid=run_context.identity_valid if isinstance(run_context.identity_valid, bool) else None,
            identity_error_reason=run_context.identity_error_reason,
            config_hash=run_context.config_hash,
            pipeline_version=run_context.pipeline_version,
            analysis_version=run_context.analysis_version,
            catalog_versions=run_context.catalog_versions,
            study_tag=run_context.study_tag,
        )
        if static_run_id is None:
            raise_db_error("static_run.create", "create_failed")
        log.info(
            f"Resolved static_run_id={static_run_id} for {stage_context.package_for_run} (session={stage_context.session_stamp})",
            category="static_analysis",
        )
        created_static_run_id = True

    if static_run_id:
        identity_mode_value = _run_writers._identity_mode(
            base_apk_sha256=run_context.base_apk_sha256,
            version_code=run_context.version_code,
        )
        identity_conflict_value = _run_writers._detect_identity_conflict(
            package_name=stage_context.package_for_run,
            version_code=run_context.version_code,
            base_apk_sha256=run_context.base_apk_sha256,
        )
        _update_static_run_metadata(
            static_run_id,
            sha256_value=run_context.base_apk_sha256 or run_context.manifest_sha,
            base_apk_sha256=run_context.base_apk_sha256,
            artifact_set_hash=run_context.artifact_set_hash,
            run_signature=run_context.run_signature,
            run_signature_version=run_context.run_signature_version,
            identity_valid=run_context.identity_valid if isinstance(run_context.identity_valid, bool) else None,
            identity_error_reason=run_context.identity_error_reason,
            identity_mode=identity_mode_value,
            identity_conflict_flag=identity_conflict_value,
            config_hash=run_context.config_hash,
            pipeline_version=run_context.pipeline_version,
            analysis_version=run_context.analysis_version,
            catalog_versions=run_context.catalog_versions,
            study_tag=run_context.study_tag,
        )

    return _TransactionBootstrapResult(
        run_id=int(run_id),
        static_run_id=int(static_run_id) if static_run_id is not None else None,
        created_run_id=created_run_id,
        created_static_run_id=created_static_run_id,
    )


def _persist_findings_and_correlations_stage(
    *,
    run_id: int,
    static_run_id: int | None,
    stage_context: _PersistenceStageContext,
    findings_context: _PreparedFindingsPersistenceContext,
    raise_db_error,
) -> None:
    try:
        ok = write_buckets(int(run_id), stage_context.metrics_bundle.buckets, static_run_id=static_run_id)
    except Exception as exc:
        raise_db_error("buckets.write", f"{exc.__class__.__name__}:{exc}")
    if not ok:
        raise_db_error("buckets.write", "returned_false")

    if findings_context.finding_rows:
        if run_id is None:
            sample = findings_context.finding_rows[0] if findings_context.finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {stage_context.package_for_run}: "
                    f"findings={findings_context.total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False, default=str)}"
                ),
                category="static_analysis",
            )
        elif not persist_findings(
            int(run_id),
            findings_context.finding_rows,
            static_run_id=static_run_id,
        ):
            raise_db_error(
                "findings.write",
                f"returned_false:run_id={run_id}:static_run_id={static_run_id}",
            )
        if static_run_id is not None:
            try:
                _persist_static_analysis_findings(
                    static_run_id=int(static_run_id),
                    rows=findings_context.canonical_finding_rows,
                )
            except Exception as exc:
                raise_db_error(
                    "canonical_findings.write",
                    f"{exc.__class__.__name__}:{exc}",
                )

    if static_run_id and findings_context.correlation_rows:
        try:
            ok = _persist_correlation_results(findings_context.correlation_rows)
        except Exception as exc:
            raise_db_error("correlations.write", f"{exc.__class__.__name__}:{exc}")
        if not ok:
            raise_db_error("correlations.write", f"returned_false:static_run_id={static_run_id}")


def _persist_permission_and_storage_stage(
    *,
    run_id: int,
    static_run_id: int | None,
    stage_context: _PersistenceStageContext,
    findings_context: _PreparedFindingsPersistenceContext,
    raise_db_error,
) -> None:
    _stage_persist_permission_and_storage(
        run_id=run_id,
        static_run_id=static_run_id,
        stage_context=stage_context,
        findings_context=findings_context,
        raise_db_error=raise_db_error,
        persist_masvs_controls=persist_masvs_controls,
        persist_storage_surface_data=persist_storage_surface_data,
        persist_permission_matrix=persist_permission_matrix,
        persist_permission_risk=persist_permission_risk,
        safe_int=safe_int,
    )


def _persist_metrics_and_sections_stage(
    *,
    run_id: int,
    static_run_id: int | None,
    stage_context: _PersistenceStageContext,
    metrics_context: _PersistenceMetricsContext,
    findings_context: _PreparedFindingsPersistenceContext,
    outcome: PersistenceOutcome,
    note_db_error,
    raise_db_error,
) -> None:
    _stage_persist_metrics_and_sections(
        run_id=run_id,
        static_run_id=static_run_id,
        stage_context=stage_context,
        metrics_context=metrics_context,
        findings_context=findings_context,
        outcome=outcome,
        note_db_error=note_db_error,
        raise_db_error=raise_db_error,
        write_metrics=write_metrics,
        write_contributors=write_contributors,
        persist_static_sections_wrapper=_persist_static_sections_wrapper,
    )


def _finalize_static_handoff_stage(
    *,
    static_run_id: int | None,
    stage_context: _PersistenceStageContext,
    run_context: _PersistenceRunContext,
    cached_schema_version: str,
    outcome: PersistenceOutcome,
) -> bool:
    handoff_failed = False
    if static_run_id and isinstance(stage_context.base_report, StaticAnalysisReport):
        try:
            handoff_payload = build_static_handoff(
                report=stage_context.base_report,
                string_data=stage_context.string_data,
                package_name=stage_context.package_for_run,
                version_code=run_context.version_code,
                base_apk_sha256=run_context.base_apk_sha256,
                artifact_set_hash=run_context.artifact_set_hash,
                static_run_id=int(static_run_id),
                session_label=stage_context.session_stamp,
                tool_semver=app_config.APP_VERSION,
                tool_git_commit=get_git_commit(),
                schema_version=cached_schema_version,
            )
            handoff_hash = persist_static_handoff(
                static_run_id=int(static_run_id),
                handoff_payload=handoff_payload,
            )
            outcome.static_handoff_hash = handoff_hash
            handoff_json_path = str(
                Path("evidence") / "static_runs" / str(static_run_id) / "static_handoff.json"
            )
            identity_block = handoff_payload.get("identity", {}) if isinstance(handoff_payload, Mapping) else {}
            masvs_block = handoff_payload.get("masvs", {}) if isinstance(handoff_payload, Mapping) else {}
            identity_mode = str(identity_block.get("identity_mode") or "") if isinstance(identity_block, Mapping) else None
            identity_conflict_flag = (
                bool(identity_block.get("identity_conflict_flag"))
                if isinstance(identity_block, Mapping)
                else None
            )
            masvs_mapping_hash = (
                str(masvs_block.get("masvs_mapping_hash") or "")
                if isinstance(masvs_block, Mapping)
                else None
            )
            run_class, non_canonical_reasons = _classify_static_contract(
                package_name=stage_context.package_for_run,
                version_code=run_context.version_code,
                base_apk_sha256=run_context.base_apk_sha256,
                identity_mode=identity_mode,
                identity_conflict_flag=identity_conflict_flag,
                static_handoff_hash=handoff_hash,
                static_handoff_json_path=handoff_json_path,
                masvs_mapping_hash=masvs_mapping_hash,
                schema_version=cached_schema_version,
                tool_semver=app_config.APP_VERSION,
                tool_git_commit=get_git_commit(),
                static_config_hash=run_context.config_hash,
                harvest_manifest_path=run_context.harvest_manifest_path,
                harvest_capture_status=run_context.harvest_capture_status,
                harvest_research_status=run_context.harvest_research_status,
                harvest_matches_planned_artifacts=(
                    bool(run_context.harvest_matches_planned_artifacts)
                    if run_context.harvest_matches_planned_artifacts is not None
                    else None
                ),
                harvest_observed_hashes_complete=(
                    bool(run_context.harvest_observed_hashes_complete)
                    if run_context.harvest_observed_hashes_complete is not None
                    else None
                ),
                harvest_non_canonical_reasons=run_context.harvest_non_canonical_reason_list,
                research_usable=(
                    bool(run_context.research_usable)
                    if run_context.research_usable is not None
                    else None
                ),
            )
            _update_static_run_metadata(
                int(static_run_id),
                static_handoff_hash=handoff_hash,
                static_handoff_json_path=handoff_json_path,
                masvs_mapping_hash=masvs_mapping_hash,
                run_class=run_class,
                non_canonical_reasons=(
                    json.dumps(non_canonical_reasons, ensure_ascii=True, sort_keys=True)
                    if non_canonical_reasons
                    else None
                ),
            )
            if run_class != "CANONICAL":
                try:
                    core_q.run_sql(
                        """
                        UPDATE static_analysis_runs
                        SET is_canonical=0,
                            canonical_reason=COALESCE(canonical_reason, %s)
                        WHERE id=%s
                        """,
                        ("contract_violation", int(static_run_id)),
                    )
                except Exception:
                    pass
        except Exception as exc:
            handoff_failed = True
            message = f"Static handoff export failed for {stage_context.package_for_run}: {exc}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
    if handoff_failed and static_run_id:
        try:
            _update_static_run_metadata(
                int(static_run_id),
                run_class="NON_CANONICAL",
                non_canonical_reasons=json.dumps(
                    ["HANDOFF_HASH_MISSING", "PERSISTENCE_ERROR"],
                    ensure_ascii=True,
                ),
            )
        except Exception:
            pass
    return handoff_failed


def _persist_static_sections_wrapper(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
    manifest: object | None,
    app_metadata: Mapping[str, object] | object,
    run_id: int | None,
    static_run_id: int | None = None,
) -> tuple[list[str], bool, int]:
    return persist_static_sections(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section,
        string_payload=string_payload,
        manifest=manifest,
        app_metadata=app_metadata,
        static_run_id=static_run_id,
    )


def _json_safe(value: object) -> object:
    return _manifest_writer._json_safe(value)


def _finding_cap_for_detector(detector_id: str) -> int:
    default_cap = int(getattr(app_config, "STATIC_FINDINGS_CAP_PER_DETECTOR", 20) or 20)
    overrides_raw = getattr(app_config, "STATIC_FINDINGS_CAP_OVERRIDES", {})
    overrides = overrides_raw if isinstance(overrides_raw, Mapping) else {}
    value = overrides.get(detector_id)
    if value is None:
        return max(1, default_cap)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return max(1, default_cap)


def _is_transient_persistence_error(exc: Exception) -> bool:
    if isinstance(exc, db_engine.TransientDbError):
        return True
    text = str(exc).lower()
    markers = ("transientdberror", "lost connection", "server has gone away", "(2013", "(2014")
    return any(marker in text for marker in markers)


def _looks_like_db_disconnect(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = ("2013", "2014", "lost connection", "server has gone away")
    return any(marker in text for marker in markers)


def _looks_like_lock_wait_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = ("1205", "1213", "lock wait timeout", "deadlock")
    return any(marker in text for marker in markers)


def _classify_static_contract(
    *,
    package_name: str | None,
    version_code: int | None,
    base_apk_sha256: str | None,
    identity_mode: str | None,
    identity_conflict_flag: bool | None,
    static_handoff_hash: str | None,
    static_handoff_json_path: str | None,
    masvs_mapping_hash: str | None,
    schema_version: str | None,
    tool_semver: str | None,
    tool_git_commit: str | None,
    static_config_hash: str | None,
    harvest_manifest_path: str | None,
    harvest_capture_status: str | None,
    harvest_research_status: str | None,
    harvest_matches_planned_artifacts: bool | None,
    harvest_observed_hashes_complete: bool | None,
    harvest_non_canonical_reasons: Sequence[str] | None,
    research_usable: bool | None,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    missing_required = False
    if not package_name or version_code is None:
        missing_required = True
    if not base_apk_sha256:
        missing_required = True
    if not static_handoff_hash:
        reasons.append("HANDOFF_HASH_MISSING")
    if not static_handoff_json_path:
        reasons.append("HANDOFF_JSON_MISSING")
    if not masvs_mapping_hash:
        reasons.append("MASVS_MAPPING_HASH_MISSING")
    if not schema_version or not tool_semver or not tool_git_commit:
        missing_required = True
    if not static_config_hash:
        missing_required = True
        reasons.append("CONFIG_HASH_MISMATCH")
    mode = str(identity_mode or "").strip().lower()
    if mode != "full_hash":
        reasons.append("IDENTITY_FALLBACK_MODE")
    if bool(identity_conflict_flag):
        reasons.append("IDENTITY_CONFLICT")
    if not harvest_manifest_path:
        reasons.append("HARVEST_MANIFEST_MISSING")
    capture_status = str(harvest_capture_status or "").strip().lower()
    if capture_status == "drifted":
        reasons.append("HARVEST_DRIFTED")
    elif capture_status == "partial":
        reasons.append("HARVEST_CAPTURE_PARTIAL")
    elif capture_status == "failed":
        reasons.append("HARVEST_CAPTURE_FAILED")
    if harvest_matches_planned_artifacts is False:
        reasons.append("HARVEST_PLANNED_OBSERVED_MISMATCH")
    if harvest_observed_hashes_complete is False:
        reasons.append("HARVEST_OBSERVED_HASHES_INCOMPLETE")
    if str(harvest_research_status or "").strip().lower() == "ineligible":
        reasons.append("HARVEST_RESEARCH_INELIGIBLE")
    if research_usable is False:
        reasons.append("HARVEST_RESEARCH_INELIGIBLE")
    for reason in harvest_non_canonical_reasons or ():
        token = str(reason or "").strip()
        if token:
            reasons.append(token)
    if missing_required:
        reasons.append("MISSING_REQUIRED_FIELD")
    unique_reasons = sorted(set(r for r in reasons if r))
    run_class = "CANONICAL" if not unique_reasons else "NON_CANONICAL"
    return run_class, unique_reasons


def _apply_mysql_session_lock_wait_timeout(db: object, timeout_s: int) -> None:
    dialect = str(getattr(db, "_dialect", "") or "").lower()
    if dialect != "mysql":
        return
    executor = getattr(db, "execute", None)
    if not callable(executor):
        return
    timeout_value = max(1, int(timeout_s))
    try:
        executor(
            "SET SESSION innodb_lock_wait_timeout = %s",
            (timeout_value,),
            query_name="static.persist.set_lock_wait_timeout",
        )
    except Exception as exc:
        # Non-fatal: keep persistence path running even when session tuning is unavailable.
        log.warning(
            f"Unable to set innodb_lock_wait_timeout={timeout_value}: {exc}",
            category="static_analysis",
        )


def _taxonomy_label(*, severity: str, detector_status: object, policy_gate: bool) -> str:
    status_text = str(getattr(detector_status, "value", detector_status) or "").upper()
    if severity == "Info":
        return "INFO"
    if status_text == "FAIL" and not policy_gate:
        return "FINDING"
    return "RISK"


def _persist_correlation_results(rows: Sequence[Mapping[str, object]]) -> bool:
    if not rows:
        return True
    try:
        gov_version = None
        gov_sha = None
        try:
            row = core_q.run_sql(
                """
                SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
                FROM permission_governance_snapshots s
                LEFT JOIN permission_governance_snapshot_rows r
                  ON r.governance_version = s.governance_version
                GROUP BY s.governance_version, s.snapshot_sha256
                ORDER BY s.loaded_at_utc DESC
                LIMIT 1
                """,
                fetch="one",
            )
            if row and row[0] and int(row[2] or 0) > 0:
                gov_version, gov_sha = row[0], row[1]
        except Exception:
            pass
        if gov_version is None or gov_sha is None:
            try:
                row = core_q.run_sql(
                    "SELECT COUNT(*) FROM permission_governance_snapshot_rows",
                    fetch="one",
                )
                if row and int(row[0] or 0) > 0:
                    log.warning(
                        "Governance snapshot rows exist without header; correlation persistence skipped.",
                        category="static_analysis",
                    )
            except Exception:
                pass
            log.warning(
                "Governance snapshot missing; skipping correlation persistence.",
                category="static_analysis",
            )
            return True
        log.info(
            f"Using governance snapshot {gov_version} (sha256={gov_sha})",
            category="static_analysis",
        )
        columns = [
            "static_run_id",
            "package_name",
            "correlation_key",
            "severity_band",
            "score",
            "rationale",
            "evidence_path",
            "evidence_preview",
        ]
        placeholders = ["%s"] * len(columns)
        values_base = [
            "static_run_id",
            "package_name",
            "correlation_key",
            "severity_band",
            "score",
            "rationale",
            "evidence_path",
            "evidence_preview",
        ]
        if gov_version is not None or gov_sha is not None:
            columns.extend(["governance_version", "governance_sha256"])
            placeholders.extend(["%s", "%s"])
            values_base.extend(["governance_version", "governance_sha256"])

        for row in rows:
            payload = dict(row)
            static_run_id = payload.get("static_run_id")
            package_name = payload.get("package_name")
            artifact_token = f"run_{static_run_id}"
            if static_run_id is not None:
                try:
                    sha_row = core_q.run_sql(
                        "SELECT sha256 FROM static_analysis_runs WHERE id=%s",
                        (static_run_id,),
                        fetch="one",
                    )
                    if sha_row and sha_row[0]:
                        artifact_token = str(sha_row[0])
                except Exception:
                    pass
            rel_path = Path("evidence") / "static_runs" / str(static_run_id) / str(package_name) / artifact_token
            rel_path.mkdir(parents=True, exist_ok=True)
            corr_key = payload.get("correlation_key") or "correlation"
            corr_file = rel_path / f"correlation_{corr_key}.json"
            wrote_evidence = False
            try:
                corr_payload = {
                    "static_run_id": static_run_id,
                    "package_name": package_name,
                    "correlation_key": corr_key,
                    "severity_band": payload.get("severity_band"),
                    "score": payload.get("score"),
                    "rationale": payload.get("rationale"),
                    "evidence_preview": payload.get("evidence_preview"),
                    "governance_version": gov_version,
                    "governance_sha256": gov_sha,
                }
                corr_file.write_text(
                    json.dumps(corr_payload, ensure_ascii=True, indent=2, default=str),
                    encoding="utf-8",
                )
                wrote_evidence = True
            except Exception:
                log.warning(
                    f"Failed to write correlation evidence for static_run_id={static_run_id}",
                    category="static_analysis",
                )
            if not wrote_evidence:
                continue
            payload["evidence_path"] = str(
                Path("evidence")
                / "static_runs"
                / str(static_run_id)
                / str(package_name)
                / artifact_token
                / corr_file.name
            )
            payload["governance_version"] = gov_version
            payload["governance_sha256"] = gov_sha
            core_q.run_sql(
                "INSERT INTO static_correlation_results ("
                + ", ".join(columns)
                + ") VALUES ("
                + ",".join(placeholders)
                + ") ON DUPLICATE KEY UPDATE "
                + ", ".join(f"{col}=VALUES({col})" for col in columns if col not in {"static_run_id", "package_name", "correlation_key"}),
                tuple(payload.get(key) for key in values_base),
            )
        return True
    except Exception as exc:
        log.warning(
            f"Failed to persist correlation results: {exc}",
            category="static_analysis",
        )
        return False


def _persist_static_analysis_findings(
    *,
    static_run_id: int,
    rows: Sequence[Mapping[str, object]],
) -> None:
    """Persist canonical per-finding rows for a static run."""

    core_q.run_sql(
        "DELETE FROM static_analysis_findings WHERE run_id=%s",
        (static_run_id,),
        query_name="static_findings_canonical.delete",
    )
    if not rows:
        return
    sql = """
        INSERT INTO static_analysis_findings (
          run_id, finding_id, status, severity, category, title, tags, evidence, fix,
          rule_id, cvss_score, masvs_control, detector, module, evidence_refs
        ) VALUES (
          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
    """
    params: list[tuple[object, ...]] = []
    for row in rows:
        params.append(
            (
                static_run_id,
                row.get("finding_id"),
                row.get("status"),
                row.get("severity"),
                row.get("category"),
                row.get("title"),
                row.get("tags"),
                row.get("evidence"),
                row.get("fix"),
                row.get("rule_id"),
                row.get("cvss_score"),
                row.get("masvs_control"),
                row.get("detector"),
                row.get("module"),
                row.get("evidence_refs"),
            )
        )
    core_q.run_sql_many(sql, params, query_name="static_findings_canonical.insert")


def _ensure_app_version(
    *,
    package_for_run: str,
    display_name: str,
    version_name: str | None,
    version_code: int | None,
    min_sdk: int | None,
    target_sdk: int | None,
) -> int | None:
    """Fetch or create an app_version row for static_analysis_runs."""
    return _run_writers._ensure_app_version(
        package_for_run=package_for_run,
        display_name=display_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
    )


def _create_static_run(
    *,
    app_version_id: int,
    session_stamp: str,
    session_label: str,
    scope_label: str,
    category: str | None,
    profile: str,
    profile_key: str | None,
    scenario_id: str | None,
    device_serial: str | None,
    tool_semver: str | None,
    tool_git_commit: str | None,
    schema_version: str | None,
    findings_total: int,
    run_started_utc: str | None,
    status: str,
    is_canonical: bool | None = None,
    canonical_set_at_utc: str | None = None,
    canonical_reason: str | None = None,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> int | None:
    return _run_writers._create_static_run(
        app_version_id=app_version_id,
        session_stamp=session_stamp,
        session_label=session_label,
        scope_label=scope_label,
        category=category,
        profile=profile,
        profile_key=profile_key,
        scenario_id=scenario_id,
        device_serial=device_serial,
        tool_semver=tool_semver,
        tool_git_commit=tool_git_commit,
        schema_version=schema_version,
        findings_total=findings_total,
        run_started_utc=run_started_utc,
        status=status,
        is_canonical=is_canonical,
        canonical_set_at_utc=canonical_set_at_utc,
        canonical_reason=canonical_reason,
        sha256=sha256,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        analysis_version=analysis_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
    )


def create_static_run_ledger(
    *,
    package_name: str,
    session_stamp: str,
    session_label: str,
    scope_label: str,
    category: str | None = None,
    profile: str,
    display_name: str | None = None,
    version_name: str | None = None,
    version_code: int | None = None,
    min_sdk: int | None = None,
    target_sdk: int | None = None,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
    run_started_utc: str | None = None,
    canonical_action: str | None = None,
    dry_run: bool = False,
) -> int | None:
    """Create a STARTED static_analysis_runs row before scanning begins."""
    canonical_actions = {"first_run", "replace", "auto_suffix", "append"}
    canonical_enabled = canonical_action in canonical_actions if canonical_action else False
    return _run_writers.create_static_run_ledger(
        package_name=package_name,
        display_name=display_name or package_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        session_stamp=session_stamp,
        session_label=session_label,
        scope_label=scope_label,
        category=category,
        profile=profile,
        profile_key=profile,
        scenario_id="static_default",
        device_serial=None,
        tool_semver=app_config.APP_VERSION,
        tool_git_commit=get_git_commit(),
        schema_version=db_diagnostics.get_schema_version() or "<unknown>",
        findings_total=0,
        run_started_utc=run_started_utc,
        status="STARTED",
        is_canonical=True if canonical_enabled else False if canonical_action else None,
        canonical_set_at_utc=run_started_utc if canonical_enabled else None,
        canonical_reason=canonical_action if canonical_enabled else None,
        sha256=sha256,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        analysis_version=analysis_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
    )


def _update_static_run_metadata(
    static_run_id: int,
    *,
    sha256_value: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
    identity_mode: str | None = None,
    identity_conflict_flag: bool | None = None,
    static_handoff_hash: str | None = None,
    static_handoff_json: str | None = None,
    static_handoff_json_path: str | None = None,
    masvs_mapping_hash: str | None = None,
    run_class: str | None = None,
    non_canonical_reasons: str | None = None,
) -> None:
    _run_writers.update_static_run_metadata(
        static_run_id=static_run_id,
        sha256=sha256_value,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        analysis_version=analysis_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
        identity_mode=identity_mode,
        identity_conflict_flag=identity_conflict_flag,
        static_handoff_hash=static_handoff_hash,
        static_handoff_json=static_handoff_json,
        static_handoff_json_path=static_handoff_json_path,
        masvs_mapping_hash=masvs_mapping_hash,
        run_class=run_class,
        non_canonical_reasons=non_canonical_reasons,
    )


def _maybe_set_canonical_static_run(
    *,
    session_label: str,
    static_run_id: int,
    canonical_action: str,
) -> None:
    if canonical_action not in {"first_run", "replace"}:
        return
    _run_writers.maybe_set_canonical_static_run(
        session_label=session_label,
        static_run_id=static_run_id,
        canonical_reason=canonical_action,
    )


def update_static_run_status(
    *,
    static_run_id: int,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    _run_writers.update_static_run_status(
        static_run_id=static_run_id,
        status=status,
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )


def finalize_open_static_runs(
    static_run_ids: Sequence[int] | None = None,
    *,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> int:
    """Finalize any STARTED static runs left open by crashes.

    If `static_run_ids` is None, finalize all open runs.
    If `static_run_ids` is an empty sequence, no-op.
    Returns number of rows updated (best-effort; 0 on error).
    """
    if static_run_ids is not None and not static_run_ids:
        return 0
    return int(
        _run_writers.finalize_open_static_runs(
            static_run_ids,
            status=status,
            ended_at_utc=ended_at_utc,
            abort_reason=abort_reason,
            abort_signal=abort_signal,
        )
        or 0
    )

def persist_run_summary(
    base_report,
    string_data: Mapping[str, object],
    run_package: str,
    *,
    session_stamp: str | None,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_payload: Mapping[str, object],
    static_run_id: int | None = None,
    run_status: str = "COMPLETED",
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
    paper_grade_requested: bool | None = None,
    canonical_action: str | None = None,
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    br = base_report
    failure_stage: str | None = None
    try:
        metadata_map: Mapping[str, object] = getattr(br, "metadata", {}) or {}
    except Exception:
        metadata_map = {}
    manifest_obj = getattr(br, "manifest", None)
    package_for_run = getattr(manifest_obj, "package_name", None) or run_package

    if dry_run:
        log.info(
            f"Dry-run enabled; persistence for {run_package} will be simulated",
            category="static_analysis",
        )
    else:
        try:
            require_canonical_schema()
        except Exception as exc:
            message = f"Canonical schema guard failed for {run_package}: {exc}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
            return outcome

    if not session_stamp and metadata_map:
        value = metadata_map.get("session_stamp")
        if isinstance(value, str) and value.strip():
            session_stamp = value.strip()

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome
    package_for_run = normalize_package_name(package_for_run, context="static_analysis")
    if not package_for_run:
        message = "identity_validation_failed: package_name missing or invalid."
        outcome.add_error(message)
        return outcome
    if not str(scope_label or "").strip():
        message = "identity_validation_failed: scope_label missing."
        outcome.add_error(message)
        return outcome

    envelope, envelope_errors = prepare_run_envelope(
        report=br,
        baseline_payload=baseline_payload,
        run_package=run_package,
        session_stamp=session_stamp,
        dry_run=dry_run,
    )
    for err in envelope_errors:
        outcome.add_error(err)
    run_id = envelope.run_id
    if run_id:
        outcome.run_id = run_id
    run_context = _build_persistence_run_context(
        base_report=br,
        manifest_obj=manifest_obj,
        metadata_map=metadata_map,
        baseline_payload=baseline_payload,
        package_for_run=package_for_run,
    )
    if static_run_id is None:
        try:
            # Prefer an existing static_analysis_runs entry for this session/package.
            rows = core_q.run_sql(
                """
                SELECT sar.id
                FROM static_analysis_runs sar
                JOIN app_versions av ON av.id = sar.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE sar.session_stamp = %s
                  AND a.package_name = %s
                """,
                (session_stamp, package_for_run),
                fetch="all",
            )
            if rows:
                if len(rows) > 1:
                    message = (
                        f"Multiple static_analysis_runs found for session={session_stamp} "
                        f"package={package_for_run}; cannot disambiguate. Use a unique session label."
                    )
                    outcome.add_error(message)
                    return outcome
                # Enforce immutable runs: do not reuse an existing static_run_id for the same session/package.
                message = (
                    f"Session label already used for package={package_for_run} "
                    f"(static_run_id={rows[0][0]}). Please rerun with a unique session label."
                )
                outcome.add_error(message)
                return outcome
        except Exception:
            static_run_id = None

    outcome.static_run_id = static_run_id
    run_status = normalize_run_status(run_status)
    metrics_bundle = compute_metrics_bundle(br, string_data)
    stage_context = _PersistenceStageContext(
        base_report=br,
        string_data=string_data,
        package_for_run=package_for_run,
        session_stamp=session_stamp,
        scope_label=scope_label,
        metadata_map=metadata_map,
        baseline_payload=baseline_payload,
        metrics_bundle=metrics_bundle,
        manifest_obj=manifest_obj,
    )

    db_errors: list[str] = []
    failure_state: dict[str, str | None] = {"stage": None}

    def _note_db_error(message: str) -> None:
        # Standardize DB persistence blockers so batch mode can display actionable reasons.
        normalized = message if message.startswith("db_write_failed:") else f"db_write_failed:{message}"
        outcome.add_error(normalized)
        db_errors.append(normalized)

    def _raise_db_error(op: str, reason: str) -> None:
        token = truncate(f"{op}:{reason}", 240)
        nonlocal failure_stage
        failure_stage = op
        failure_state["stage"] = op
        _note_db_error(token)
        raise RuntimeError(token)

    def _canonical_cvss_score(value: object, *, field: str) -> str | None:
        if value is None:
            return None
        try:
            return canonical_decimal_text(
                value,
                field=field,
                scale=1,
                min_value=0.0,
                max_value=10.0,
            )
        except ValueError as exc:
            _raise_db_error("cvss.validation", str(exc))

    baseline_counts = coerce_severity_counts(finding_totals)
    try:
        findings_context = _prepare_findings_persistence_context(
            base_report=br,
            package_for_run=package_for_run,
            static_run_id=static_run_id,
            envelope=envelope,
            baseline_counts=baseline_counts,
            canonical_cvss_score=_canonical_cvss_score,
        )
    except Exception as exc:
        message = f"Failed to coerce findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        findings_context = _PreparedFindingsPersistenceContext(
            finding_rows=[],
            canonical_finding_rows=[],
            correlation_rows=[],
            control_summary=[],
            control_entry_count=0,
            total_findings=0,
            persisted_totals=Counter(baseline_counts),
            downgraded_high=0,
            capped_by_detector=Counter(),
            taxonomy_counter=Counter(),
            rule_assigned=0,
            base_vector_count=0,
            bte_vector_count=0,
            preview_assigned=0,
            path_assigned=0,
            missing_masvs=0,
        )

    outcome.runtime_findings = int(findings_context.total_findings)
    outcome.persisted_findings = len(findings_context.finding_rows)
    missing_masvs = findings_context.missing_masvs
    if missing_masvs:
        log.warning(
            f"{missing_masvs} findings missing MASVS tags for {run_package}; "
            "DB MASVS Summary may be incomplete.",
            category="static_analysis",
        )
    mismatch = {
        key: findings_context.persisted_totals.get(key, 0) - baseline_counts.get(key, 0)
        for key in findings_context.persisted_totals
        if findings_context.persisted_totals.get(key, 0) != baseline_counts.get(key, 0)
    }
    if mismatch:
        log.info(
            f"Adjusted severity totals for {run_package} based on detector output: {mismatch}",
            category="static_analysis",
        )

    metrics_context = _build_persistence_metrics_context(
        base_report=br,
        metrics_bundle=metrics_bundle,
        code_http_hosts=metrics_bundle.code_http_hosts,
        asset_http_hosts=metrics_bundle.asset_http_hosts,
        total_findings=findings_context.total_findings,
        persisted_finding_count=len(findings_context.finding_rows),
        downgraded_high=findings_context.downgraded_high,
        capped_by_detector=findings_context.capped_by_detector,
        taxonomy_counter=findings_context.taxonomy_counter,
        rule_assigned=findings_context.rule_assigned,
        base_vector_count=findings_context.base_vector_count,
        bte_vector_count=findings_context.bte_vector_count,
        preview_assigned=findings_context.preview_assigned,
        path_assigned=findings_context.path_assigned,
    )

    # Canonicalize numeric metrics to deterministic fixed precision before write.
    canonical_metrics_payload: dict[str, tuple[object | None, str | None]] = {}
    for key, (num_value, text_value) in metrics_context.metrics_payload.items():
        if num_value is None:
            canonical_metrics_payload[key] = (None, text_value)
            continue
        try:
            canonical_num = canonical_decimal_text(
                num_value,
                field=f"metrics.{key}",
                scale=6,
            )
        except ValueError as exc:
            _raise_db_error("metrics.validation", str(exc))
        canonical_metrics_payload[key] = (canonical_num, text_value)
    metrics_context.metrics_payload = canonical_metrics_payload

    persistence_failed = False
    if not dry_run:
        policy = PersistenceRetryPolicy(
            cached_schema_version=db_diagnostics.get_schema_version() or "<unknown>",
            max_txn_attempts=max(1, int(getattr(app_config, "STATIC_PERSIST_TRANSIENT_RETRIES", 4) or 4)),
            max_lock_wait_attempts=max(
                1,
                int(getattr(app_config, "STATIC_PERSIST_LOCK_WAIT_RETRIES", 2) or 2),
            ),
            lock_wait_timeout_s=max(
                1,
                int(getattr(app_config, "STATIC_PERSIST_LOCK_WAIT_TIMEOUT_S", 15) or 15),
            ),
            retry_backoff_base_s=max(
                0.0,
                float(getattr(app_config, "STATIC_PERSIST_RETRY_BACKOFF_BASE_S", 0.35) or 0.35),
            ),
            retry_backoff_max_s=0.0,
        )
        policy.retry_backoff_max_s = max(
            policy.retry_backoff_base_s,
            float(getattr(app_config, "STATIC_PERSIST_RETRY_BACKOFF_MAX_S", 3.0) or 3.0),
        )
        callbacks = PersistenceTransactionCallbacks(
            database_session=database_session,
            apply_lock_wait_timeout=_apply_mysql_session_lock_wait_timeout,
            bootstrap_persistence_transaction=_bootstrap_persistence_transaction,
            persist_findings_and_correlations_stage=_persist_findings_and_correlations_stage,
            persist_permission_and_storage_stage=_persist_permission_and_storage_stage,
            persist_metrics_and_sections_stage=_persist_metrics_and_sections_stage,
            finalize_static_handoff_stage=_finalize_static_handoff_stage,
            is_transient_persistence_error=_is_transient_persistence_error,
            looks_like_lock_wait_error=_looks_like_lock_wait_error,
            looks_like_db_disconnect=_looks_like_db_disconnect,
            record_static_persistence_failure=record_static_persistence_failure,
            update_static_run_metadata=_update_static_run_metadata,
            update_static_run_status=update_static_run_status,
        )
        txn_result = execute_persistence_transaction(
            run_package=run_package,
            run_id=run_id,
            static_run_id=static_run_id,
            stage_context=stage_context,
            run_context=run_context,
            envelope=envelope,
            finding_totals=finding_totals,
            findings_context=findings_context,
            metrics_context=metrics_context,
            outcome=outcome,
            ended_at_utc=ended_at_utc,
            abort_reason=abort_reason,
            abort_signal=abort_signal,
            policy=policy,
            callbacks=callbacks,
            db_errors=db_errors,
            failure_state=failure_state,
            note_db_error=_note_db_error,
            raise_db_error=_raise_db_error,
        )
        run_id = txn_result.run_id
        static_run_id = txn_result.static_run_id
        failure_stage = failure_state.get("stage")
        persistence_failed = txn_result.persistence_failed
    else:
        if findings_context.finding_rows:
            sample = findings_context.finding_rows[0] if findings_context.finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {run_package}: "
                    f"findings={findings_context.total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False, default=str)}"
                ),
                category="static_analysis",
            )

    summary_run_id = run_id if run_id is not None else "dry-run"
    log.info(
        (
            f"Persistence summary for {run_package} (run_id={summary_run_id}): "
            f"findings={findings_context.total_findings} "
            f"rule_id={metrics_context.rule_cov_pct:.1f}% "
            f"preview={metrics_context.preview_cov_pct:.1f}% "
            f"path={metrics_context.path_cov_pct:.1f}% "
            f"bte={metrics_context.bte_cov_pct:.1f}%"
        ),
        category="static_analysis",
    )

    run_status = finalize_persisted_static_run(
        static_run_id=static_run_id,
        dry_run=dry_run,
        package_for_run=package_for_run,
        session_stamp=session_stamp,
        scope_label=scope_label,
        run_package=run_package,
        run_status=run_status,
        paper_grade_requested=paper_grade_requested,
        canonical_action=canonical_action,
        persistence_failed=persistence_failed,
        outcome=outcome,
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
        callbacks=StaticRunFinalizationCallbacks(
            run_sql=core_q.run_sql,
            export_dep_json=export_dep_json,
            maybe_set_canonical_static_run=_maybe_set_canonical_static_run,
            update_static_run_metadata=_update_static_run_metadata,
            update_static_run_status=update_static_run_status,
            normalize_run_status=normalize_run_status,
        ),
    )

    return outcome


def _write_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    return _manifest_writer.write_static_run_manifest(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )


def refresh_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    return _manifest_writer.refresh_static_run_manifest(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )


__all__ = [
    "persist_run_summary",
    "create_static_run_ledger",
    "update_static_run_status",
    "finalize_open_static_runs",
    "refresh_static_run_manifest",
    "PersistenceOutcome",
]
