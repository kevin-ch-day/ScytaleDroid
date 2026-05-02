"""Persistence handoff helpers for static results rendering."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast


def merge_persistence_metadata(*, base_report: object, app_result: object, params: object) -> None:
    try:
        metadata_map = (
            dict(base_report.metadata)
            if isinstance(getattr(base_report, "metadata", None), Mapping)
            else {}
        )
        if app_result.base_apk_sha256 and not metadata_map.get("base_apk_sha256"):
            metadata_map["base_apk_sha256"] = app_result.base_apk_sha256
        if app_result.artifact_set_hash and not metadata_map.get("artifact_set_hash"):
            metadata_map["artifact_set_hash"] = app_result.artifact_set_hash
        if app_result.run_signature and not metadata_map.get("run_signature"):
            metadata_map["run_signature"] = app_result.run_signature
        if app_result.run_signature_version and not metadata_map.get("run_signature_version"):
            metadata_map["run_signature_version"] = app_result.run_signature_version
        if app_result.identity_valid is not None and metadata_map.get("identity_valid") is None:
            metadata_map["identity_valid"] = bool(app_result.identity_valid)
        if app_result.identity_error_reason and not metadata_map.get("identity_error_reason"):
            metadata_map["identity_error_reason"] = app_result.identity_error_reason
        if app_result.harvest_manifest_path and not metadata_map.get("harvest_manifest_path"):
            metadata_map["harvest_manifest_path"] = app_result.harvest_manifest_path
        if app_result.harvest_capture_status and not metadata_map.get("harvest_capture_status"):
            metadata_map["harvest_capture_status"] = app_result.harvest_capture_status
        if app_result.harvest_persistence_status and not metadata_map.get("harvest_persistence_status"):
            metadata_map["harvest_persistence_status"] = app_result.harvest_persistence_status
        if app_result.harvest_research_status and not metadata_map.get("harvest_research_status"):
            metadata_map["harvest_research_status"] = app_result.harvest_research_status
        if (
            app_result.harvest_matches_planned_artifacts is not None
            and metadata_map.get("harvest_matches_planned_artifacts") is None
        ):
            metadata_map["harvest_matches_planned_artifacts"] = bool(
                app_result.harvest_matches_planned_artifacts
            )
        if (
            app_result.harvest_observed_hashes_complete is not None
            and metadata_map.get("harvest_observed_hashes_complete") is None
        ):
            metadata_map["harvest_observed_hashes_complete"] = bool(
                app_result.harvest_observed_hashes_complete
            )
        if app_result.research_usable is not None and metadata_map.get("research_usable") is None:
            metadata_map["research_usable"] = bool(app_result.research_usable)
        if metadata_map.get("exploratory_only") is None:
            metadata_map["exploratory_only"] = bool(app_result.exploratory_only)
        if app_result.research_block_reasons and not metadata_map.get("harvest_non_canonical_reasons"):
            metadata_map["harvest_non_canonical_reasons"] = list(app_result.research_block_reasons)
        if getattr(params, "config_hash", None) and not metadata_map.get("config_hash"):
            metadata_map["config_hash"] = params.config_hash
        if getattr(params, "analysis_version", None) and not metadata_map.get("pipeline_version"):
            metadata_map["pipeline_version"] = params.analysis_version
        if getattr(params, "catalog_versions", None) and not metadata_map.get("catalog_versions"):
            metadata_map["catalog_versions"] = params.catalog_versions
        if metadata_map:
            base_report.metadata = metadata_map
    except Exception:
        pass


def apply_persistence_outcome(
    *,
    app_result: object,
    outcome_status: object,
) -> tuple[int, int]:
    normalized_findings_delta = 0
    string_samples_delta = 0
    if outcome_status:
        static_run_id = getattr(outcome_status, "static_run_id", None)
        if static_run_id:
            app_result.static_run_id = static_run_id
        app_result.static_handoff_hash = getattr(outcome_status, "static_handoff_hash", None)
        app_result.persistence_retry_count = int(
            getattr(outcome_status, "persistence_retry_count", 0) or 0
        )
        app_result.persistence_db_disconnect = bool(
            getattr(outcome_status, "persistence_db_disconnect", False)
        )
        app_result.persistence_exception_class = getattr(
            outcome_status, "persistence_exception_class", None
        )
        app_result.persistence_transaction_state = getattr(
            outcome_status, "persistence_transaction_state", None
        )
        app_result.persistence_failure_stage = getattr(
            outcome_status, "persistence_failure_stage", None
        )
        normalized_findings_delta = int(getattr(outcome_status, "persisted_findings", 0) or 0)
        string_samples_delta = int(getattr(outcome_status, "string_samples_persisted", 0) or 0)
        app_result.persistence_runtime_findings = int(getattr(outcome_status, "runtime_findings", 0) or 0)
        app_result.persistence_persisted_findings = normalized_findings_delta
        app_result.persistence_findings_capped_total = int(getattr(outcome_status, "findings_capped_total", 0) or 0)
        capped_map = getattr(outcome_status, "findings_capped_by_detector", None)
        if isinstance(capped_map, Mapping):
            app_result.persistence_findings_capped_by_detector = {str(k): int(v) for k, v in cast(Mapping[Any, Any], capped_map).items()}
        else:
            app_result.persistence_findings_capped_by_detector = {}
    return normalized_findings_delta, string_samples_delta


def collect_persistence_errors(
    *,
    outcome_status: object,
) -> tuple[list[str], list[str], list[str]]:
    canonical_failures: list[str] = []
    persistence_errors: list[str] = []
    compat_export_errors: list[str] = []
    if outcome_status and not bool(getattr(outcome_status, "success", False)):
        compat_export_failed = bool(getattr(outcome_status, "compat_export_failed", False))
        for err in getattr(outcome_status, "errors", []) or []:
            msg = str(err)
            if "canonical_enforcement_failed" in msg:
                canonical_failures.append(msg)
            elif compat_export_failed:
                compat_export_errors.append(msg)
            else:
                persistence_errors.append(msg)
    return canonical_failures, persistence_errors, compat_export_errors


__all__ = [
    "apply_persistence_outcome",
    "collect_persistence_errors",
    "merge_persistence_metadata",
]
