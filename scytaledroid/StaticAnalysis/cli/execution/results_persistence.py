"""Persistence handoff helpers for static results rendering."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast


def _set_report_metadata(*, base_report: object, metadata_map: Mapping[str, object]) -> None:
    try:
        object.__setattr__(base_report, "metadata", dict(metadata_map))
    except Exception:
        base_report.metadata = dict(metadata_map)


def _finding_fidelity_status(
    *,
    runtime_findings: int | None,
    capped_not_persisted: int | None,
) -> str:
    runtime = int(runtime_findings or 0)
    capped = int(capped_not_persisted or 0)
    if runtime <= 0:
        return "unknown"
    if capped <= 0:
        return "complete"
    return "capped"


def _build_findings_fidelity_metadata(*, app_result: object) -> dict[str, object] | None:
    runtime_findings = getattr(app_result, "persistence_runtime_findings", None)
    persisted_findings = getattr(app_result, "persistence_persisted_findings", None)
    capped_findings = getattr(app_result, "persistence_findings_capped_total", None)
    if not any(isinstance(value, int) for value in (runtime_findings, persisted_findings, capped_findings)):
        return None

    runtime = int(runtime_findings or 0)
    persisted = int(persisted_findings or 0)
    capped = int(capped_findings or 0)
    fidelity_ratio = None
    capped_ratio = None
    if runtime > 0:
        fidelity_ratio = round(persisted / runtime, 6)
        capped_ratio = round(capped / runtime, 6)

    runtime_p0 = getattr(app_result, "persistence_runtime_p0_findings", None)
    persisted_p0 = getattr(app_result, "persistence_persisted_p0_findings", None)
    capped_p0 = getattr(app_result, "persistence_capped_p0_findings", None)

    notes: list[str] = []
    if capped > 0:
        notes.append(
            "Canonical DB finding rows are incomplete for this package because per-detector caps fired during persistence."
        )
    if int(capped_p0 or 0) > 0:
        notes.append(
            f"High-priority fidelity warning: {int(capped_p0 or 0)} P0 findings were capped before canonical DB persistence."
        )

    return {
        "finding_fidelity_status": _finding_fidelity_status(
            runtime_findings=runtime,
            capped_not_persisted=capped,
        ),
        "runtime_findings": runtime,
        "persisted_db_findings": persisted,
        "capped_not_persisted": capped,
        "fidelity_ratio": fidelity_ratio,
        "capped_ratio": capped_ratio,
        "canonical_db_complete": capped <= 0,
        "artifact_runtime_evidence_complete": True,
        "cap_policy_applied": capped > 0,
        "cap_policy_basis": "detector_count",
        "cap_policy_detector_aware": True,
        "cap_policy_severity_aware": False,
        "cap_metadata_grain": "package",
        "per_finding_persistence_status_available": False,
        "runtime_p0_findings": int(runtime_p0 or 0) if isinstance(runtime_p0, int) else None,
        "persisted_db_p0_findings": int(persisted_p0 or 0) if isinstance(persisted_p0, int) else None,
        "capped_p0_findings": int(capped_p0 or 0) if isinstance(capped_p0, int) else None,
        "notes": notes,
    }


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
        if getattr(app_result, "apk_set_id", None) and not metadata_map.get("apk_set_id"):
            metadata_map["apk_set_id"] = app_result.apk_set_id
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
        findings_fidelity = _build_findings_fidelity_metadata(app_result=app_result)
        if findings_fidelity is not None:
            metadata_map["findings_fidelity"] = findings_fidelity
        if metadata_map:
            _set_report_metadata(base_report=base_report, metadata_map=metadata_map)
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
        app_result.persistence_exception_message = getattr(
            outcome_status, "persistence_exception_message", None
        )
        app_result.persistence_sql_errno = getattr(outcome_status, "persistence_sql_errno", None)
        app_result.persistence_sqlstate = getattr(outcome_status, "persistence_sqlstate", None)
        app_result.persistence_failing_table = getattr(outcome_status, "persistence_failing_table", None)
        app_result.persistence_writer = getattr(outcome_status, "persistence_writer", None)
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
        app_result.persistence_runtime_p0_findings = int(
            getattr(outcome_status, "runtime_p0_findings", 0) or 0
        )
        app_result.persistence_persisted_p0_findings = int(
            getattr(outcome_status, "persisted_p0_findings", 0) or 0
        )
        app_result.persistence_capped_p0_findings = int(
            getattr(outcome_status, "capped_p0_findings", 0) or 0
        )
        capped_map = getattr(outcome_status, "findings_capped_by_detector", None)
        if isinstance(capped_map, Mapping):
            app_result.persistence_findings_capped_by_detector = {str(k): int(v) for k, v in cast(Mapping[Any, Any], capped_map).items()}
        else:
            app_result.persistence_findings_capped_by_detector = {}
        pw = getattr(outcome_status, "persistence_warnings", None) or []
        if pw:
            app_result.persistence_warnings.extend(list(pw))
    return normalized_findings_delta, string_samples_delta


def format_persistence_failure_detail(
    *,
    package_name: str,
    session_stamp: str | None,
    static_run_id: int | None,
    outcome_status: object | None,
    issue_label: str,
) -> str:
    """
    Operator-facing multi-line detail for persistence aborts (stdout + logs).

    Keeps Permission Intel / governance messages separate — only persistence outcome fields here.
    """

    lines: list[str] = [
        f"persistence_stage={issue_label}",
        f"package_name={package_name}",
        f"session_stamp={session_stamp or '—'}",
        f"static_run_id={static_run_id or '—'}",
    ]
    if outcome_status is None:
        return "\n".join(lines)
    stage = getattr(outcome_status, "persistence_failure_stage", None)
    if stage:
        lines.append(f"persistence_failure_stage={stage}")
    exc_cls = getattr(outcome_status, "persistence_exception_class", None)
    if exc_cls:
        lines.append(f"persistence_exception_class={exc_cls}")
    exc_msg = getattr(outcome_status, "persistence_exception_message", None)
    if exc_msg:
        lines.append(f"persistence_exception_message={exc_msg}")
    sql_errno = getattr(outcome_status, "persistence_sql_errno", None)
    if sql_errno is not None:
        lines.append(f"persistence_sql_errno={sql_errno}")
    sqlstate = getattr(outcome_status, "persistence_sqlstate", None)
    if sqlstate:
        lines.append(f"persistence_sqlstate={sqlstate}")
    fail_tbl = getattr(outcome_status, "persistence_failing_table", None)
    if fail_tbl:
        lines.append(f"persistence_failing_table={fail_tbl}")
    writer = getattr(outcome_status, "persistence_writer", None)
    if writer:
        lines.append(f"persistence_writer={writer}")
    tx_state = getattr(outcome_status, "persistence_transaction_state", None)
    if tx_state:
        lines.append(f"persistence_transaction_state={tx_state}")
    if bool(getattr(outcome_status, "compat_export_failed", False)):
        ces = getattr(outcome_status, "compat_export_stage", None)
        if ces:
            lines.append(f"compat_export_stage={ces}")
    errs = getattr(outcome_status, "errors", None) or []
    for i, err in enumerate(errs):
        lines.append(f"persistence_error[{i}]={err}")
    if getattr(outcome_status, "persistence_db_disconnect", False):
        lines.append("persistence_db_disconnect=1")
    retry = getattr(outcome_status, "persistence_retry_count", None)
    if retry is not None and int(retry) > 0:
        lines.append(f"persistence_retry_count={retry}")
    return "\n".join(lines)


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
    "format_persistence_failure_detail",
    "merge_persistence_metadata",
]
