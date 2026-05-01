"""Stage writer helpers for static run summary persistence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from scytaledroid.Utils.LoggingUtils import logging_utils as log


def persist_permission_and_storage_stage(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context: object,
    findings_context: object,
    raise_db_error,
    persist_masvs_controls,
    persist_storage_surface_data,
    persist_permission_matrix,
    persist_permission_risk,
    safe_int,
) -> None:
    if run_id is not None and getattr(findings_context, "control_summary", None):
        try:
            persist_masvs_controls(
                int(run_id),
                stage_context.package_for_run,
                findings_context.control_summary,
            )
        except Exception as exc:
            raise_db_error("masvs_controls.write", f"{exc.__class__.__name__}:{exc}")
    else:
        log.info(
            (
                f"No MASVS control coverage derived for {stage_context.package_for_run}; "
                f"total_findings={findings_context.total_findings} "
                f"entries={findings_context.control_entry_count}"
            ),
            category="static_analysis",
        )
    try:
        persist_storage_surface_data(
            stage_context.base_report,
            stage_context.session_stamp,
            stage_context.scope_label,
        )
    except Exception as exc:
        raise_db_error("storage_surface.write", f"{exc.__class__.__name__}:{exc}")
    metadata_map = (
        stage_context.metadata_map if isinstance(getattr(stage_context, "metadata_map", None), Mapping) else {}
    )
    apk_identifier = safe_int(metadata_map.get("apk_id")) if metadata_map else None
    if apk_identifier is None and metadata_map:
        apk_identifier = safe_int(metadata_map.get("apkId"))
    if apk_identifier is None:
        apk_identifier = safe_int(metadata_map.get("android_apk_id")) if metadata_map else None
    if apk_identifier is None:
        apk_identifier = (
            int(static_run_id)
            if static_run_id is not None
            else (int(run_id) if run_id is not None else None)
        )

    permission_profiles_map: Mapping[str, Mapping[str, object]] | None = None
    detector_metrics = getattr(stage_context.base_report, "detector_metrics", None)
    if isinstance(detector_metrics, Mapping):
        permission_metrics = detector_metrics.get("permissions_profile")
        if isinstance(permission_metrics, Mapping):
            profiles = permission_metrics.get("permission_profiles")
            if isinstance(profiles, Mapping):
                permission_profiles_map = profiles

    try:
        persist_permission_matrix(
            static_run_id=int(static_run_id) if static_run_id is not None else None,
            package_name=stage_context.package_for_run,
            apk_id=apk_identifier,
            permission_profiles=permission_profiles_map,
        )
    except Exception as exc:
        raise_db_error("permission_matrix.write", f"{exc.__class__.__name__}:{exc}")
    try:
        persist_permission_risk(
            run_id=int(run_id) if run_id is not None else None,
            static_run_id=int(static_run_id) if static_run_id is not None else None,
            report=stage_context.base_report,
            package_name=stage_context.package_for_run,
            session_stamp=stage_context.session_stamp,
            scope_label=stage_context.scope_label,
            metrics_bundle=stage_context.metrics_bundle,
            baseline_payload=stage_context.baseline_payload,
            permission_profiles=permission_profiles_map,
        )
    except Exception as exc:
        raise_db_error("permission_risk.write", f"{exc.__class__.__name__}:{exc}")


def persist_metrics_and_sections_stage(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context: object,
    metrics_context: object,
    findings_context: object,
    outcome: object,
    note_db_error,
    raise_db_error,
    write_metrics,
    write_contributors,
    persist_static_sections_wrapper,
) -> None:
    if run_id is not None:
        try:
            ok = write_metrics(int(run_id), metrics_context.metrics_payload, static_run_id=static_run_id)
        except Exception as exc:
            raise_db_error("metrics.write", f"{exc.__class__.__name__}:{exc}")
        if not ok:
            raise_db_error("metrics.write", f"returned_false:run_id={run_id}")

        if stage_context.metrics_bundle.contributors:
            try:
                ok = write_contributors(int(run_id), stage_context.metrics_bundle.contributors)
            except Exception as exc:
                raise_db_error("contributors.write", f"{exc.__class__.__name__}:{exc}")
            if not ok:
                raise_db_error("contributors.write", f"returned_false:run_id={run_id}")

    baseline_section = (
        stage_context.baseline_payload.get("baseline")
        if isinstance(stage_context.baseline_payload, Mapping)
        else {}
    )
    string_payload = baseline_section.get("string_analysis") if isinstance(baseline_section, Mapping) else {}
    static_errors, baseline_written, sample_total = persist_static_sections_wrapper(
        package_name=stage_context.package_for_run,
        session_stamp=stage_context.session_stamp,
        scope_label=stage_context.scope_label,
        finding_totals=findings_context.persisted_totals,
        baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
        string_payload=string_payload if isinstance(string_payload, Mapping) else {},
        manifest=stage_context.manifest_obj,
        app_metadata=(
            stage_context.baseline_payload.get("app")
            if isinstance(stage_context.baseline_payload, Mapping)
            else {}
        ),
        run_id=run_id,
        static_run_id=static_run_id,
    )
    if baseline_written:
        outcome.baseline_written = True
    outcome.string_samples_persisted = sample_total
    for err in static_errors:
        note_db_error(err)


__all__ = [
    "persist_metrics_and_sections_stage",
    "persist_permission_and_storage_stage",
]
