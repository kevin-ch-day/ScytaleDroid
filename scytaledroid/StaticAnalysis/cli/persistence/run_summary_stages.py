"""Stage helper implementations for static persistence orchestration."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from scytaledroid.Config import app_config


def bootstrap_persistence_transaction(
    *,
    run_id: int | None,
    static_run_id: int | None,
    outcome,
    stage_context,
    run_context,
    envelope,
    finding_totals: Mapping[str, int],
    cached_schema_version: str,
    raise_db_error,
    ensure_app_version_fn,
    create_static_run_fn,
    update_static_run_metadata_fn,
    identity_mode_fn,
    detect_identity_conflict_fn,
    get_git_commit_fn,
    transaction_bootstrap_result_cls,
    log,
) -> object:
    _ = outcome, envelope
    created_run_id = False
    created_static_run_id = False
    if static_run_id is None:
        app_version_id = ensure_app_version_fn(
            package_for_run=stage_context.package_for_run,
            display_name=run_context.display_name,
            version_name=run_context.version_name,
            version_code=run_context.version_code,
            min_sdk=run_context.min_sdk,
            target_sdk=run_context.target_sdk,
        )
        if app_version_id is None:
            raise_db_error("static_run.create", "app_version_unresolved")
        static_run_id = create_static_run_fn(
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
            tool_git_commit=get_git_commit_fn(),
            schema_version=cached_schema_version,
            findings_total=int(finding_totals.get("total", 0) or 0),
            run_started_utc=None,
            status="STARTED",
            sha256=run_context.base_apk_sha256 or run_context.manifest_sha,
            base_apk_sha256=run_context.base_apk_sha256,
            artifact_set_hash=run_context.artifact_set_hash,
            apk_set_id=run_context.apk_set_id,
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
        identity_mode_value = identity_mode_fn(
            base_apk_sha256=run_context.base_apk_sha256,
            version_code=run_context.version_code,
        )
        identity_conflict_value = detect_identity_conflict_fn(
            package_name=stage_context.package_for_run,
            version_code=run_context.version_code,
            base_apk_sha256=run_context.base_apk_sha256,
        )
        update_static_run_metadata_fn(
            static_run_id,
            sha256_value=run_context.base_apk_sha256 or run_context.manifest_sha,
            base_apk_sha256=run_context.base_apk_sha256,
            artifact_set_hash=run_context.artifact_set_hash,
            apk_set_id=run_context.apk_set_id,
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

    return transaction_bootstrap_result_cls(
        run_id=int(run_id) if run_id is not None else None,
        static_run_id=int(static_run_id) if static_run_id is not None else None,
        created_run_id=created_run_id,
        created_static_run_id=created_static_run_id,
    )


def persist_findings_and_correlations_stage(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context,
    findings_context,
    raise_db_error,
    persist_static_analysis_findings_fn,
    persist_correlation_results_fn,
) -> None:
    _ = run_id, stage_context
    if findings_context.finding_rows and static_run_id is not None:
        try:
            persist_static_analysis_findings_fn(
                static_run_id=int(static_run_id),
                rows=findings_context.canonical_finding_rows,
            )
        except Exception as exc:
            raise_db_error("canonical_findings.write", f"{exc.__class__.__name__}:{exc}")

    if static_run_id and findings_context.correlation_rows:
        try:
            ok = persist_correlation_results_fn(findings_context.correlation_rows)
        except Exception as exc:
            raise_db_error("static_correlation_results.write", f"{exc.__class__.__name__}:{exc}")
        if not ok:
            raise_db_error("static_correlation_results.write", f"returned_false:static_run_id={static_run_id}")


def persist_permission_and_storage_stage(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context,
    findings_context,
    raise_db_error,
    outcome,
    stage_persist_permission_and_storage_fn,
    persist_masvs_controls,
    persist_storage_surface_data,
    persist_permission_matrix,
    persist_permission_risk,
    safe_int,
) -> None:
    stage_persist_permission_and_storage_fn(
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
        outcome=outcome,
    )


def persist_metrics_and_sections_stage(
    *,
    run_id: int | None,
    static_run_id: int | None,
    stage_context,
    metrics_context,
    findings_context,
    outcome,
    note_db_error,
    raise_db_error,
    stage_persist_metrics_and_sections_fn,
    persist_static_sections_wrapper,
) -> None:
    stage_persist_metrics_and_sections_fn(
        run_id=run_id,
        static_run_id=static_run_id,
        stage_context=stage_context,
        metrics_context=metrics_context,
        findings_context=findings_context,
        outcome=outcome,
        note_db_error=note_db_error,
        raise_db_error=raise_db_error,
        persist_static_sections_wrapper=persist_static_sections_wrapper,
    )


def finalize_static_handoff_stage(
    *,
    static_run_id: int | None,
    stage_context,
    run_context,
    cached_schema_version: str,
    outcome,
    build_static_handoff_fn,
    persist_static_handoff_fn,
    classify_static_contract_fn,
    update_static_run_metadata_fn,
    run_sql_fn,
    get_git_commit_fn,
    log,
) -> bool:
    handoff_failed = False
    if static_run_id and stage_context.base_report.__class__.__name__ == "StaticAnalysisReport":
        try:
            handoff_payload = build_static_handoff_fn(
                report=stage_context.base_report,
                string_data=stage_context.string_data,
                package_name=stage_context.package_for_run,
                version_code=run_context.version_code,
                base_apk_sha256=run_context.base_apk_sha256,
                artifact_set_hash=run_context.artifact_set_hash,
                static_run_id=int(static_run_id),
                session_label=stage_context.session_stamp,
                tool_semver=app_config.APP_VERSION,
                tool_git_commit=get_git_commit_fn(),
                schema_version=cached_schema_version,
            )
            handoff_hash = persist_static_handoff_fn(
                static_run_id=int(static_run_id),
                handoff_payload=handoff_payload,
            )
            outcome.static_handoff_hash = handoff_hash
            handoff_json_path = str(Path("evidence") / "static_runs" / str(static_run_id) / "static_handoff.json")
            identity_block = handoff_payload.get("identity", {}) if isinstance(handoff_payload, Mapping) else {}
            masvs_block = handoff_payload.get("masvs", {}) if isinstance(handoff_payload, Mapping) else {}
            identity_mode = str(identity_block.get("identity_mode") or "") if isinstance(identity_block, Mapping) else None
            identity_conflict_flag = bool(identity_block.get("identity_conflict_flag")) if isinstance(identity_block, Mapping) else None
            masvs_mapping_hash = str(masvs_block.get("masvs_mapping_hash") or "") if isinstance(masvs_block, Mapping) else None
            run_class, non_canonical_reasons = classify_static_contract_fn(
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
                tool_git_commit=get_git_commit_fn(),
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
                research_usable=(bool(run_context.research_usable) if run_context.research_usable is not None else None),
            )
            update_static_run_metadata_fn(
                int(static_run_id),
                static_handoff_hash=handoff_hash,
                static_handoff_json_path=handoff_json_path,
                masvs_mapping_hash=masvs_mapping_hash,
                run_class=run_class,
                non_canonical_reasons=(json.dumps(non_canonical_reasons, ensure_ascii=True, sort_keys=True) if non_canonical_reasons else None),
            )
            if run_class != "CANONICAL":
                try:
                    run_sql_fn(
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
            update_static_run_metadata_fn(
                int(static_run_id),
                run_class="NON_CANONICAL",
                non_canonical_reasons=json.dumps(["HANDOFF_HASH_MISSING", "PERSISTENCE_ERROR"], ensure_ascii=True),
            )
        except Exception:
            pass
    return handoff_failed


def persist_static_sections_wrapper(
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
    persist_static_sections_boundary_fn,
) -> tuple[list[str], bool, int]:
    return persist_static_sections_boundary_fn(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section,
        string_payload=string_payload,
        manifest=manifest,
        app_metadata=app_metadata,
        run_id=run_id,
        static_run_id=static_run_id,
    )
