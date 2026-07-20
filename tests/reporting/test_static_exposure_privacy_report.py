from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest
from scytaledroid.Reporting.models import ReportRequest
from scytaledroid.Reporting.services.report_scope_selector import (
    _static_run_select_sql,
    build_report_request,
    find_static_application_matches,
    list_application_categories,
    resolve_application_category_scope,
    resolve_static_evidence,
)
from scytaledroid.Reporting.study_profiles.static_exposure_privacy import (
    _component_exposure_from_findings,
    generate_static_exposure_privacy_report,
)


def _fake_run_sql(query: str, params: tuple[Any, ...] = (), *, fetch: str = "none", **_: Any) -> list[dict[str, Any]]:
    if "FROM apps a" in query and "COUNT(DISTINCT LOWER(a.package_name))" in query:
        return [{"category_name": "Messaging", "app_count": 2}]
    if "FROM apps a" in query and "WHERE LOWER(COALESCE" in query:
        return [{"package_name": "example.app"}, {"package_name": "second.app"}]
    if "FROM apps a" in query and "LOWER(a.package_name) = LOWER" in query:
        return [
            {
                "package_name": "com.facebook.katana",
                "display_name": "Facebook",
                "app_category": "Social",
            }
        ]
    if "FROM static_analysis_runs sar" in query and "JOIN app_versions" in query:
        return [
            {
                "static_run_id": 4,
                "package_name": "example.app",
                "display_name": "Example",
                "app_category": "Social",
                "version_code": "90",
                "version_name": "0.9",
                "base_apk_sha256": "c" * 64,
                "static_session_stamp": "fixture-session",
                "run_started_at_utc": "2026-07-07T00:00:00+00:00",
                "created_at": "2026-07-07T00:00:00+00:00",
                "status": "COMPLETED",
                "canonical_status": "CANONICAL",
                "identity_valid": 1,
                "split_count": 1,
            },
            {
                "static_run_id": 1,
                "package_name": "example.app",
                "display_name": "Example",
                "app_category": "Social",
                "version_code": "100",
                "version_name": "1.0",
                "base_apk_sha256": "a" * 64,
                "static_session_stamp": "fixture-session",
                "run_started_at_utc": "2026-07-08T00:00:00+00:00",
                "created_at": "2026-07-08T00:00:00+00:00",
                "status": "COMPLETED",
                "canonical_status": "CANONICAL",
                "identity_valid": 1,
                "split_count": 1,
            },
            {
                "static_run_id": 2,
                "package_name": "example.app",
                "display_name": "Example",
                "app_category": "Social",
                "version_code": "100",
                "version_name": "1.0",
                "base_apk_sha256": "a" * 64,
                "static_session_stamp": "fixture-session",
                "run_started_at_utc": "2026-07-09T00:00:00+00:00",
                "created_at": "2026-07-09T00:00:00+00:00",
                "status": "COMPLETED",
                "canonical_status": "CANONICAL",
                "identity_valid": 1,
                "split_count": 1,
            },
            {
                "static_run_id": 3,
                "package_name": "second.app",
                "display_name": "Facebook Messenger",
                "app_category": "Messaging",
                "version_code": "200",
                "version_name": "2.0",
                "base_apk_sha256": "b" * 64,
                "static_session_stamp": "fixture-session",
                "run_started_at_utc": "2026-07-09T01:00:00+00:00",
                "created_at": "2026-07-09T01:00:00+00:00",
                "status": "COMPLETED",
                "canonical_status": "CANONICAL",
                "identity_valid": 1,
                "split_count": 1,
            },
        ]
    if "FROM static_permission_matrix" in query:
        return [
            {"run_id": 2, "package_name": "example.app", "permission_name": "android.permission.CAMERA", "is_runtime_dangerous": 1, "is_special_access": 0, "is_custom": 0},
            {"run_id": 2, "package_name": "example.app", "permission_name": "android.permission.INTERNET", "is_runtime_dangerous": 0, "is_special_access": 0, "is_custom": 0},
            {"run_id": 2, "package_name": "example.app", "permission_name": "android.permission.CAMERA", "is_runtime_dangerous": 1, "is_special_access": 0, "is_custom": 0},
            {"run_id": 3, "package_name": "second.app", "permission_name": "android.permission.INTERNET", "is_runtime_dangerous": 0, "is_special_access": 0, "is_custom": 0},
        ]
    if "FROM static_fileproviders" in query:
        return [
            {"run_id": 2, "package_name": "example.app", "component_name": "Provider", "exported": 1, "effective_guard": "none"},
            {"run_id": 2, "package_name": "example.app", "component_name": "InternalProvider", "exported": 0, "effective_guard": "weak"},
            {"run_id": 3, "package_name": "second.app", "component_name": "Provider", "exported": 0, "effective_guard": "strong"},
        ]
    if "FROM static_analysis_findings" in query:
        return [
            {"run_id": 2, "finding_id": "f1", "severity": "HIGH", "title": "Exported activity without permission", "masvs_area": "PLATFORM"},
            {"run_id": 2, "finding_id": "f2", "severity": "LOW", "title": "Network security config", "masvs_area": "NETWORK"},
            {"run_id": 2, "finding_id": "storage_legacy_external", "severity": "MEDIUM", "title": "Legacy external storage requested", "masvs_area": "STORAGE"},
            {"run_id": 3, "finding_id": "f3", "severity": "INFO", "title": "Storage note", "masvs_area": "STORAGE"},
        ]
    if "FROM static_string_summary" in query:
        return [
            {"run_id": 2, "package_name": "example.app", "endpoints": 4, "http_cleartext": 1, "analytics_ids": 2, "cloud_refs": 1},
            {"run_id": 3, "package_name": "second.app", "endpoints": 1, "http_cleartext": 0, "analytics_ids": 0, "cloud_refs": 1},
        ]
    return []


def _request() -> ReportRequest:
    return build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="research_cohort",
        scope_key="fixture",
        scope_label="Fixture",
        package_names=["example.app", "second.app"],
        evidence_basis_type="named_static_session",
        evidence_basis_key="fixture-session",
        output_contract="publication_candidate",
    )


def test_report_request_validates_independent_dimensions() -> None:
    request = _request()
    assert request.study_profile_key == "static_exposure_privacy"
    with pytest.raises(ValueError):
        ReportRequest(
            study_profile_key="bad",
            study_profile_version="1.0",
            scope_type="research_cohort",
            scope_key="x",
            scope_label="x",
            package_names=["example.app"],
            evidence_basis_type="named_static_session",
            evidence_basis_key="s",
            output_contract="publication_candidate",
        )


def test_static_exposure_report_does_not_create_bundle_when_evidence_validation_fails(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="research_cohort",
        scope_key="fixture",
        scope_label="Fixture",
        package_names=["example.app"],
        evidence_basis_type="fixed_recent_window",
        evidence_basis_key="missing_window",
        output_contract="publication_candidate",
    )
    output_dir = tmp_path / "blocked_report"

    with pytest.raises(ValueError, match="fixed_recent_window requires"):
        generate_static_exposure_privacy_report(request, output_dir=output_dir, run_sql_fn=_fake_run_sql)

    assert not output_dir.exists()


def test_static_exposure_report_blocks_zero_row_output(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="single_app",
        scope_key="missing.app",
        scope_label="missing.app",
        package_names=["missing.app"],
        evidence_basis_type="named_static_session",
        evidence_basis_key="fixture-session",
        output_contract="publication_candidate",
    )
    output_dir = tmp_path / "zero_report"

    with pytest.raises(ValueError, match="No completed canonical"):
        generate_static_exposure_privacy_report(request, output_dir=output_dir, run_sql_fn=lambda *_args, **_kwargs: [])

    assert not output_dir.exists()


def test_application_category_scope_resolves_packages() -> None:
    categories = list_application_categories(run_sql_fn=_fake_run_sql)
    assert categories == [{"category_name": "Messaging", "app_count": 2}]

    scope_key, scope_label, packages = resolve_application_category_scope("Messaging", run_sql_fn=_fake_run_sql)
    assert scope_key == "messaging"
    assert scope_label == "Messaging"
    assert packages == ["example.app", "second.app"]


def test_find_static_application_matches_searches_labels_and_packages() -> None:
    rows = find_static_application_matches("facebook", run_sql_fn=_fake_run_sql)
    assert rows == [
        {
            "package_name": "com.facebook.katana",
            "display_name": "Facebook",
            "app_category": "Social",
        }
    ]


def test_fixed_recent_window_static_evidence_dedupes_latest_per_package() -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="application_category",
        scope_key="messaging",
        scope_label="Messaging",
        package_names=["example.app", "second.app"],
        evidence_basis_type="fixed_recent_window",
        evidence_basis_key="current_static_evidence_30d",
        output_contract="publication_candidate",
        window_start_utc="2026-06-10T00:00:00+00:00",
        window_end_utc="2026-07-10T00:00:00+00:00",
    )
    resolution = resolve_static_evidence(request, run_sql_fn=_fake_run_sql)
    assert resolution.reproduction_status == "CURRENT WINDOW ANALYSIS"
    assert [row.static_run_id for row in resolution.selected_runs] == [2, 3]


def test_single_app_history_window_keeps_distinct_versions_for_same_app() -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="single_app",
        scope_key="example.app",
        scope_label="Example",
        package_names=["example.app"],
        evidence_basis_type="fixed_recent_window",
        evidence_basis_key="single_app_history_14d",
        output_contract="publication_candidate",
        window_start_utc="2026-06-26T00:00:00+00:00",
        window_end_utc="2026-07-10T00:00:00+00:00",
    )
    resolution = resolve_static_evidence(request, run_sql_fn=_fake_run_sql)
    assert [row.static_run_id for row in resolution.selected_runs if row.package_name == "example.app"] == [4, 2]
    assert resolution.exclusions[0]["reason"] == "duplicate_same_build_static_analysis_not_history_contributor"


def test_app_version_history_window_keeps_multiple_runs_per_package() -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="application_category",
        scope_key="messaging",
        scope_label="Messaging",
        package_names=["example.app", "second.app"],
        evidence_basis_type="fixed_recent_window",
        evidence_basis_key="app_version_history_30d",
        output_contract="publication_candidate",
        window_start_utc="2026-06-10T00:00:00+00:00",
        window_end_utc="2026-07-10T00:00:00+00:00",
    )
    resolution = resolve_static_evidence(request, run_sql_fn=_fake_run_sql)
    assert [row.static_run_id for row in resolution.selected_runs] == [4, 2, 3]
    assert resolution.exclusions[0]["reason"] == "duplicate_same_build_static_analysis_not_history_contributor"


def test_static_evidence_named_session_dedupes_to_one_row_per_package() -> None:
    resolution = resolve_static_evidence(_request(), run_sql_fn=_fake_run_sql)
    assert [row.static_run_id for row in resolution.selected_runs] == [2, 3]
    reasons = {row["reason"] for row in resolution.exclusions}
    assert "duplicate_selected_build_static_analysis_not_app_level_contributor" in reasons
    assert "older_or_different_build_static_analysis_not_app_level_contributor" in reasons


def test_static_run_selector_uses_apk_set_split_count_not_set_id() -> None:
    sql = _static_run_select_sql()
    assert "COALESCE(apks.split_count, 0) AS split_count" in sql
    assert "LEFT JOIN apk_sets apks ON apks.apk_set_id = sar.apk_set_id" in sql
    assert "COALESCE(sar.apk_set_id, 0) AS split_count" not in sql


def test_component_exposure_parses_activity_aliases_separately() -> None:
    exposure = _component_exposure_from_findings(
        [
            {
                "title": "Exported activity alias without permission",
                "evidence": '{"detail": "Activity Alias com.example.IconOneAlias is exported but does not declare android:permission."}',
            },
            {
                "title": "Exported activity alias without permission",
                "evidence": '{"detail": "Activity Alias com.example.IconOneAlias is exported but does not declare android:permission."}',
            },
            {
                "title": "Exported activity without permission",
                "evidence": '{"detail": "Activity com.example.MainActivity is exported but does not declare android:permission."}',
            },
            {
                "title": "Exported service gated by android.permission.BIND_JOB_SERVICE",
                "finding_id": "ipc_service_permission_com.example.JobService",
                "evidence": '{"detail": "Service com.example.JobService is exported with permission android.permission.BIND_JOB_SERVICE."}',
            },
            {
                "title": "Exported service gated by android.permission.BIND_JOB_SERVICE",
                "finding_id": "ipc_service_permission_com.example.SecondJobService",
                "evidence": '{"detail": "Exported service relies on android.permission.BIND_JOB_SERVICE (protectionLevel=signature)."}',
                "evidence_hash": "same-for-shared-permission",
            },
            {
                "title": "Exported service gated by android.permission.BIND_JOB_SERVICE",
                "finding_id": "ipc_service_permission_com.example.ThirdJobService",
                "evidence": '{"detail": "Exported service relies on android.permission.BIND_JOB_SERVICE (protectionLevel=signature)."}',
                "evidence_hash": "same-for-shared-permission",
            },
        ]
    )

    assert exposure["exported_activities"] == 1
    assert exposure["exported_activity_aliases"] == 1
    assert exposure["exported_services"] == 3
    assert exposure["exported_total"] == 5
    assert exposure["unguarded_ipc_components"] == 2


def test_static_exposure_privacy_report_fixture_generation(tmp_path: Path) -> None:
    result = generate_static_exposure_privacy_report(_request(), output_dir=tmp_path / "report", run_sql_fn=_fake_run_sql)
    root = Path(result["output_dir"])
    app_rows = list(csv.DictReader((root / "data" / "app_static_metrics.csv").open()))
    assert len(app_rows) == 2
    example = next(row for row in app_rows if row["package_name"] == "example.app")
    assert example["static_run_ids"] == "2"
    assert example["total_declared_permissions"] == "2"
    assert example["normal_permissions"] == "1"
    assert example["dangerous_permissions"] == "1"
    assert example["total_exported_components"] == "2"
    assert example["exported_components_without_permission_guard"] == "2"
    assert "embedded_service_sdk_indicators" in example
    assert "service_indicators" not in example
    assert "composite_static_risk_score" not in example
    manifest = json.loads((root / "manifest" / "report_manifest.json").read_text(encoding="utf-8"))
    assert manifest["mutation_scope"] == "read_only"
    assert manifest["read_only_verification"]["db_rows_mutated"] is False
    assert manifest["study_profile_key"] == "static_exposure_privacy"
    assert manifest["resolved_package_names"] == ["example.app", "second.app"]
    assert manifest["selected_app_build_static_run_identities"][0]["static_run_ids"] == 2
    assert manifest["source_checksums"]
    assert manifest["generated_artifact_checksums"]
    assert manifest["row_counts"]["applications"] == 2
    assert (root / "tables" / "cohort_build_summary.csv").exists()
    assert (root / "tables" / "cohort_build_summary.tex").exists()
    assert (root / "tables" / "paper1_manifest_component_parity.csv").exists()
    assert (root / "tables" / "paper1_permission_usage_matrix.csv").exists()
    assert (root / "tables" / "paper1_network_storage_parity.csv").exists()
    assert (root / "tables" / "paper1_masvs_policy_readiness.csv").exists()
    assert (root / "tables" / "paper1_score_model_inputs.csv").exists()
    assert (root / "tables" / "paper1_score_status.csv").exists()
    assert (root / "report" / "paper1_reproduction_map.csv").exists()
    assert (root / "report" / "paper1_reproduction_gap_analysis.txt").exists()
    assert (root / "report" / "paper1_publication_use_notes.md").exists()
    use_notes = (root / "report" / "paper1_publication_use_notes.md").read_text(encoding="utf-8")
    assert "Do not report a 0-100 overall static risk score" in use_notes
    paper1_score_rows = list(csv.DictReader((root / "tables" / "paper1_score_status.csv").open()))
    assert paper1_score_rows[0]["current_status"] == "blocked"
    assert paper1_score_rows[0]["current_source"] == "tables/paper1_score_model_inputs.csv"
    permission_matrix = list(csv.DictReader((root / "tables" / "paper1_permission_usage_matrix.csv").open()))
    assert permission_matrix[0]["internet"] == "X"
    assert permission_matrix[0]["camera"] == "X"
    network_storage = list(csv.DictReader((root / "tables" / "paper1_network_storage_parity.csv").open()))
    assert network_storage[0]["legacy_external_storage_requested"] == "yes"
    masvs_policy = list(csv.DictReader((root / "tables" / "paper1_masvs_policy_readiness.csv").open()))
    assert masvs_policy[0]["platform_area_status"] == "area_has_findings"
    assert masvs_policy[0]["claim_status"] == "descriptive_only_not_compliance"
    score_inputs = list(csv.DictReader((root / "tables" / "paper1_score_model_inputs.csv").open()))
    assert score_inputs[0]["score_status"] == "inputs_ready_formula_unapproved"
    assert score_inputs[0]["severity_high_count"] == "1"
    assert score_inputs[0]["api_key_indicators"] == "0"
    assert (root / "figures" / "permission_profile_source.csv").exists()
    assert (root / "figures" / "permission_profile.png").exists()
    assert (root / "figures" / "activity_alias_exposure_source.csv").exists()
    assert (root / "figures" / "activity_alias_exposure.png").exists()
    component_rows = list(csv.DictReader((root / "figures" / "component_exposure_source.csv").open()))
    assert "exported_activity_aliases" not in component_rows[0]
    assert "exported_activities" in component_rows[0]
    assert "exported_providers" in component_rows[0]
    masvs_rows = list(csv.DictReader((root / "figures" / "masvs_distribution_source.csv").open()))
    assert "masvs_platform_count" not in masvs_rows[0]
    assert "masvs_platform_non_alias_count" not in masvs_rows[0]
    assert "masvs_privacy_count" in masvs_rows[0]
    assert "masvs_network_count" in masvs_rows[0]
    assert "masvs_storage_count" in masvs_rows[0]
    platform_rows = list(csv.DictReader((root / "figures" / "platform_surface_breakdown_source.csv").open()))
    assert "platform_ipc_component_count" not in platform_rows[0]
    assert "platform_activity_alias_count" not in platform_rows[0]
    assert "platform_provider_acl_count" in platform_rows[0]
    assert "platform_app_link_count" in platform_rows[0]
    assert not (root / "figures" / "permission_profile.pdf").exists()
    assert not (root / "figures" / "permission_profile.svg").exists()
    assert not (root / "figures" / "permission_profile_caption.txt").exists()
    assert not (root / "latex").exists()
    assert (root / "report" / "static_run_provenance_reconciliation.csv").exists()
    assert (root / "report" / "metric_definition_audit.txt").exists()
    assert (root / "report" / "metric_integrity_audit.csv").exists()
    assert (root / "report" / "artifact_quality_audit.csv").exists()
    assert (root / "report" / "large_scope_artifact_policy.txt").exists()
    assert not (root / "report" / "layout_fit_report.txt").exists()
    assert not (root / "report" / "layout_fit_smoke.tex").exists()
    assert not (root / "report" / "static_social_media_2025_reproduction_status.txt").exists()


def test_static_exposure_report_can_opt_into_tex_assets(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="research_cohort",
        scope_key="fixture",
        scope_label="Fixture",
        package_names=["example.app", "second.app"],
        evidence_basis_type="named_static_session",
        evidence_basis_key="fixture-session",
        output_contract="publication_candidate",
        requested_formats=["csv", "json", "txt", "figures", "tex"],
    )
    result = generate_static_exposure_privacy_report(request, output_dir=tmp_path / "report_tex", run_sql_fn=_fake_run_sql)
    root = Path(result["output_dir"])
    assert (root / "tables" / "cohort_build_summary.tex").exists()
    assert (root / "latex" / "methods_insert.tex").exists()
    assert (root / "report" / "layout_fit_report.txt").exists()
    assert (root / "report" / "layout_fit_smoke.tex").exists()


def test_static_exposure_history_report_distinguishes_apps_from_app_build_rows(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="application_category",
        scope_key="messaging",
        scope_label="Messaging",
        package_names=["example.app", "second.app"],
        evidence_basis_type="fixed_recent_window",
        evidence_basis_key="app_version_history_30d",
        output_contract="publication_candidate",
        window_start_utc="2026-06-10T00:00:00+00:00",
        window_end_utc="2026-07-10T00:00:00+00:00",
    )
    result = generate_static_exposure_privacy_report(request, output_dir=tmp_path / "history", run_sql_fn=_fake_run_sql)
    root = Path(result["output_dir"])
    manifest = json.loads((root / "manifest" / "report_manifest.json").read_text(encoding="utf-8"))
    assert manifest["row_counts"]["applications"] == 2
    assert manifest["row_counts"]["application_builds"] == 3

    summary = (root / "report" / "findings_summary.txt").read_text(encoding="utf-8")
    assert "Applications: 2" in summary
    assert "App/build rows: 3" in summary

    figure_rows = list(csv.DictReader((root / "figures" / "permission_profile_source.csv").open()))
    assert "total_declared_permissions" not in figure_rows[0]
    assert "normal_permissions" in figure_rows[0]
    assert "dangerous_permissions" in figure_rows[0]
    assert "special_access_permissions" in figure_rows[0]
    assert "custom_permissions" in figure_rows[0]
    labels = [row["app_label"] for row in figure_rows]
    assert labels[0].startswith("Example (")
    assert labels[1].startswith("Example (")
    assert any(label.startswith("Facebook Msg") for label in labels)
    assert not any(label.startswith("Facebook Messenger") for label in labels)
    assert labels[0] != labels[1]


def test_exact_historical_freeze_missing_manifest_fails_closed(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="single_app",
        scope_key="example.app",
        scope_label="example.app",
        package_names=["example.app"],
        evidence_basis_type="exact_historical_freeze",
        evidence_basis_key=str(tmp_path / "missing.csv"),
        output_contract="frozen",
    )
    with pytest.raises(FileNotFoundError):
        resolve_static_evidence(request, run_sql_fn=_fake_run_sql)


def test_single_app_report_uses_focused_artifact_language(tmp_path: Path) -> None:
    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type="single_app",
        scope_key="example.app",
        scope_label="example.app",
        package_names=["example.app"],
        evidence_basis_type="named_static_session",
        evidence_basis_key="fixture-session",
        output_contract="exploratory",
    )
    result = generate_static_exposure_privacy_report(request, output_dir=tmp_path / "single", run_sql_fn=_fake_run_sql)
    root = Path(result["output_dir"])
    assert (root / "figures" / "permission_breakdown_source.csv").exists()
    permission_rows = list(csv.DictReader((root / "figures" / "permission_breakdown_source.csv").open()))
    assert "total_declared_permissions" not in permission_rows[0]
    assert "normal_permissions" in permission_rows[0]
    component_rows = list(csv.DictReader((root / "figures" / "component_exposure_breakdown_source.csv").open()))
    assert "exported_activity_aliases" not in component_rows[0]
    assert "exported_activities" in component_rows[0]
    assert (root / "figures" / "activity_alias_exposure_source.csv").exists()
    assert (root / "figures" / "platform_surface_breakdown_source.csv").exists()
    assert not (root / "figures" / "permission_heatmap_source.csv").exists()
    assert "descriptive only" in (root / "report" / "limitations.txt").read_text(encoding="utf-8").lower()
