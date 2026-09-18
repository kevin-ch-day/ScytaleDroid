"""Versioned install-set identity must survive the real static-to-dynamic path."""

from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.plans.db_lookup import fetch_static_run_row
from scytaledroid.DynamicAnalysis.plans.payload import extract_plan_identity, plan_schema_issues
from scytaledroid.DynamicAnalysis.storage.persistence import _extract_plan_identity
from scytaledroid.StaticAnalysis.cli.execution.results_persistence import merge_persistence_metadata
from scytaledroid.StaticAnalysis.cli.persistence.run_summary import _build_persistence_run_context
from scytaledroid.StaticAnalysis.cli.persistence.static_handoff import build_static_handoff
from scytaledroid.StaticAnalysis.core import (
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)


def _report() -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=1,
        hashes={"sha256": "b" * 64},
        manifest=ManifestSummary(package_name="com.example.app", version_code="7"),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
    )


def test_persistence_context_reads_artifact_set_hash_version() -> None:
    context = _build_persistence_run_context(
        base_report=_report(),
        manifest_obj=None,
        metadata_map={
            "base_apk_sha256": "a" * 64,
            "artifact_set_hash": "c" * 64,
            "artifact_set_hash_version": "v1",
            "apk_set_id": 843,
        },
        baseline_payload={},
        package_for_run="com.example.app",
    )
    assert context.artifact_set_hash == "c" * 64
    assert context.artifact_set_hash_version == "v1"
    assert context.apk_set_id == 843


def test_static_handoff_payload_keeps_version() -> None:
    payload = build_static_handoff(
        report=_report(),
        string_data={},
        package_name="com.example.app",
        version_code=7,
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        artifact_set_hash_version="v1",
        static_run_id=9,
        session_label="lab",
        tool_semver="2.3.1",
        tool_git_commit="deadbeef",
        schema_version="0.3.16",
    )
    identity = payload["identity"]
    assert identity["artifact_set_hash"] == "c" * 64
    assert identity["artifact_set_hash_version"] == "v1"


def test_dynamic_plan_identity_fallback_copies_version() -> None:
    plan = {
        "package_name": "com.example.app",
        "run_identity": {
            "artifact_set_hash": "c" * 64,
            "artifact_set_hash_version": "v1",
            "base_apk_sha256": "a" * 64,
        },
    }
    extracted = extract_plan_identity(plan)
    assert extracted["artifact_set_hash_version"] == "v1"
    fallback = _extract_plan_identity(
        {
            "run_identity": {
                "artifact_set_hash": "c" * 64,
                "artifact_set_hash_version": "v1",
            }
        }
    )
    assert fallback["artifact_set_hash_version"] == "v1"


def test_unknown_dynamic_identity_does_not_invent_a_version() -> None:
    extracted = extract_plan_identity({"package_name": "com.example.app", "run_identity": {}})
    assert extracted["artifact_set_hash_version"] is None
    fallback = _extract_plan_identity({"run_identity": {"artifact_set_hash": "c" * 64}})
    assert "artifact_set_hash_version" not in fallback or fallback.get("artifact_set_hash_version") in {None, ""}


def test_historical_plan_schema_does_not_require_hash_version() -> None:
    issues = plan_schema_issues(
        {
            "plan_schema_version": "v1",
            "schema_version": "0.2.6",
            "generated_at": "2026-02-06T00:00:00Z",
            "run_identity": {
                "base_apk_sha256": "a" * 64,
                "artifact_set_hash": "c" * 64,
                "run_signature": "d" * 64,
                "run_signature_version": "v1",
                "identity_valid": True,
                "identity_error_reason": None,
            },
            "network_targets": {
                "domains": [],
                "cleartext_domains": [],
                "domain_sources": [],
                "domain_sources_note": "note",
            },
        }
    )
    assert "missing:run_identity.artifact_set_hash_version" not in issues


def test_archived_report_metadata_receives_hash_version() -> None:
    report = _report()
    app_result = SimpleNamespace(
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        artifact_set_hash_version="v1",
        apk_set_id=843,
        run_signature=None,
        run_signature_version=None,
        identity_valid=True,
        identity_error_reason=None,
        harvest_manifest_path=None,
        harvest_capture_status=None,
        harvest_persistence_status=None,
        harvest_research_status=None,
        harvest_matches_planned_artifacts=None,
        harvest_observed_hashes_complete=None,
        research_usable=None,
        exploratory_only=False,
        research_block_reasons=None,
    )
    merge_persistence_metadata(base_report=report, app_result=app_result, params=SimpleNamespace())
    assert report.metadata["artifact_set_hash_version"] == "v1"


def test_static_run_lookup_reads_version_from_apk_sets(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        captured["query"] = query
        return {
            "static_run_id": 1,
            "artifact_set_hash": "c" * 64,
            "artifact_set_hash_version": "v1",
        }

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.plans.db_lookup.core_q.run_sql", _fake_run_sql)
    row = fetch_static_run_row(1)
    query = str(captured["query"])
    assert "apk_sets" in query
    assert "artifact_set_hash_version" in query
    assert "sar.artifact_set_hash_version" in query
    assert row["artifact_set_hash_version"] == "v1"
