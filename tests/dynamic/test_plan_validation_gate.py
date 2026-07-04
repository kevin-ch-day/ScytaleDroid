from __future__ import annotations

import pytest
from scytaledroid.DynamicAnalysis.plans import loader


def _fake_run_sql_factory(db_row, link_row=None):
    def _fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        if "static_analysis_runs" in query:
            return db_row
        if "static_session_run_links" in query:
            return link_row
        return None

    return _fake_run_sql


def _base_plan():
    return {
        "plan_schema_version": "v1",
        "schema_version": "0.2.6",
        "generated_at": "2026-02-06T00:00:00Z",
        "package_name": "com.example.app",
        "static_run_id": 101,
        "run_identity": {
            "base_apk_sha256": "base123",
            "artifact_set_hash": "hash123",
            "static_handoff_hash": "h" * 64,
            "run_signature": "abc123",
            "run_signature_version": "v1",
            "identity_valid": True,
            "identity_error_reason": None,
        },
        "network_targets": {
            "domains": [],
            "cleartext_domains": [],
            "domain_sources": [],
            "domain_sources_note": "Sources are advisory signals (strings, nsc) and are not ground truth.",
        },
    }


def _db_row():
    return {
        "static_run_id": 101,
        "run_signature": "abc123",
        "run_signature_version": "v1",
        "artifact_set_hash": "hash123",
        "static_handoff_hash": "h" * 64,
        "base_apk_sha256": "base123",
        "pipeline_version": "2.0.0-alpha",
        "package_name": "com.example.app",
    }


def test_plan_validation_pass(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "PASS"
    assert outcome.reasons == []


def test_plan_validation_package_mismatch(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.other.app")
    assert outcome.status == "FAIL"
    assert any("package" in mismatch["field"] for mismatch in outcome.mismatches)


def test_plan_validation_missing_required_fields(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    plan = _base_plan()
    # run_signature is nested under run_identity in v1 plans.
    plan["run_identity"].pop("run_signature")
    outcome = loader.validate_dynamic_plan(plan, package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any("missing required fields" in reason for reason in outcome.reasons)


def test_plan_validation_unsupported_signature_version(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    plan = _base_plan()
    # run_signature_version is nested under run_identity in v1 plans.
    plan["run_identity"]["run_signature_version"] = "v2"
    outcome = loader.validate_dynamic_plan(plan, package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any("unsupported run_signature_version" in reason for reason in outcome.reasons)


def test_plan_validation_run_signature_mismatch(monkeypatch):
    db_row = _db_row()
    db_row["run_signature"] = "different"
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any(mismatch["field"] == "run_signature" for mismatch in outcome.mismatches)


def test_plan_validation_artifact_set_hash_mismatch(monkeypatch):
    db_row = _db_row()
    db_row["artifact_set_hash"] = "different"
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any(mismatch["field"] == "artifact_set_hash" for mismatch in outcome.mismatches)


def test_plan_validation_static_run_id_mismatch(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    outcome = loader.validate_dynamic_plan(
        _base_plan(),
        package_name="com.example.app",
        static_run_id=999,
    )
    assert outcome.status == "FAIL"
    assert any(mismatch["field"] == "static_run_id" for mismatch in outcome.mismatches)


def test_plan_validation_base_apk_sha256_warn(monkeypatch):
    db_row = _db_row()
    db_row["base_apk_sha256"] = "different"
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "PASS"
    assert any("base_apk_sha256" in warning for warning in outcome.warnings)


def test_plan_validation_db_signature_version_unsupported(monkeypatch):
    db_row = _db_row()
    db_row["run_signature_version"] = "v2"
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any("unsupported db run_signature_version" in reason for reason in outcome.reasons)


def test_plan_validation_static_handoff_hash_mismatch(monkeypatch):
    db_row = _db_row()
    db_row["static_handoff_hash"] = "z" * 64
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))
    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any(mismatch["field"] == "static_handoff_hash" for mismatch in outcome.mismatches)


def test_plan_validation_missing_static_handoff_hash(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    plan = _base_plan()
    plan["run_identity"].pop("static_handoff_hash")
    outcome = loader.validate_dynamic_plan(plan, package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any("missing required fields" in reason for reason in outcome.reasons)


def test_render_plan_validation_block_surfaces_static_handoff_hash_status(monkeypatch):
    db_row = _db_row()
    db_row["static_handoff_hash"] = "z" * 64
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(db_row))

    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
    block = loader.render_plan_validation_block(outcome)

    assert "PLAN VALIDATION FAILED" in block
    assert "Static handoff hash  : MISMATCH" in block
    assert "Dynamic execution blocked." in block


def test_build_plan_validation_event_includes_summary_counts(monkeypatch):
    plan = _base_plan()
    plan["run_identity"].pop("static_handoff_hash")
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))

    outcome = loader.validate_dynamic_plan(plan, package_name="com.example.app")
    event = loader.build_plan_validation_event(outcome)

    assert event["validation_result"] == "FAIL"
    assert event["summary"]["reason_count"] >= 1
    assert event["summary"]["warning_count"] == 0
    assert event["summary"]["mismatch_count"] == len(outcome.mismatches)
    assert event["summary"]["db_row_found"] is True
    assert event["summary"]["has_static_link"] is False


def test_plan_validation_missing_static_handoff_hash_column_degrades_cleanly(monkeypatch):
    fallback_row = dict(_db_row())
    fallback_row.pop("static_handoff_hash")

    def _fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        if "sar.static_handoff_hash" in query:
            raise loader.DatabaseError("no such column: sar.static_handoff_hash")
        if "static_analysis_runs" in query:
            return fallback_row
        return None

    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql)

    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")

    assert outcome.status == "FAIL"
    assert any(
        "static_analysis_runs missing fields: static_handoff_hash" in reason
        for reason in outcome.reasons
    )


def test_plan_validation_unknown_static_handoff_hash_column_degrades_cleanly(monkeypatch):
    fallback_row = dict(_db_row())
    fallback_row.pop("static_handoff_hash")

    def _fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        if "sar.static_handoff_hash" in query:
            raise loader.DatabaseError("Unknown column 'sar.static_handoff_hash' in 'field list'")
        if "static_analysis_runs" in query:
            return fallback_row
        return None

    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql)

    outcome = loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")

    assert outcome.status == "FAIL"
    assert any(
        "static_analysis_runs missing fields: static_handoff_hash" in reason
        for reason in outcome.reasons
    )


def test_plan_validation_re_raises_unrelated_db_errors(monkeypatch):
    def _fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        raise loader.DatabaseError("no such table: static_analysis_runs")

    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql)

    with pytest.raises(loader.DatabaseError, match="no such table: static_analysis_runs"):
        loader.validate_dynamic_plan(_base_plan(), package_name="com.example.app")
