from __future__ import annotations

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
        "package_name": "com.example.app",
        "static_run_id": 101,
        "run_signature": "abc123",
        "run_signature_version": "v1",
        "artifact_set_hash": "hash123",
        "base_apk_sha256": "base123",
    }


def _db_row():
    return {
        "static_run_id": 101,
        "run_signature": "abc123",
        "run_signature_version": "v1",
        "artifact_set_hash": "hash123",
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
    plan.pop("run_signature")
    outcome = loader.validate_dynamic_plan(plan, package_name="com.example.app")
    assert outcome.status == "FAIL"
    assert any("missing required fields" in reason for reason in outcome.reasons)


def test_plan_validation_unsupported_signature_version(monkeypatch):
    monkeypatch.setattr(loader.core_q, "run_sql", _fake_run_sql_factory(_db_row()))
    plan = _base_plan()
    plan["run_signature_version"] = "v2"
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
