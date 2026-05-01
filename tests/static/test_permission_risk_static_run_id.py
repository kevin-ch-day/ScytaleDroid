from __future__ import annotations


def test_permission_risk_uses_static_run_id_for_vnext(monkeypatch):
    from scytaledroid.StaticAnalysis.cli.persistence import permission_risk as mod

    # Avoid DB schema checks in unit tests.
    monkeypatch.setattr(mod, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(mod, "_ensure_risk_scores_table", lambda: True)
    monkeypatch.setattr(mod, "_ensure_permission_vnext_table", lambda: True)

    captured: dict[str, int] = {}

    def _fake_upsert_risk(_record):
        return None

    def _fake_upsert_vnext(payload):
        captured["run_id"] = int(payload["run_id"])

    monkeypatch.setattr(mod.risk_scores_db, "upsert_risk", _fake_upsert_risk)
    monkeypatch.setattr(mod.permission_risk_db, "upsert_vnext", _fake_upsert_vnext)

    class _Report:
        metadata = {"app_label": "TestApp"}

    class _Bundle:
        permission_detail = {"score_3dp": 2.5, "grade": "B", "dangerous_count": 0, "signature_count": 0, "oem_count": 0}
        permission_score = 2.5
        permission_grade = "B"
        dangerous_permissions = 0
        signature_permissions = 0
        oem_permissions = 0

    mod.persist_permission_risk(
        run_id=111,  # legacy run_id (runs.id)
        static_run_id=222,  # static_analysis_runs.id
        report=_Report(),
        package_name="com.example.app",
        session_stamp="sess",
        scope_label="Example (com.example.app)",
        metrics_bundle=_Bundle(),
        baseline_payload={"app": {"package_name": "com.example.app"}},
        permission_profiles={"android.permission.INTERNET": {"guard_strength": "strong"}},
    )

    assert captured["run_id"] == 222

