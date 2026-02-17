from __future__ import annotations

import types
from collections.abc import Mapping

import pytest
from scytaledroid.StaticAnalysis.cli.persistence.metrics_writer import MetricsBundle
from scytaledroid.StaticAnalysis.cli.persistence.permission_risk import persist_permission_risk


class DummyReport:
    def __init__(self, metadata: Mapping[str, object]) -> None:
        self.metadata = metadata
        self.manifest = types.SimpleNamespace(package_name=metadata.get("package_name"))
        self.hashes = metadata.get("hashes", {})


def _bundle(dangerous: int, signature: int, vendor: int, score: float, grade: str) -> MetricsBundle:
    return MetricsBundle(
        buckets={},
        contributors=[],
        code_http_hosts=0,
        asset_http_hosts=0,
        uses_cleartext=False,
        dangerous_permissions=dangerous,
        signature_permissions=signature,
        oem_permissions=vendor,
        permission_score=score,
        permission_grade=grade,
        permission_detail={
            "dangerous_count": dangerous,
            "signature_count": signature,
            "vendor_count": vendor,
            "score_3dp": score,
            "grade": grade,
        },
    )


@pytest.fixture(autouse=True)
def clear_permission_tables():
    from scytaledroid.Database.db_core import db_queries as core_q

    core_q.run_sql("DELETE FROM static_permission_risk")
    core_q.run_sql("DELETE FROM static_permission_risk_vnext")
    core_q.run_sql("DELETE FROM risk_scores")
    core_q.run_sql("DELETE FROM permission_audit_apps")
    core_q.run_sql("DELETE FROM permission_audit_snapshots")
    yield
    core_q.run_sql("DELETE FROM static_permission_risk")
    core_q.run_sql("DELETE FROM static_permission_risk_vnext")
    core_q.run_sql("DELETE FROM risk_scores")


@pytest.fixture(autouse=True)
def strict_risk_scores_ready(monkeypatch):
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_risk_scores_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda *_args, **_kwargs: True,
    )


def _fetch_spr_vnext():
    from scytaledroid.Database.db_core import db_queries as core_q

    rows = core_q.run_sql(
        """
        SELECT run_id, permission_name, risk_score, risk_class, rationale_code
        FROM static_permission_risk_vnext
        ORDER BY run_id ASC, permission_name ASC
        """,
        fetch="all",
    )
    return rows or []


def test_persist_permission_risk_writes_risk_scores_and_vnext_rows(monkeypatch):
    session = "20250101-000000"
    report = DummyReport(
        {
            "sha256": "aa" * 32,
            "apk_id": 123,
            "package_name": "com.example.app",
        }
    )
    bundle = _bundle(2, 3, 1, 5.0, "C")
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda payload: captured.__setitem__("risk_scores", payload),
    )

    persist_permission_risk(
        run_id=1,
        report=report,
        package_name="com.example.app",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
        permission_profiles={
            "android.permission.camera": {
                "is_runtime_dangerous": True,
                "guard_strength": "weak",
            }
        },
    )

    record = captured["risk_scores"]
    assert str(record.package_name) == "com.example.app"
    assert str(record.risk_score) == "5.000"
    assert str(record.risk_grade) == "C"
    assert int(record.dangerous) == 2
    assert int(record.signature) == 3
    assert int(record.vendor) == 1

    vnext = _fetch_spr_vnext()
    assert len(vnext) == 1
    assert vnext[0][0] == 1
    assert vnext[0][1] == "android.permission.camera"


def test_persist_permission_risk_writes_risk_scores_without_profiles(monkeypatch):
    session = "20250101-000001"
    report = DummyReport({"apk_id": 456})
    bundle = _bundle(1, 0, 0, 2.5, "B")
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda payload: captured.__setitem__("risk_scores", payload),
    )

    persist_permission_risk(
        run_id=2,
        report=report,
        package_name="com.example.baseline",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    record = captured["risk_scores"]
    assert str(record.package_name) == "com.example.baseline"
    assert str(record.risk_score) == "2.500"
    assert str(record.risk_grade) == "B"
    assert _fetch_spr_vnext() == []


def test_persist_permission_risk_does_not_require_hash_fields(monkeypatch):
    session = "20250101-000002"
    report = DummyReport({})
    bundle = _bundle(0, 0, 0, 0.0, "A")
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda payload: captured.__setitem__("risk_scores", payload),
    )

    persist_permission_risk(
        run_id=3,
        report=report,
        package_name="com.example.skip",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    record = captured["risk_scores"]
    assert str(record.package_name) == "com.example.skip"


def test_persist_permission_risk_canonicalizes_score_precision(monkeypatch):
    session = "20250101-000010"
    report = DummyReport(
        {
            "sha256": "dd" * 32,
            "apk_id": 321,
            "package_name": "Com.Example.Mixed",
        }
    )
    bundle = _bundle(2, 1, 0, 2.34567, "C")
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda payload: captured.__setitem__("risk_scores", payload),
    )

    persist_permission_risk(
        run_id=10,
        report=report,
        package_name="Com.Example.Mixed",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    record = captured["risk_scores"]
    assert str(record.package_name) == "com.example.mixed"
    assert str(record.risk_score) == "2.346"


def test_persist_permission_risk_fails_when_risk_scores_unavailable(monkeypatch):
    session = "20250101-000003"
    report = DummyReport({"apk_id": 999, "sha256": "cc" * 32})
    bundle = _bundle(1, 1, 0, 1.5, "B")
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_risk_scores_table",
        lambda: False,
    )

    with pytest.raises(RuntimeError, match="risk_scores table unavailable"):
        persist_permission_risk(
            run_id=4,
            report=report,
            package_name="com.example.fail",
            session_stamp=session,
            scope_label="Test",
            metrics_bundle=bundle,
            baseline_payload={},
        )


def test_persist_permission_risk_fails_on_out_of_range_score():
    session = "20250101-000011"
    report = DummyReport({"apk_id": 500, "sha256": "ee" * 32})
    bundle = _bundle(1, 0, 0, 10.1234, "F")

    with pytest.raises(RuntimeError, match="PERSIST_VALIDATION_FAIL"):
        persist_permission_risk(
            run_id=11,
            report=report,
            package_name="com.example.range",
            session_stamp=session,
            scope_label="Test",
            metrics_bundle=bundle,
            baseline_payload={},
        )


def test_persist_permission_risk_always_calls_vnext_writer(monkeypatch):
    session = "20250101-000012"
    report = DummyReport({"apk_id": 600, "sha256": "ff" * 32})
    bundle = _bundle(1, 0, 0, 1.111, "B")
    called = {"vnext": False}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._persist_permission_risk_vnext",
        lambda **_kwargs: called.__setitem__("vnext", True),
    )

    persist_permission_risk(
        run_id=12,
        report=report,
        package_name="com.example.vnext",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
        permission_profiles={"android.permission.internet": {"is_runtime_dangerous": False}},
    )
    assert called["vnext"] is True


def test_persist_permission_risk_writes_risk_scores_before_vnext_writer(monkeypatch):
    session = "20250101-000014"
    report = DummyReport({"apk_id": 602, "sha256": "22" * 32})
    bundle = _bundle(1, 0, 0, 1.234, "B")
    called = {"risk_scores": False}

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_risk_scores_table",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk.risk_scores_db.upsert_risk",
        lambda *_args, **_kwargs: called.__setitem__("risk_scores", True),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._persist_permission_risk_vnext",
        lambda **_kwargs: True,
    )

    persist_permission_risk(
        run_id=14,
        report=report,
        package_name="com.example.order",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    assert called["risk_scores"] is True


def test_persist_permission_risk_vnext_rejects_noncanonical_permission_name(monkeypatch):
    session = "20250101-000015"
    report = DummyReport({"apk_id": 603, "sha256": "33" * 32})
    bundle = _bundle(1, 0, 0, 1.234, "B")
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_permission_vnext_table",
        lambda: True,
    )

    with pytest.raises(RuntimeError, match="permission_name must be canonical lowercase"):
        persist_permission_risk(
            run_id=15,
            report=report,
            package_name="com.example.case",
            session_stamp=session,
            scope_label="Test",
            metrics_bundle=bundle,
            baseline_payload={},
            permission_profiles={"Android.Permission.CAMERA": {"is_runtime_dangerous": True}},
        )


def test_persist_permission_risk_vnext_rejects_duplicate_after_canonicalization(monkeypatch):
    session = "20250101-000016"
    report = DummyReport({"apk_id": 604, "sha256": "44" * 32})
    bundle = _bundle(1, 0, 0, 1.234, "B")
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_permission_vnext_table",
        lambda: True,
    )

    class _DupProfiles(dict):
        def items(self):
            return iter(
                [
                    ("android.permission.camera", {"is_runtime_dangerous": True}),
                    ("android.permission.camera", {"is_runtime_dangerous": False}),
                ]
            )

    with pytest.raises(RuntimeError, match="duplicate permission_name after canonicalization"):
        persist_permission_risk(
            run_id=16,
            report=report,
            package_name="com.example.dupe",
            session_stamp=session,
            scope_label="Test",
            metrics_bundle=bundle,
            baseline_payload={},
            permission_profiles=_DupProfiles(),
        )


def test_vnext_permission_risk_keeps_cross_run_rows(monkeypatch):
    from scytaledroid.Database.db_core import db_queries as core_q

    core_q.run_sql(
        """
        CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id INTEGER NOT NULL,
          permission_name TEXT NOT NULL,
          risk_score REAL NOT NULL,
          risk_class TEXT NULL,
          rationale_code TEXT NULL,
          created_at_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(run_id, permission_name)
        )
        """
    )
    core_q.run_sql("DELETE FROM static_permission_risk_vnext")

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._ensure_permission_vnext_table",
        lambda: True,
    )
    report = DummyReport({"apk_id": 701, "sha256": "66" * 32})
    bundle = _bundle(1, 0, 0, 1.500, "B")
    profiles = {"android.permission.camera": {"is_runtime_dangerous": True, "guard_strength": "weak"}}

    persist_permission_risk(
        run_id=19,
        report=report,
        package_name="com.example.vnext.crossrun",
        session_stamp="20250101-000019",
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
        permission_profiles=profiles,
    )
    persist_permission_risk(
        run_id=20,
        report=report,
        package_name="com.example.vnext.crossrun",
        session_stamp="20250101-000020",
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
        permission_profiles=profiles,
    )

    rows = core_q.run_sql(
        "SELECT run_id, permission_name, risk_score FROM static_permission_risk_vnext ORDER BY run_id ASC",
        fetch="all",
    )
    assert rows == [(19, "android.permission.camera", 1.5), (20, "android.permission.camera", 1.5)]
