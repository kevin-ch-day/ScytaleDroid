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
    core_q.run_sql("DELETE FROM permission_audit_apps")
    core_q.run_sql("DELETE FROM permission_audit_snapshots")
    yield
    core_q.run_sql("DELETE FROM static_permission_risk")


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


def _fetch_spr():
    from scytaledroid.Database.db_core import db_queries as core_q

    rows = core_q.run_sql(
        "SELECT package_name, sha256, risk_score, risk_grade, dangerous, signature, vendor FROM static_permission_risk",
        fetch="all",
    )
    return rows or []


def test_persist_permission_risk_uses_report_hash_when_available():
    session = "20250101-000000"
    report = DummyReport(
        {
            "sha256": "aa" * 32,
            "apk_id": 123,
            "package_name": "com.example.app",
        }
    )
    bundle = _bundle(2, 3, 1, 5.0, "C")

    persist_permission_risk(
        run_id=1,
        report=report,
        package_name="com.example.app",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    rows = _fetch_spr()
    assert len(rows) == 1
    pkg, sha, score, grade, d, s, v = rows[0]
    assert pkg == "com.example.app"
    assert sha == "aa" * 32
    assert float(score) == pytest.approx(5.0)
    assert grade == "C"
    assert d == 2
    assert s == 3
    assert v == 1


def test_persist_permission_risk_uses_baseline_hash_when_report_missing():
    session = "20250101-000001"
    report = DummyReport({"apk_id": 456})
    baseline = {"hashes": {"sha256": "bb" * 32}}
    bundle = _bundle(1, 0, 0, 2.5, "B")

    persist_permission_risk(
        run_id=2,
        report=report,
        package_name="com.example.baseline",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload=baseline,
    )

    rows = _fetch_spr()
    assert len(rows) == 1
    assert rows[0][0] == "com.example.baseline"
    assert rows[0][1] == "bb" * 32
    assert float(rows[0][2]) == pytest.approx(2.5)
    assert rows[0][3] == "B"


def test_persist_permission_risk_skips_when_no_hash():
    session = "20250101-000002"
    report = DummyReport({})
    bundle = _bundle(0, 0, 0, 0.0, "A")

    persist_permission_risk(
        run_id=3,
        report=report,
        package_name="com.example.skip",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    rows = _fetch_spr()
    # Without a hash the helper falls back to run_id-derived identifiers.
    assert len(rows) == 1
    assert rows[0][0] == "com.example.skip"


def test_persist_permission_risk_canonicalizes_score_precision():
    session = "20250101-000010"
    report = DummyReport(
        {
            "sha256": "dd" * 32,
            "apk_id": 321,
            "package_name": "Com.Example.Mixed",
        }
    )
    bundle = _bundle(2, 1, 0, 2.34567, "C")

    persist_permission_risk(
        run_id=10,
        report=report,
        package_name="Com.Example.Mixed",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
    )

    rows = _fetch_spr()
    assert len(rows) == 1
    assert rows[0][0] == "com.example.mixed"
    assert float(rows[0][2]) == pytest.approx(2.346, rel=0.0, abs=1e-6)


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


def test_persist_permission_risk_vnext_disabled_by_default(monkeypatch):
    session = "20250101-000012"
    report = DummyReport({"apk_id": 600, "sha256": "ff" * 32})
    bundle = _bundle(1, 0, 0, 1.111, "B")
    called = {"vnext": False}
    monkeypatch.delenv("SCYTALEDROID_ENABLE_SPR_VNEXT", raising=False)
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
        permission_profiles={"android.permission.INTERNET": {"is_runtime_dangerous": False}},
    )
    assert called["vnext"] is False


def test_persist_permission_risk_vnext_enabled_calls_writer(monkeypatch):
    session = "20250101-000013"
    report = DummyReport({"apk_id": 601, "sha256": "11" * 32})
    bundle = _bundle(2, 0, 0, 2.222, "C")
    captured: dict[str, object] = {}
    monkeypatch.setenv("SCYTALEDROID_ENABLE_SPR_VNEXT", "1")

    def _capture(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.permission_risk._persist_permission_risk_vnext",
        _capture,
    )

    profiles = {
        "android.permission.READ_CONTACTS": {
            "is_runtime_dangerous": True,
            "guard_strength": "weak",
        }
    }
    persist_permission_risk(
        run_id=13,
        report=report,
        package_name="com.example.vnext",
        session_stamp=session,
        scope_label="Test",
        metrics_bundle=bundle,
        baseline_payload={},
        permission_profiles=profiles,
    )
    assert captured["run_id"] == 13
    assert captured["permission_profiles"] == profiles
    assert captured["risk_score_text"] == "2.222"
