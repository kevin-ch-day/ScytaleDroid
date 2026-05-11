"""Session-level permission insights (audit JSON rollup + DB metrics hooks)."""

from __future__ import annotations

import json
from pathlib import Path

import scytaledroid.StaticAnalysis.cli.audit.permission_session_insights as psi
from scytaledroid.StaticAnalysis.cli.audit.permission_session_insights import fetch_permission_session_insights


def test_classify_matrix_risk_skew() -> None:
    assert psi._classify_matrix_risk_skew("COMPLETED", 1, 1) is None
    assert psi._classify_matrix_risk_skew("COMPLETED", 0, 0) is None
    b = psi._classify_matrix_risk_skew("COMPLETED", 2, 0)
    assert b is not None and b[0] == "SUSPICIOUS_B"
    c = psi._classify_matrix_risk_skew("COMPLETED", 0, 3)
    assert c is not None and c[0] == "SUSPICIOUS_C"
    a = psi._classify_matrix_risk_skew("FAILED", 5, 0)
    assert a is not None and a[0] == "EXPECTED_A"
    a2 = psi._classify_matrix_risk_skew("FAILED", 0, 4)
    assert a2 is not None and a2[0] == "EXPECTED_A" and "vnext" in a2[1].lower()


def test_fetch_duplicate_skips_from_audit_json(tmp_path: Path, monkeypatch) -> None:
    audit_dir = tmp_path / "audit" / "persistence"
    audit_dir.mkdir(parents=True)
    payload = {
        "rows": [
            {
                "package_name": "a.b",
                "static_run_id": 1,
                "persistence_warnings": [
                    {
                        "warning_code": "duplicate_permission_skipped",
                        "canonical_permission_name": "android.permission.camera",
                        "duplicates_skipped_count": "2",
                    }
                ],
            }
        ]
    }
    (audit_dir / "sess-x_persistence_audit.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.audit.permission_session_insights.core_q.run_sql",
        lambda *_a, **_k: None,
    )

    data = fetch_permission_session_insights("sess-x", output_dir=str(tmp_path))
    assert data.get("duplicate_skip_warnings_in_audit") == 1
    assert data.get("duplicate_permission_skips_total_from_audit") == 2
    assert data.get("top_duplicate_canonical_in_audit") == [("android.permission.camera", 2)]


def test_fetch_duplicate_audit_notes_when_historical_payload_has_no_warnings(
    tmp_path: Path, monkeypatch
) -> None:
    audit_dir = tmp_path / "audit" / "persistence"
    audit_dir.mkdir(parents=True)
    payload = {"rows": [{"package_name": "x", "static_run_id": 1}]}
    (audit_dir / "hist_persistence_audit.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.audit.permission_session_insights.core_q.run_sql",
        lambda *_a, **_k: None,
    )

    data = fetch_permission_session_insights("hist", output_dir=str(tmp_path))
    notes = data.get("duplicate_audit_notes") or []
    assert len(notes) >= 1
    assert "persistence_warnings" in " ".join(notes).lower()
