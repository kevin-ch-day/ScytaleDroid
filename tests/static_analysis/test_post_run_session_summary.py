"""Tests for post-run session summary helpers."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.audit.post_run_session_summary import (
    _audit_row_stats,
    load_persistence_audit_payload,
    resolve_persistence_audit_path,
)


def test_resolve_persistence_audit_path(tmp_path: Path) -> None:
    base = tmp_path / "audit" / "persistence"
    base.mkdir(parents=True)
    p = base / "sess-x_persistence_audit.json"
    p.write_text("{}", encoding="utf-8")
    assert resolve_persistence_audit_path("sess-x", output_dir=str(tmp_path)) == p


def test_load_persistence_audit_payload_stats(tmp_path: Path) -> None:
    base = tmp_path / "audit" / "persistence"
    base.mkdir(parents=True)
    payload = {
        "total_apps": 2,
        "outcome": {"persistence_failed": True},
        "rows": [
            {"package_name": "a.b", "stage": "completed"},
            {
                "package_name": "c.d",
                "stage": "permission_risk.write",
                "exception_class": "RuntimeError",
                "exception_message": "boom",
            },
        ],
    }
    (base / "sess-y_persistence_audit.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    loaded = load_persistence_audit_payload("sess-y", output_dir=str(tmp_path))
    assert loaded is not None
    assert len(loaded["rows"]) == 2
    stats = _audit_row_stats(loaded["rows"])
    assert stats["persistence_warning_rows"] == 0


def test_audit_row_stats_counts_persistence_warnings() -> None:
    rows = [
        {"package_name": "a", "persistence_warnings": [{"warning_code": "duplicate_permission_skipped"}]},
        {"package_name": "b"},
    ]
    stats = _audit_row_stats(rows)
    assert stats["persistence_warning_rows"] == 1
