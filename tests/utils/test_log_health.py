from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scytaledroid.Utils.System.log_health import (
    collect_log_health,
    configured_stale_days,
    render_log_health,
)


def _set_mtime(path: Path, timestamp: float) -> None:
    os.utime(path, (timestamp, timestamp))


def test_collect_log_health_classifies_active_rotated_subdirs_and_stale(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    active = logs / "app.log"
    rotated = logs / "app.log.1.gz"
    harvest = logs / "harvest" / "run.log"
    third_party = logs / "third_party" / "androguard.test.log"
    harvest.parent.mkdir()
    third_party.parent.mkdir()
    active.write_bytes(b"active")
    rotated.write_bytes(b"rotated")
    harvest.write_bytes(b"harvest")
    third_party.write_bytes(b"debug")

    now = datetime(2026, 9, 28, tzinfo=UTC)
    old = datetime(2026, 8, 1, tzinfo=UTC).timestamp()
    _set_mtime(rotated, old)
    _set_mtime(harvest, old)

    report = collect_log_health(logs, older_than_days=30, largest_limit=2, now=now)

    assert report["read_only"] is True
    assert report["summary"] == {
        "file_count": 4,
        "total_size_bytes": 25,
        "active_file_count": 3,
        "rotated_file_count": 1,
        "stale_file_count": 2,
        "stale_active_file_count": 1,
        "stale_rotated_file_count": 1,
        "unreadable_file_count": 0,
        "skipped_symlink_count": 0,
    }
    assert report["categories"]["application"]["file_count"] == 2
    assert report["categories"]["harvest"]["stale_file_count"] == 1
    assert report["categories"]["third_party"]["file_count"] == 1
    assert report["oldest_rotated"]["path"] == "app.log.1.gz"
    assert len(report["largest_files"]) == 2


def test_collect_log_health_skips_symlinks_and_handles_missing_root(tmp_path: Path) -> None:
    missing = collect_log_health(tmp_path / "missing", now=datetime(2026, 9, 28, tzinfo=UTC))
    assert missing["log_root_exists"] is False
    assert missing["summary"]["file_count"] == 0

    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "outside.log"
    target.write_text("outside", encoding="utf-8")
    (logs / "linked.log").symlink_to(target)
    report = collect_log_health(logs, now=datetime(2026, 9, 28, tzinfo=UTC))
    assert report["summary"]["file_count"] == 0
    assert report["summary"]["skipped_symlink_count"] == 1
    assert report["skipped_symlinks"] == ["linked.log"]


def test_collect_log_health_validates_bounds(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="older_than_days"):
        collect_log_health(tmp_path, older_than_days=-1)
    with pytest.raises(ValueError, match="largest_limit"):
        collect_log_health(tmp_path, largest_limit=0)


def test_configured_stale_days_falls_back_for_invalid_values() -> None:
    assert configured_stale_days({}) == 30
    assert configured_stale_days({"SCYTALEDROID_LOGS_STALE_DAYS": "14"}) == 14
    assert configured_stale_days({"SCYTALEDROID_LOGS_STALE_DAYS": "bad"}) == 30
    assert configured_stale_days({"SCYTALEDROID_LOGS_STALE_DAYS": "-1"}) == 30


def test_render_log_health_explains_read_only_result(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "db.log").write_bytes(b"database")
    report = collect_log_health(logs, now=datetime(2026, 9, 28, tzinfo=UTC))
    rendered = render_log_health(report)
    assert "LOG HEALTH — READ ONLY" in rendered
    assert "database" in rendered
    assert "No files were modified or deleted." in rendered
