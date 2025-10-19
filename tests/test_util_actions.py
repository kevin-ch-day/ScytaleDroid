from __future__ import annotations

import os

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scytaledroid.Config import app_config
from scytaledroid.Utils.System import util_actions


@pytest.fixture()
def temp_app_config(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "output"
    logs_dir = tmp_path / "logs"
    data_dir.mkdir()
    output_dir.mkdir()
    logs_dir.mkdir()

    monkeypatch.setattr(app_config, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(app_config, "LOGS_DIR", str(logs_dir))
    monkeypatch.setattr(app_config, "DEVICE_STATE_DIR", "state")

    return data_dir, output_dir, logs_dir


def _touch(path: Path, *, days_ago: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("test")
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    timestamp = when.timestamp()
    os.utime(path, (timestamp, timestamp))


def test_clean_static_analysis_artifacts_prunes_old_files(temp_app_config, capsys):
    data_dir, output_dir, _ = temp_app_config

    reports_dir = Path(data_dir) / "static_analysis" / "reports"
    html_dir = Path(output_dir) / "reports" / "static_analysis"
    tmp_dir = Path(data_dir) / "static_analysis" / "tmp"
    cache_dir = Path(data_dir) / "static_analysis" / "cache"

    _touch(reports_dir / "old.json", days_ago=45)
    _touch(reports_dir / "recent.json", days_ago=1)
    _touch(html_dir / "old.html", days_ago=60)
    _touch(tmp_dir / "temp.bin", days_ago=0)
    _touch(cache_dir / "cache.bin", days_ago=0)

    util_actions.clean_static_analysis_artifacts(retention_days=30)

    captured = capsys.readouterr().out

    assert not (reports_dir / "old.json").exists()
    assert (reports_dir / "recent.json").exists()
    assert not (html_dir / "old.html").exists()
    assert not any(tmp_dir.iterdir())
    assert not any(cache_dir.iterdir())
    assert "deleted" in captured


def test_clean_static_analysis_artifacts_honours_env_override(temp_app_config, monkeypatch):
    data_dir, _, _ = temp_app_config

    reports_dir = Path(data_dir) / "static_analysis" / "reports"
    _touch(reports_dir / "stale.json", days_ago=10)

    monkeypatch.setenv("SCYTALEDROID_STATIC_RETENTION_DAYS", "5")

    util_actions.clean_static_analysis_artifacts()

    assert not (reports_dir / "stale.json").exists()


def test_show_log_locations_lists_expected_paths(temp_app_config, capsys):
    _, _, logs_dir = temp_app_config

    util_actions.show_log_locations()

    output = capsys.readouterr().out

    assert str(Path(logs_dir) / "static_analysis.log") in output
    assert "Device state cache" in output
