import json
from pathlib import Path

from scytaledroid.BehaviorAnalysis.schemas import FEATURE_SCHEMA_HEADERS, PROCESS_SCHEMA
from scytaledroid.BehaviorAnalysis.cli import write_csv


def test_feature_headers_are_stable():
    assert "window_start_utc" in FEATURE_SCHEMA_HEADERS
    assert "window_end_utc" in FEATURE_SCHEMA_HEADERS
    assert FEATURE_SCHEMA_HEADERS[0] == "window_start_utc"


def test_write_csv_writes_headers(tmp_path: Path):
    path = tmp_path / "test.csv"
    write_csv(path, [{"ts_utc": "t"}], PROCESS_SCHEMA)
    text = path.read_text()
    lines = text.strip().splitlines()
    assert lines[0] == ",".join(PROCESS_SCHEMA.headers)
