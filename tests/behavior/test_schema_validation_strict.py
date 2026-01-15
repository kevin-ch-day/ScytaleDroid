from pathlib import Path

import pytest

from scytaledroid.BehaviorAnalysis.schemas import PROCESS_SCHEMA
from scytaledroid.BehaviorAnalysis.cli import write_csv


def test_write_csv_warns_on_bad_type(tmp_path: Path):
    path = tmp_path / "warn.csv"
    # threads expected int; provide non-int, should coerce to blank (non-strict)
    write_csv(path, [{"threads": "not-int"}], PROCESS_SCHEMA, strict=False)
    lines = path.read_text().strip().splitlines()
    assert lines[0] == ",".join(PROCESS_SCHEMA.headers)


def test_write_csv_strict_raises(tmp_path: Path):
    path = tmp_path / "strict.csv"
    with pytest.raises(ValueError):
        write_csv(path, [{"threads": "not-int"}], PROCESS_SCHEMA, strict=True)
