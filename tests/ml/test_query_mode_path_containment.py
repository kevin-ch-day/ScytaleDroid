from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.ml.query_mode_runner import _run_output_dir


@pytest.mark.parametrize("run_id", ["../escape", "/tmp/escape", "nested/run", " run-1 ", ".", ""])
def test_run_output_dir_rejects_unsafe_run_ids(tmp_path: Path, run_id: str) -> None:
    with pytest.raises(ValueError, match="Unsafe operational ML run_id"):
        _run_output_dir(tmp_path / "snapshot", run_id)


def test_run_output_dir_keeps_valid_run_below_snapshot(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"

    output = _run_output_dir(snapshot, "run-1")

    assert output == snapshot / "runs" / "run-1" / "ml" / "v1"
