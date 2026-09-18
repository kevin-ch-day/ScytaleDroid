"""Static run INSERT must not assume the 0.3.17 identity-version column exists."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import run_writers


def test_filter_omits_hash_version_for_schema_0_3_16() -> None:
    columns = ["artifact_set_hash", "artifact_set_hash_version", "status"]
    values: list[object] = ["b" * 64, "v1", "STARTED"]
    out_columns, out_values = run_writers._filter_static_run_insert_columns(
        columns,
        values,
        include_hash_version=False,
    )
    assert out_columns == ["artifact_set_hash", "status"]
    assert out_values == ["b" * 64, "STARTED"]


def test_filter_keeps_hash_version_when_column_exists() -> None:
    columns = ["artifact_set_hash", "artifact_set_hash_version", "status"]
    values: list[object] = ["b" * 64, "v1", "STARTED"]
    out_columns, out_values = run_writers._filter_static_run_insert_columns(
        columns,
        values,
        include_hash_version=True,
    )
    assert out_columns == columns
    assert out_values == values
