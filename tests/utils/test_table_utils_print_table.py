from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import table_utils


def test_print_table_accepts_row_dicts(capsys) -> None:
    table_utils.print_table(
        [
            {"A": "x", "B": 1},
            {"A": "y", "B": 2},
        ],
        headers=["A", "B"],
    )
    out = capsys.readouterr().out
    # Basic smoke: header and at least one row printed.
    assert "A" in out
    assert "B" in out
    assert "x" in out

