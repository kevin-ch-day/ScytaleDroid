"""table_utils.py - Helpers for rendering tabular output in the CLI."""

from __future__ import annotations

from typing import Iterable, List, Sequence


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    padding: int = 2,
    header_separator: str = "-",
) -> None:
    """Render a simple left-aligned ASCII table."""
    rows = list(rows)
    column_count = len(headers)
    widths: List[int] = [len(str(header)) for header in headers]

    for row in rows:
        if len(row) != column_count:
            raise ValueError("Row length does not match headers")
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell or "")))

    pad = " " * padding
    formatted_headers = pad.join(
        str(header).ljust(widths[idx]) for idx, header in enumerate(headers)
    )
    separator = pad.join(header_separator * widths[idx] for idx in range(column_count))

    print(formatted_headers)
    print(separator)
    for row in rows:
        print(pad.join(str(cell or "").ljust(widths[idx]) for idx, cell in enumerate(row)))


def render_key_value_pairs(pairs: Sequence[tuple[str, object]], *, padding: int = 2) -> None:
    """Render key/value information as a two-column table."""
    if not pairs:
        print("No data available.")
        return

    keys = [key for key, _ in pairs]
    key_width = max(len(key) for key in keys)
    for key, value in pairs:
        print(f"{key.ljust(key_width)}{' ' * padding}{value}")
