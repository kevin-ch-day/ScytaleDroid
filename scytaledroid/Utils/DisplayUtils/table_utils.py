"""table_utils.py - Helpers for rendering tabular output in the CLI."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from . import colors


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    padding: int = 2,
    header_separator: str = "-",
    use_color: bool | None = None,
    accent_first_column: bool = True,
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
    header_cells = [str(header).ljust(widths[idx]) for idx, header in enumerate(headers)]
    formatted_headers = pad.join(header_cells)
    separator = pad.join(header_separator * widths[idx] for idx in range(column_count))

    if use_color is None:
        use_color = colors.colors_enabled()

    palette = colors.get_palette() if use_color else None

    if use_color and palette:
        formatted_headers = colors.apply(formatted_headers, palette.header, bold=True)
        separator = colors.apply(separator, palette.divider)
    print(formatted_headers)
    print(separator)

    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            content = str(cell or "").ljust(widths[idx])
            if use_color and palette:
                if idx == 0 and accent_first_column and content.strip():
                    cells.append(colors.apply(content, palette.accent, bold=True))
                else:
                    cells.append(colors.apply(content, palette.text))
            else:
                cells.append(content)
        print(pad.join(cells))


def render_key_value_pairs(pairs: Sequence[tuple[str, object]], *, padding: int = 2) -> None:
    """Render key/value information as a two-column table."""
    if not pairs:
        print("No data available.")
        return

    keys = [key for key, _ in pairs]
    key_width = max(len(key) for key in keys)
    for key, value in pairs:
        print(f"{key.ljust(key_width)}{' ' * padding}{value}")
