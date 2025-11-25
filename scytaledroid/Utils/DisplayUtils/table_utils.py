"""table_utils.py - Helpers for rendering tabular output in the CLI."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from . import colors, text_blocks
from .terminal import get_terminal_width


def _stringify(cell: object) -> str:
    return "" if cell is None else str(cell)


def _pad_visible(text: str, width: int) -> str:
    visible = text_blocks.visible_width(text)
    if visible >= width:
        return text
    return text + " " * (width - visible)


def _shrink_widths(widths: list[int], available: int, padding: int) -> list[int]:
    if not widths:
        return widths
    total_padding = padding * (len(widths) - 1)
    target = max(0, available - total_padding)
    if sum(widths) <= target or target <= 0:
        return widths

    adjusted = widths[:]
    min_width = 4
    changed = True
    while sum(adjusted) > target and changed:
        changed = False
        for idx in reversed(range(len(adjusted))):
            if adjusted[idx] > min_width and sum(adjusted) > target:
                adjusted[idx] -= 1
                changed = True
    return adjusted


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    padding: int = 2,
    header_separator: str = "-",
    use_color: bool | None = None,
    accent_first_column: bool = True,
    compact: bool = False,
    column_styles: Sequence[str] | None = None,
) -> None:
    """Render a simple left-aligned ASCII table."""

    rows = list(rows)
    column_count = len(headers)
    widths: List[int] = [max(1, text_blocks.visible_width(str(header))) for header in headers]

    for row in rows:
        if len(row) != column_count:
            raise ValueError("Row length does not match headers")
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], text_blocks.visible_width(_stringify(cell)))

    term_width = get_terminal_width()
    widths = _shrink_widths(widths, term_width, padding)

    pad = " " * (1 if compact else padding)
    header_cells = [
        _pad_visible(text_blocks.truncate_visible(str(header), widths[idx]), widths[idx])
        for idx, header in enumerate(headers)
    ]
    formatted_headers = pad.join(header_cells)
    separator_cells = []
    for idx in range(column_count):
        cell_width = widths[idx]
        separator_cells.append(header_separator * cell_width)
    separator = pad.join(separator_cells)

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
            raw = _stringify(cell)
            coloured = raw
            if use_color and palette and "\033[" not in raw:
                style_name = None
                if column_styles and idx < len(column_styles):
                    style_name = column_styles[idx]
                if style_name:
                    coloured = colors.apply(raw, colors.style(style_name))
                elif idx == 0 and accent_first_column and raw.strip():
                    coloured = colors.apply(raw, palette.accent, bold=True)
                else:
                    coloured = colors.apply(raw, palette.text)
            truncated = text_blocks.truncate_visible(coloured, widths[idx])
            padded = _pad_visible(truncated, widths[idx])
            cells.append(padded)
        print(pad.join(cells))


def render_key_value_pairs(pairs: Sequence[tuple[str, object]], *, padding: int = 2) -> None:
    """Render key/value information as a two-column table."""
    if not pairs:
        print("No data available.")
        return

    keys = [key for key, _ in pairs]
    key_width = max(text_blocks.visible_width(key) for key in keys)
    for key, value in pairs:
        label = _pad_visible(key, key_width)
        print(f"{label}{' ' * padding}{value}")
