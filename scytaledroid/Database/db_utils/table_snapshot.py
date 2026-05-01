"""Utilities for rendering database table snapshots as Markdown."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass
class ColumnInfo:
    """Metadata about a column in a database table."""

    name: str
    data_type: str
    is_nullable: bool
    default: str | None
    is_primary: bool
    notes: str | None = None


@dataclass
class IndexInfo:
    """Description of an index for a database table."""

    name: str
    columns: Sequence[str]
    unique: bool


@dataclass
class TableSnapshot:
    """Container for a rendered snapshot of a database table."""

    name: str
    table_type: str | None
    row_count: int | None
    max_timestamp: str | None
    timestamp_column: str | None
    columns: Sequence[ColumnInfo]
    example_rows: Sequence[dict[str, Any]]
    indexes: Sequence[IndexInfo]
    order_column: str | None

    def render_markdown(self) -> str:
        """Return a Markdown representation of the snapshot."""

        parts: list[str] = []
        parts.append(f"## table: {self.name}\n")

        row_count_text = str(self.row_count) if self.row_count is not None else "unknown"
        type_label = (self.table_type or "").lower()
        if type_label in {"base table", "table"}:
            type_display = "table"
        elif type_label == "view":
            type_display = "view"
        else:
            type_display = self.table_type

        meta_line = f"**row_count:** {row_count_text}"
        if type_display:
            meta_line += f" | **type:** {type_display}"
        if self.max_timestamp and self.timestamp_column:
            meta_line += f" | **max_{self.timestamp_column}:** {self.max_timestamp}"
        parts.append(meta_line + "\n")

        parts.append("### schema")
        parts.append(self._render_schema_table())

        parts.append("")
        parts.append("### example_rows (3)")
        parts.append(self._render_example_rows())

        parts.append("")
        parts.append("### indexes")
        parts.extend(self._render_indexes())

        parts.append("")
        parts.append("### sample_queries")
        parts.extend(self._render_sample_queries())

        return "\n".join(parts).rstrip() + "\n"

    def _render_schema_table(self) -> str:
        headers = ["column", "type", "null", "default", "pk", "notes"]
        header_line = "| " + " | ".join(headers) + " |"
        separator_line = "| " + " | ".join(["------"] * len(headers)) + " |"

        rendered_lines: list[str] = [header_line, separator_line]
        for column in self.columns:
            default_value = column.default if column.default is not None else ""
            notes_value = column.notes or ""
            row = [
                column.name,
                column.data_type,
                "NO" if not column.is_nullable else "YES",
                default_value,
                "yes" if column.is_primary else "no",
                notes_value,
            ]
            rendered_row = "| " + " | ".join(_format_cell(item) for item in row) + " |"
            rendered_lines.append(rendered_row)
        if len(rendered_lines) == 2:  # no columns
            rendered_lines.append("| *(no columns)* | | | | | |")
        return "\n".join(rendered_lines)

    def _render_example_rows(self) -> str:
        column_names = [col.name for col in self.columns]
        if not column_names:
            return "(no columns)"

        header = "| " + " | ".join(column_names) + " |"
        separator = "| " + " | ".join(["---"] * len(column_names)) + " |"

        if not self.example_rows:
            placeholder = "| " + " | ".join(["*(no rows)*"] + ["" for _ in column_names[1:]]) + " |"
            return "\n".join([header, separator, placeholder])

        rendered_rows = []
        for row in self.example_rows:
            rendered = [_format_cell(row.get(name)) for name in column_names]
            rendered_rows.append("| " + " | ".join(rendered) + " |")
        return "\n".join([header, separator, *rendered_rows])

    def _render_indexes(self) -> list[str]:
        if not self.indexes:
            return ["- (none)"]

        entries: list[str] = []
        for index in self.indexes:
            cols = ", ".join(index.columns) if index.columns else "<no columns>"
            unique_text = "yes" if index.unique else "no"
            entries.append(f"- {index.name} ON ({cols}) [unique? {unique_text}]")
        return entries

    def _render_sample_queries(self) -> list[str]:
        table_name = self.name
        queries = [f"- `SELECT COUNT(*) FROM {table_name};`"]
        if self.order_column:
            queries.append(
                f"- `SELECT * FROM {table_name} ORDER BY {self.order_column} DESC LIMIT 3;`"
            )
        else:
            queries.append(f"- `SELECT * FROM {table_name} LIMIT 3;`")
        return queries


def _escape_pipe(value: str) -> str:
    """Escape pipe characters for Markdown tables."""

    return value.replace("|", "\\|")


def _format_cell(value: Any) -> str:
    """Convert a value into a Markdown-friendly string."""

    if value is None:
        return "null"
    if isinstance(value, (bytes, bytearray)):
        return f"0x{value[:8].hex()}…" if value else "0x"
    text = str(value)
    text = text.replace("\n", "\\n")
    if len(text) > 80:
        return text[:77] + "…"
    return _escape_pipe(text)
