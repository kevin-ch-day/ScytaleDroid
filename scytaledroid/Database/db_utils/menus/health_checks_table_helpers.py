"""Table/render utility helpers for DB health checks."""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from typing import Callable

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, table_utils
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width


def print_table_list(title: str, tables: Sequence[str]) -> None:
    if not tables:
        return
    menu_utils.print_section(title)
    print_wrapped_table_block(list(tables))


def count_tables(table_names: Sequence[str], *, scalar: Callable[..., object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in table_names:
        try:
            count = scalar(f"SELECT COUNT(*) FROM {table}") or 0
        except Exception:
            count = 0
        counts[table] = int(count)
    return counts


def print_table_counts(title: str, counts: dict[str, int]) -> None:
    menu_utils.print_section(title)
    if not counts:
        print("  (none)")
        return
    rows = [[name, str(count)] for name, count in counts.items()]
    table_utils.render_table(["Table", "Rows"], rows)


def table_exists(table: str) -> bool:
    try:
        row = run_sql(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = %s
            """,
            (table,),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row and row[0])


def print_wrapped_table_block(tables: Sequence[str], width: int | None = None) -> None:
    if not tables:
        return
    effective_width = width or min(get_terminal_width(), 96)
    joined = ", ".join(tables)
    wrapped = textwrap.wrap(joined, width=effective_width - 2) or [joined]
    for line in wrapped:
        print(f"  {line}")
