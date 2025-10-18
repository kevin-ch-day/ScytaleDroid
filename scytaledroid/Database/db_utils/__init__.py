"""Utility helpers for ad-hoc database diagnostics."""

from .diagnostics import (
    check_connection,
    get_server_info,
    check_required_tables,
    list_tables,
    table_counts,
    compare_columns,
    get_table_columns,
    build_table_snapshot,
)
from .database_menu import database_menu

__all__ = [
    "check_connection",
    "get_server_info",
    "check_required_tables",
    "list_tables",
    "table_counts",
    "compare_columns",
    "get_table_columns",
    "build_table_snapshot",
    "database_menu",
]
