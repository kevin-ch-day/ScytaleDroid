"""Utility helpers for ad-hoc database diagnostics."""

from .database_menu import database_menu
from .diagnostics import (
    build_table_snapshot,
    check_connection,
    check_required_tables,
    compare_columns,
    get_server_info,
    get_table_columns,
    list_tables,
    table_counts,
)

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
