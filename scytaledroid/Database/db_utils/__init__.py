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
from .maintenance import provision_permission_analysis_tables
from .menu import database_menu

__all__ = [
    "check_connection",
    "get_server_info",
    "check_required_tables",
    "list_tables",
    "table_counts",
    "compare_columns",
    "get_table_columns",
    "build_table_snapshot",
    "provision_permission_analysis_tables",
    "database_menu",
]
