"""Utility helpers for ad-hoc database diagnostics."""

from importlib import import_module

_LAZY_EXPORTS = {
    "database_menu": (".database_menu", "database_menu"),
    "build_table_snapshot": (".diagnostics", "build_table_snapshot"),
    "check_connection": (".diagnostics", "check_connection"),
    "check_required_tables": (".diagnostics", "check_required_tables"),
    "compare_columns": (".diagnostics", "compare_columns"),
    "get_server_info": (".diagnostics", "get_server_info"),
    "get_table_columns": (".diagnostics", "get_table_columns"),
    "list_tables": (".diagnostics", "list_tables"),
    "table_counts": (".diagnostics", "table_counts"),
}


def __getattr__(name: str) -> object:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

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
