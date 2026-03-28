"""Sub-menus for Database Utilities."""

from importlib import import_module

_LAZY_EXPORTS = {
    "run_health_summary": (".health_checks", "run_health_summary"),
    "run_health_checks": (".health_checks", "run_health_checks"),
    "run_query_menu": (".query_runner", "run_query_menu"),
    "show_recent_runs_dashboard": (".runs_dashboard", "show_recent_runs_dashboard"),
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
    "run_health_summary",
    "run_health_checks",
    "run_query_menu",
    "show_recent_runs_dashboard",
]
