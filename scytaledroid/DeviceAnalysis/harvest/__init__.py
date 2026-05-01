"""Utilities for targeted APK harvest operations."""

from importlib import import_module

from . import rules
from .models import (
    ArtifactError,
    ArtifactPlan,
    ArtifactResult,
    HarvestPlan,
    InventoryRow,
    PackagePlan,
    PullResult,
    ScopeSelection,
)

_LAZY_EXPORTS = {
    "build_harvest_plan": (".planner", "build_harvest_plan"),
    "quick_harvest": (".quick_harvest", "quick_harvest"),
    "execute_harvest": (".runner", "execute_harvest"),
    "find_package_manifests": (".replay", "find_package_manifests"),
    "build_inventory_rows": (".scope", "build_inventory_rows"),
    "reset_last_scope": (".scope", "reset_last_scope"),
    "select_package_scope": (".scope", "select_package_scope"),
    "select_package_scope_auto": (".scope", "select_package_scope_auto"),
    "HarvestRunMetrics": (".summary", "HarvestRunMetrics"),
    "is_harvest_simple_mode": (".summary", "is_harvest_simple_mode"),
    "preview_plan": (".summary", "preview_plan"),
    "print_package_result": (".summary", "print_package_result"),
    "render_harvest_summary": (".summary", "render_harvest_summary"),
    "render_plan_summary": (".summary", "render_plan_summary"),
    "render_harvest_summary_structured": (".views", "render_harvest_summary_structured"),
    "render_scope_overview": (".views", "render_scope_overview"),
    "replay_manifests": (".replay", "replay_manifests"),
    "replay_package_manifest": (".replay", "replay_package_manifest"),
    "Watchlist": (".watchlists", "Watchlist"),
    "filter_rows_by_watchlist": (".watchlists", "filter_rows_by_watchlist"),
    "load_watchlists": (".watchlists", "load_watchlists"),
    "reset_watchlist_cache": (".watchlists", "reset_watchlist_cache"),
    "save_watchlist": (".watchlists", "save_watchlist"),
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
    "ArtifactError",
    "ArtifactPlan",
    "ArtifactResult",
    "HarvestPlan",
    "InventoryRow",
    "PackagePlan",
    "PullResult",
    "ScopeSelection",
    "build_harvest_plan",
    "build_inventory_rows",
    "quick_harvest",
    "execute_harvest",
    "find_package_manifests",
    "HarvestRunMetrics",
    "is_harvest_simple_mode",
    "preview_plan",
    "print_package_result",
    "render_harvest_summary",
    "render_plan_summary",
    "render_harvest_summary_structured",
    "render_scope_overview",
    "replay_manifests",
    "replay_package_manifest",
    "reset_last_scope",
    "rules",
    "select_package_scope",
    "select_package_scope_auto",
    "Watchlist",
    "filter_rows_by_watchlist",
    "load_watchlists",
    "reset_watchlist_cache",
    "save_watchlist",
]
