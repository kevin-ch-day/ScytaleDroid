"""Interactive menu for database provisioning tasks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Sequence

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.menus import sql_helpers
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .tasks_actions import (
    provision_harvest_tables,
    provision_permission_tables,
    provision_static_tables,
    seed_permission_signals,
)


@dataclass(slots=True)
class TaskHealth:
    """Represents the readiness state for a provisioning task."""

    healthy: bool
    missing: tuple[str, ...] = field(default_factory=tuple)
    note: str | None = None


@dataclass(slots=True)
class ProvisioningItem:
    """Provisioning task with its health check and action."""

    key: str
    label: str
    description: str
    action: Callable[[], None]
    health_check: Callable[[], TaskHealth]


_STATIC_TABLES: tuple[str, ...] = (
    "runs",
    "metrics",
    "buckets",
    "correlations",
    "findings",
    "contributors",
    "static_findings_summary",
    "static_findings",
    "static_string_summary",
    "static_string_samples",
    "doc_hosts",
)

_STATIC_VIEWS: tuple[str, ...] = (
    "v_strings_normalized",
    "v_doc_policy_drift",
    "v_strings_effective",
    "v_string_findings_enriched",
)

_PERMISSION_TABLES: tuple[str, ...] = (
    "permission_signal_catalog",
    "permission_signal_mappings",
    "permission_cohort_expectations",
    "permission_audit_snapshots",
    "permission_audit_apps",
)

_HARVEST_TABLES: tuple[str, ...] = (
    "static_fileproviders",
    "static_provider_acl",
    "static_dynload_events",
    "static_reflection_calls",
    "android_detected_permissions",
)


def _missing_tables(required: Sequence[str]) -> list[str]:
    """Return a list of tables from *required* that are absent."""

    status = diagnostics.check_required_tables(list(required))
    return [name for name in required if not status.get(name)]


def _static_tables_health() -> TaskHealth:
    missing: list[str] = _missing_tables(_STATIC_TABLES)

    for view_name in _STATIC_VIEWS:
        if not sql_helpers.view_exists(view_name):
            missing.append(view_name)

    note: str | None = None
    doc_host_count = sql_helpers.scalar("SELECT COUNT(*) FROM doc_hosts")
    if doc_host_count is None:
        missing.append("doc_hosts (unreachable)")
    elif doc_host_count == 0:
        missing.append("doc_hosts (empty)")
        note = "Seed the documentation allow-list before running static analysis."

    return TaskHealth(healthy=not missing, missing=tuple(missing), note=note)


def _permission_tables_health() -> TaskHealth:
    missing = _missing_tables(_PERMISSION_TABLES)
    return TaskHealth(healthy=not missing, missing=tuple(missing))


def _harvest_tables_health() -> TaskHealth:
    missing = _missing_tables(_HARVEST_TABLES)
    return TaskHealth(healthy=not missing, missing=tuple(missing))


def _permission_catalog_seeded() -> TaskHealth:
    missing = _missing_tables(("permission_signal_catalog",))
    if missing:
        return TaskHealth(healthy=False, missing=tuple(missing))

    count = sql_helpers.scalar("SELECT COUNT(*) FROM permission_signal_catalog")
    if count is None:
        return TaskHealth(healthy=False, missing=("permission_signal_catalog (unreachable)",))
    if count == 0:
        note = "Seed default permission weights to unlock scoring."
        return TaskHealth(
            healthy=False,
            missing=("permission_signal_catalog (empty)",),
            note=note,
        )

    return TaskHealth(healthy=True)


PROVISIONING_ITEMS: tuple[ProvisioningItem, ...] = (
    ProvisioningItem(
        key="1",
        label="Provision static-analysis tables",
        description="Create core run, findings, and string views if they are missing.",
        action=provision_static_tables,
        health_check=_static_tables_health,
    ),
    ProvisioningItem(
        key="2",
        label="Provision permission-analytics tables",
        description="Ensure permission catalog, mappings, and audit tables exist.",
        action=provision_permission_tables,
        health_check=_permission_tables_health,
    ),
    ProvisioningItem(
        key="3",
        label="Provision harvest support tables",
        description="Create provider, dynamic loading, and detected permission tables.",
        action=provision_harvest_tables,
        health_check=_harvest_tables_health,
    ),
    ProvisioningItem(
        key="4",
        label="Seed permission signal catalog",
        description="Insert default permission signal weights if the catalog is empty.",
        action=seed_permission_signals,
        health_check=_permission_catalog_seeded,
    ),
)


def _collect_statuses() -> list[tuple[ProvisioningItem, TaskHealth]]:
    """Evaluate health for each provisioning task."""

    statuses: list[tuple[ProvisioningItem, TaskHealth]] = []
    for item in PROVISIONING_ITEMS:
        try:
            health = item.health_check()
        except Exception:
            health = TaskHealth(healthy=False, missing=("database connection",))
        statuses.append((item, health))
    return statuses


def show_database_tasks_menu() -> None:
    """Display the database tasks menu and dispatch actions."""

    while True:
        print()
        menu_utils.print_header("Database Tasks")

        statuses = _collect_statuses()
        menu_utils.print_section("Provisioning status")
        for item, health in statuses:
            if health.healthy:
                print(status_messages.status(f"{item.label}: ready", level="success"))
                continue

            print(status_messages.status(f"{item.label}: action required", level="error"))
            if health.missing:
                for missing in health.missing:
                    print(f"    • {missing}")
            else:
                print(f"    • {item.description}")
            if health.note:
                print(f"      Note: {health.note}")

        incomplete = [item for item, health in statuses if not health.healthy]
        if not incomplete:
            print()
            print(
                status_messages.status(
                    "All required database components are provisioned. No further actions needed.",
                    level="success",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

        print()
        print(
            status_messages.status(
                "Select a task to create the missing tables or seed required reference data.",
                level="info",
            )
        )

        options = [
            menu_utils.MenuOption(item.key, item.label, item.description)
            for item in incomplete
        ]

        default_choice = options[0].key if options else "0"
        menu_utils.print_menu(
            options,
            padding=False,
            show_exit=True,
            exit_label="Back",
            default=default_choice,
        )

        valid_keys = [option.key for option in options] + ["0"]
        choice = prompt_utils.get_choice(valid_keys, default=default_choice)

        if choice == "0":
            break

        selected = next((item for item in incomplete if item.key == choice), None)
        if selected is None:
            print(status_messages.status("Option not available.", level="warn"))
            continue

        selected.action()


__all__ = ["show_database_tasks_menu"]
