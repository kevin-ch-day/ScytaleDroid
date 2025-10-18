"""Interactive menu for database utilities."""

from __future__ import annotations

from typing import List

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_CORE_TABLES: List[str] = [
    "android_app_definitions",
    "android_apk_repository",
    "harvest_storage_roots",
    "harvest_artifact_paths",
    "harvest_source_paths",
]

_ANALYTICS_TABLES: List[str] = [
    "permission_signal_catalog",
    "permission_signal_mappings",
    "permission_cohort_expectations",
    "permission_audit_snapshots",
    "permission_audit_apps",
]

def database_menu() -> None:
    """Render the database utilities menu (flat layout)."""

    while True:
        # Clear screen before drawing a new menu screen (optional)
        try:
            from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui
            if _ui.should_clear():
                from scytaledroid.Utils.System.util_actions import clear_screen as _clear
                _clear()
            else:
                print()
        except Exception:
            print()
        menu_utils.print_header("Database Utilities")

        # Determine current DB state to toggle setup actions
        analytics_ready = False
        framework_catalog_loaded = False
        try:
            exists = diagnostics.check_required_tables(_ANALYTICS_TABLES + ["android_framework_permissions"]) or {}
            analytics_ready = all(bool(exists.get(t)) for t in _ANALYTICS_TABLES)
            counts = diagnostics.table_counts(["android_framework_permissions"]) or {}
            framework_catalog_loaded = bool((counts.get("android_framework_permissions") or 0) > 0)
        except Exception:
            pass

        # Build a flat, ordered list of options
        options: list[tuple[str, str, str]] = []
        options.append(("1", "Check connection & show config", "Verify connectivity and display active parameters."))
        options.append(("2", "Schema snapshot (Markdown)", "Render copy-pasteable schema summaries for each table."))
        # Option 3 repurposed for schema audit (Quick stats removed)
        options.append(("3", "Run schema audit script", "Launch the experimental schema checker for deeper diagnostics."))

        menu_utils.print_menu(options, padding=True, show_exit=True)
        choice = prompt_utils.get_choice(valid=[opt[0] for opt in options] + ["0"]) 

        if choice == "1":
            _handle_check_connection_and_config()
        elif choice == "2":
            _handle_schema_inspection()
        elif choice == "3":
            _handle_run_schema_audit_script()
        elif choice == "0":
            break

def _handle_check_connection_and_config() -> None:
    """Display DB configuration and test the connection (plain, underlined style)."""

    # Read hardcoded configuration only (no venv/env/file overrides)
    try:
        from scytaledroid.Database.db_core import db_config as _dbc
        cfg = _dbc.DB_CONFIG
        host = str(cfg.get("host", "<unknown>"))
        port_display = str(cfg.get("port", "<unknown>"))
        database = str(cfg.get("database", "<unknown>"))
        user = str(cfg.get("user", "<unknown>"))
    except Exception as exc:
        host = port_display = database = user = "<unknown>"
        print(status_messages.status(f"Unable to read DB config: {exc}", level="warn"))

    # Render configuration in plain, underlined sections
    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Database Configuration")
    print(f"    Host:       {host}")
    print(f"    Port:       {port_display}")
    print(f"    Database:   {database}")
    print(f"    Username:   {user}")
    print()

    _section("Test Database Connection")
    success = diagnostics.check_connection()
    if success:
        print("    Connection established successfully")
    else:
        print("    Connection failed. Check logs for details.")
    prompt_utils.press_enter_to_continue()


def _handle_schema_inspection() -> None:
    tables = diagnostics.list_tables()
    if not tables:
        print(status_messages.status("Unable to list tables (connection failed).", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    info = diagnostics.get_server_info()
    database_name = info.get("database") or "<unknown>"
    print(f"# Database snapshot — {database_name}")
    print(f"_tables discovered: {len(tables)}_\n")

    for table in sorted(tables):
        snapshot = diagnostics.build_table_snapshot(table)
        if snapshot is None:
            print(f"<!-- Unable to introspect {table} -->\n")
            continue
        print(snapshot.render_markdown())

    prompt_utils.press_enter_to_continue()


def _handle_core_counts() -> None:
    counts = diagnostics.table_counts(_CORE_TABLES)
    if not counts:
        print(status_messages.status("Unable to query table counts.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    for table in _CORE_TABLES:
        value = counts.get(table)
        if value is None:
            print(status_messages.status(f"{table}: unable to query", level="error"))
        else:
            print(status_messages.status(f"{table}: {value} row(s)", level="info"))
    prompt_utils.press_enter_to_continue()


def _handle_quick_stats() -> None:
    # Combine core and permission table counts and framework protection distribution.
    from scytaledroid.Database.db_utils import diagnostics as _dbu

    tables_perm = [
        "android_framework_permissions",
        "android_vendor_permissions",
        "android_unknown_permissions",
        "android_detected_permissions",
    ]

    counts = _dbu.table_counts(_CORE_TABLES + tables_perm)

    print()
    menu_utils.print_section("Core table counts")
    for table in _CORE_TABLES:
        value = counts.get(table)
        if value is None:
            print(status_messages.status(f"{table}: unable to query", level="error"))
        else:
            print(status_messages.status(f"{table}: {value} row(s)", level="info"))

    print()
    menu_utils.print_section("Permission tables counts")
    for table in tables_perm:
        value = counts.get(table)
        if value is None:
            print(status_messages.status(f"{table}: unable to query", level="error"))
        else:
            print(status_messages.status(f"{table}: {value} row(s)", level="info"))

    # Framework permission protection distribution (catalog)
    print()
    menu_utils.print_section("Framework permissions: counts by protection")
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_queries.permissions import framework_permissions as fpq
        rows = core_q.run_sql(fpq.PROTECTION_COUNTS, fetch="all")
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))
        rows = []
    menu_utils.print_table(["Protection", "Count"], rows or [])
    prompt_utils.press_enter_to_continue()


def _handle_run_schema_audit_script() -> None:
    print(status_messages.status("Launching schema audit script…", level="info"))
    try:
        from scytaledroid.Database.tools.schema_audit import run_interactive

        run_interactive()
    except Exception as exc:
        print(status_messages.status(f"Schema audit failed to run: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


if __name__ == "__main__":  # pragma: no cover - manual invocation helper
    database_menu()
