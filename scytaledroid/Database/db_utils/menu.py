"""Interactive menu for database utilities."""

from __future__ import annotations

from typing import List

from scytaledroid.Database.db_utils import db_utils
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_CORE_TABLES: List[str] = [
    "android_app_definitions",
    "android_apk_repository",
    "harvest_storage_roots",
    "harvest_artifact_paths",
]

_EXPECTED_COLUMNS = {
    "android_apk_repository": {
        "apk_id",
        "app_id",
        "package_name",
        "file_name",
        "file_size",
        "is_system",
        "installer",
        "version_name",
        "version_code",
        "md5",
        "sha1",
        "sha256",
        "signer_fingerprint",
        "device_serial",
        "harvested_at",
        "is_split_member",
        "split_group_id",
        "created_at",
        "updated_at",
    },
    "harvest_storage_roots": {
        "root_id",
        "host_name",
        "data_root",
        "created_at",
        "updated_at",
    },
    "harvest_artifact_paths": {
        "apk_id",
        "storage_root_id",
        "source_path",
        "local_rel_path",
        "created_at",
        "updated_at",
    },
}


def database_menu() -> None:
    """Render the database utilities menu."""

    while True:
        menu_utils.print_header("Database Utilities")
        options = {
            "1": "Check database connection",
            "2": "Inspect table schemas",
            "3": "Show core table row counts",
        }
        menu_utils.print_menu(options)
        choice = prompt_utils.get_choice(valid=list(options.keys()) + ["0"])

        if choice == "1":
            _handle_check_connection()
        elif choice == "2":
            _handle_schema_inspection()
        elif choice == "3":
            _handle_core_counts()
        elif choice == "0":
            break


def _handle_check_connection() -> None:
    success = db_utils.check_connection()
    if success:
        print(status_messages.status("Database connection established successfully.", level="success"))
    else:
        print(status_messages.status("Database connection failed. Check logs for details.", level="error"))
    prompt_utils.press_enter_to_continue()


def _handle_schema_inspection() -> None:
    tables = db_utils.list_tables()
    if not tables:
        print(status_messages.status("Unable to list tables (connection failed).", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status("Database server: {}".format(db_utils.get_server_info().get("database")), level="info"))
    print(status_messages.status("Found {} table(s).".format(len(tables)), level="info"))
    print()

    for table in sorted(tables):
        print(status_messages.status(f"Table: {table}", level="info"))

        expected = _EXPECTED_COLUMNS.get(table)
        if expected is None:
            cols = db_utils.get_table_columns(table)
            if cols is None:
                print(status_messages.status(
                    "  Unable to read column metadata (insufficient privileges?).",
                    level="error",
                ))
            elif not cols:
                print(status_messages.status(
                    "  No column information returned. Table may be empty or a view requiring privileges.",
                    level="warn",
                ))
            else:
                print(status_messages.status(f"  Columns: {', '.join(cols)}", level="info"))
            print()
            continue

        compare = db_utils.compare_columns(table, expected)
        actual_cols = ", ".join(compare["actual"]) if compare["actual"] else "<no columns>"
        print(status_messages.status(f"  Columns: {actual_cols}", level="info"))
        if compare["unexpected"]:
            print(status_messages.status(
                f"  Unexpected columns: {', '.join(compare['unexpected'])}", level="warn"
            ))
        if compare["missing"]:
            print(status_messages.status(
                f"  Missing expected columns: {', '.join(compare['missing'])}", level="error"
            ))
        print()

    prompt_utils.press_enter_to_continue()


def _handle_core_counts() -> None:
    counts = db_utils.table_counts(_CORE_TABLES)
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
