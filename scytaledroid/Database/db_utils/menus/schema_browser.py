"""Schema browser helpers for Database Utilities menu."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.table_snapshot import TableSnapshot
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_SCHEMA_GROUPS = {
    "static_analysis": (
        "static_findings_summary",
        "static_findings",
        "static_string_summary",
        "static_string_samples",
        "static_fileproviders",
        "static_provider_acl",
        "metrics",
        "runs",
    ),
    "apk_metadata": (
        "android_apk_repository",
        "apk_split_groups",
        "harvest_storage_roots",
        "harvest_artifact_paths",
        "harvest_source_paths",
    ),
    "app_data": (
        "apps",
        "android_app_categories",
    ),
    "permissions": (
        "android_permission_dict_aosp",
        "android_permission_dict_oem",
        "android_permission_dict_queue",
        "android_permission_dict_unknown",
        "android_permission_meta_oem_prefix",
        "android_permission_meta_oem_vendor",
    ),
    "scoring": (
        "permission_audit_snapshots",
        "permission_audit_apps",
        "buckets",
        "contributors",
        "correlations",
        "risk_scores",
    ),
}


def show_schema_browser() -> None:
    """Render the schema browser sub-menu."""

    while True:
        print()
        menu_utils.print_header("Schema Snapshot / Browser")
        menu_options = [
            ("1", "Full schema (with PK + indexes)"),
            ("2", "Columns + sample rows (compact)"),
            ("3", "Static analysis tables"),
            ("4", "APK metadata"),
            ("5", "App data & categories"),
            ("6", "Android permissions"),
            ("7", "Scoring & buckets"),
        ]
        spec = menu_utils.MenuSpec(
            items=menu_options,
            show_exit=True,
            exit_label="Back",
            padding=True,
        )
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice(valid=[opt[0] for opt in menu_options] + ["0"])

        if choice == "1":
            tables = diagnostics.list_tables()
            options = _prompt_render_options(default_include_indexes=True)
            _render_schema_for_tables(tables, **options)
        elif choice == "2":
            tables = diagnostics.list_tables()
            options = _prompt_render_options(default_include_indexes=False)
            _render_schema_for_tables(tables, **options)
        elif choice in {"3", "4", "5", "6", "7"}:
            group_key = {
                "3": "static_analysis",
                "4": "apk_metadata",
                "5": "app_data",
                "6": "permissions",
                "7": "scoring",
            }[choice]
            tables = _filter_existing_tables(_SCHEMA_GROUPS[group_key])
            options = _prompt_render_options(default_include_indexes=True)
            _render_schema_for_tables(tables, show_missing=True, **options)
        elif choice in {"8", "0"}:
            break


def _prompt_render_options(*, default_include_indexes: bool) -> dict[str, object]:
    include_indexes = prompt_utils.prompt_yes_no(
        "Show indexes?",
        default=default_include_indexes,
    )

    sample_input = prompt_utils.prompt_text(
        "Rows to sample [default 3]",
        default="3",
        required=False,
    ).strip()
    try:
        sample_limit = max(0, int(sample_input)) if sample_input else 3
    except ValueError:
        sample_limit = 3

    clip_input = prompt_utils.prompt_text(
        "Clip width for sample rows [default 100]",
        default="100",
        required=False,
    ).strip()
    try:
        clip_width = max(20, int(clip_input)) if clip_input else 100
    except ValueError:
        clip_width = 100

    return {
        "include_indexes": include_indexes,
        "sample_limit": sample_limit,
        "clip_width": clip_width,
    }


def _render_schema_for_tables(
    table_names: Sequence[str],
    *,
    include_indexes: bool,
    sample_limit: int,
    clip_width: int,
    show_missing: bool = False,
) -> None:
    if not table_names:
        print(status_messages.status("No tables found for this selection.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    rendered = 0
    for name in table_names:
        snapshot = diagnostics.build_table_snapshot(name)
        if snapshot is None:
            if show_missing:
                print(status_messages.status(f"{name}: unable to introspect.", level="warn"))
            continue
        if rendered:
            print()
        _render_table_snapshot(
            snapshot,
            include_indexes=include_indexes,
            sample_limit=sample_limit,
            clip_width=clip_width,
        )
        rendered += 1

    if rendered == 0:
        level = "warn" if show_missing else "error"
        print(
            status_messages.status(
                "No tables could be introspected. Check connection or permissions.",
                level=level,
            )
        )
    prompt_utils.press_enter_to_continue()


def _render_table_snapshot(
    snapshot: TableSnapshot,
    *,
    include_indexes: bool,
    sample_limit: int,
    clip_width: int,
) -> None:
    type_token = _format_table_type(snapshot.table_type)
    row_count = "unknown" if snapshot.row_count is None else str(snapshot.row_count)
    header = f"table: {snapshot.name}"
    if type_token:
        header += f"   [{type_token}]"
    meta_bits: list[str] = [f"rows={row_count}"]
    if snapshot.max_timestamp and snapshot.timestamp_column:
        meta_bits.append(f"max({snapshot.timestamp_column})={snapshot.max_timestamp}")
    header += "   " + " · ".join(meta_bits)
    print(header)

    print("columns")
    for column in snapshot.columns:
        default_text = _format_default(column.default)
        null_text = "NULL" if column.is_nullable else "NOT NULL"
        pk_text = " PK" if column.is_primary else ""
        notes_text = f" | notes: {column.notes}" if column.notes else ""
        line = (
            f"  {column.name} ({column.data_type}){pk_text} | {null_text} | "
            f"default: {default_text}{notes_text}"
        )
        print(line)
    if not snapshot.columns:
        print("  (none)")

    if include_indexes:
        print("indexes")
        if snapshot.indexes:
            for index in snapshot.indexes:
                cols = ", ".join(index.columns) if index.columns else "<no columns>"
                unique_text = " [UNIQUE]" if index.unique else ""
                print(f"  {index.name} ({cols}){unique_text}")
        else:
            print("  (none)")

    print(f"sample rows ({sample_limit})")
    if sample_limit <= 0:
        print("  (skipped)")
    else:
        rows = list(snapshot.example_rows or [])[:sample_limit]
        if rows:
            for row in rows:
                print(f"  {_format_sample_row(row, max_length=clip_width)}")
        else:
            print("  (none)")


def _filter_existing_tables(tables: Iterable[str]) -> list[str]:
    existing = set(diagnostics.list_tables())
    filtered: list[str] = []
    for table in tables:
        if table in existing:
            filtered.append(table)
        else:
            print(status_messages.status(f"{table}: not found in current schema.", level="warn"))
    return filtered


def _format_table_type(table_type: str | None) -> str:
    if not table_type:
        return ""
    lowered = table_type.strip().lower()
    if lowered in {"base table", "table"}:
        return "table"
    if lowered == "view":
        return "view"
    return table_type


def _format_default(value: str | None) -> str:
    if value is None or value == "":
        return "—"
    text = str(value)
    if len(text) > 60:
        return text[:57] + "..."
    return text


def _format_sample_row(row: dict, *, max_length: int) -> str:
    try:
        payload = json.dumps(row, default=str, ensure_ascii=False)
    except Exception:
        payload = str(row)
    if len(payload) > max_length:
        return payload[: max_length - 3] + "..."
    return payload


__all__ = ["show_schema_browser"]
