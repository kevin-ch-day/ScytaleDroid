"""Interactive menu for database utilities."""

from __future__ import annotations

from typing import List
import json
from pathlib import Path

from scytaledroid.Database.db_utils import db_utils
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_CORE_TABLES: List[str] = [
    "android_app_definitions",
    "android_apk_repository",
    "harvest_storage_roots",
    "harvest_artifact_paths",
    "harvest_source_paths",
]

def database_menu() -> None:
    """Render the database utilities menu."""

    while True:
        print()
        menu_utils.print_header("Database Utilities")
        menu_utils.print_hint(
            "Use the new provisioning helpers to prepare analytics tables before running permission audits.",
            icon="★",
        )

        groups = [
            (
                "Connection & setup",
                [
                    ("1", "Check database connection", "Verify the current credentials and connectivity."),
                    ("8", "Show DB config (source and values)", "Display the active connection parameters."),
                    ("9", "Configure DB connection (write config/db.json)", "Interactively update connection settings."),
                    ("10", "Create database if missing", "Attempt to create the configured schema on the server."),
                ],
            ),
            (
                "Schema & inventory",
                [
                    ("2", "Inspect table snapshots (Markdown)", "Render copy-pasteable schema summaries for each table."),
                    ("3", "Show core table row counts", "Quick health check for harvest-related tables."),
                    ("4", "Framework permissions: counts by protection", "Breakdown of framework permissions by protection level."),
                    ("5", "Permission tables row counts", "Row counts for framework/vendor/unknown/detected tables."),
                ],
            ),
            (
                "Permission analytics",
                [
                    ("6", "Provision permission analytics tables", "Create helper tables that store signal catalogs and audit runs."),
                    ("7", "Sync framework permission catalog", "Download and upsert the latest Android framework permission metadata."),
                    ("12", "Detected permissions summary", "Top-level stats for detected permissions, vendors, and apps."),
                ],
            ),
            (
                "Advanced",
                [
                    ("11", "Run schema audit script", "Launch the experimental schema checker for deeper diagnostics."),
                ],
            ),
        ]

        valid_choices = ["0"]
        for title, options in groups:
            menu_utils.print_section(title)
            menu_utils.print_menu(options, padding=True)
            valid_choices.extend([str(option[0]) for option in options])

        print("0) Back")
        choice = prompt_utils.get_choice(valid=valid_choices)

        if choice == "1":
            _handle_check_connection()
        elif choice == "2":
            _handle_schema_inspection()
        elif choice == "3":
            _handle_core_counts()
        elif choice == "4":
            _handle_framework_protection_counts()
        elif choice == "5":
            _handle_permission_table_counts()
        elif choice == "6":
            _handle_provision_permission_tables()
        elif choice == "7":
            _handle_write_framework_catalog()
        elif choice == "8":
            _handle_show_db_config()
        elif choice == "9":
            _handle_configure_db_connection()
        elif choice == "10":
            _handle_create_database()
        elif choice == "11":
            _handle_run_schema_audit_script()
        elif choice == "12":
            _handle_detected_summary()
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

    info = db_utils.get_server_info()
    database_name = info.get("database") or "<unknown>"
    print(f"# Database snapshot — {database_name}")
    print(f"_tables discovered: {len(tables)}_\n")

    for table in sorted(tables):
        snapshot = db_utils.build_table_snapshot(table)
        if snapshot is None:
            print(f"<!-- Unable to introspect {table} -->\n")
            continue
        print(snapshot.render_markdown())

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


def _handle_framework_protection_counts() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_queries import framework_permissions as fpq
        rows = core_q.run_sql(fpq.PROTECTION_COUNTS, fetch="all")
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    print()
    menu_utils.print_table(["Protection", "Count"], rows or [])
    prompt_utils.press_enter_to_continue()


def _handle_permission_table_counts() -> None:
    tables = [
        "android_framework_permissions",
        "android_vendor_permissions",
        "android_unknown_permissions",
        "android_detected_permissions",
    ]
    from scytaledroid.Database.db_utils import db_utils as _dbu
    counts = _dbu.table_counts(tables)
    for table in tables:
        value = counts.get(table)
        if value is None:
            print(status_messages.status(f"{table}: unable to query", level="error"))
        else:
            print(status_messages.status(f"{table}: {value} row(s)", level="info"))
    prompt_utils.press_enter_to_continue()


def _handle_provision_permission_tables() -> None:
    results = db_utils.provision_permission_analysis_tables()
    created = results.get("created") or {}
    seeded = results.get("seeded") or {}

    if not created:
        print(status_messages.status("Unable to provision tables (see logs).", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    for table_name, ok in sorted(created.items()):
        level = "success" if ok else "error"
        verb = "ready" if ok else "failed"
        print(status_messages.status(f"{table_name}: {verb}", level=level))

    if seeded:
        for table_name, count in sorted(seeded.items()):
            level = "success" if count else "info"
            message = f"{table_name}: seeded {count} row(s)"
            print(status_messages.status(message, level=level))

    prompt_utils.press_enter_to_continue()


def _handle_write_framework_catalog() -> None:
    """Load the latest framework catalog snapshot and upsert into DB."""
    print(status_messages.status("Preparing to write framework catalog to DB…", level="info"))
    try:
        from scytaledroid.Utils.AndroidPermCatalog.cli import DEFAULT_CACHE
        from scytaledroid.Utils.AndroidPermCatalog import api as perm_api
        from scytaledroid.Database.db_func import framework_permissions as fp

        # Ensure table exists
        if not fp.table_exists() and not fp.ensure_table():
            print(status_messages.status("Unable to create android_framework_permissions table.", level="error"))
            prompt_utils.press_enter_to_continue()
            return

        # Load catalog JSON; if missing, refresh
        items = []
        if DEFAULT_CACHE.exists():
            items = perm_api.load_catalog_json(DEFAULT_CACHE)
        if not items:
            try:
                items = perm_api.load_catalog("auto")
                perm_api.save_catalog_json(
                    DEFAULT_CACHE,
                    items,
                    source="auto",
                    base_url=perm_api.ONLINE_URL,
                    base_urls=[perm_api.ONLINE_URL, *perm_api.additional_doc_urls()],
                )
            except Exception as exc:
                print(status_messages.status(f"Failed to load framework catalog: {exc}", level="error"))
                prompt_utils.press_enter_to_continue()
                return

        processed = fp.upsert_permissions(items, source="db-cli")
        print(status_messages.status(f"Upserts: {processed} / Items: {len(items)}", level="success"))
    except Exception as exc:
        print(status_messages.status(f"DB write failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _handle_show_db_config() -> None:
    try:
        from scytaledroid.Database.db_core import db_config as _dbc
        cfg = _dbc.DB_CONFIG
        src = getattr(_dbc, "DB_CONFIG_SOURCE", "defaults")
        socket_info = cfg.get('unix_socket')
        if socket_info:
            extra = f" unix_socket={socket_info}"
        else:
            extra = ""
        print(status_messages.status(
            f"DB config source: {src}\n  host={cfg.get('host')} port={cfg.get('port')} db={cfg.get('database')} user={cfg.get('user')}{extra}",
            level="info",
        ))
    except Exception as exc:
        print(status_messages.status(f"Unable to read DB config: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _write_file(path: str, content: str) -> bool:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            return False
        p.write_text(content, encoding="utf-8")
        return True
    except Exception:
        return False


def _handle_write_config_template() -> None:
    template = (
        '{\n'
        '  "host": "127.0.0.1",\n'
        '  "port": 3306,\n'
        '  "user": "root",\n'
        '  "password": "",\n'
        '  "database": "scytaledroid",\n'
        '  "charset": "utf8mb4"\n'
        '}\n'
    )
    ok = _write_file("config/db.json.example", template)
    if ok:
        print(status_messages.status("Wrote config/db.json.example — copy to config/db.json and edit values.", level="success"))
    else:
        print(status_messages.status("config/db.json.example already exists (or could not be written).", level="warn"))
    prompt_utils.press_enter_to_continue()


def _handle_configure_db_connection() -> None:
    try:
        from scytaledroid.Database.db_core import db_config as _dbc
        cfg = dict(_dbc.DB_CONFIG)
    except Exception:
        cfg = {"host": "127.0.0.1", "port": 3306, "user": "root", "password": "", "database": "scytaledroid", "charset": "utf8mb4"}

    host = prompt_utils.prompt_text("Host (leave blank if using unix_socket)", default=str(cfg.get("host", "127.0.0.1")))
    port_raw = prompt_utils.prompt_text("Port", default=str(cfg.get("port", 3306)))
    try:
        port = int(port_raw)
    except Exception:
        port = 3306
    user = prompt_utils.prompt_text("User", default=str(cfg.get("user", "root")))
    password = prompt_utils.prompt_text("Password", default=str(cfg.get("password", "")))
    database = prompt_utils.prompt_text("Database", default=str(cfg.get("database", "scytaledroid")))
    charset = prompt_utils.prompt_text("Charset", default=str(cfg.get("charset", "utf8mb4")))

    unix_socket = prompt_utils.prompt_text("unix_socket path (optional)", default=str(cfg.get("unix_socket", "")))

    payload = {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "charset": charset,
    }
    if unix_socket:
        payload["unix_socket"] = unix_socket

    # Write to config/db.json so db_engine overlays next connection
    p = Path("config/db.json")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(status_messages.status(f"Wrote {p}.", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Failed to write {p}: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Quick test using new settings
    from scytaledroid.Database.db_utils import db_utils as _dbu
    ok = _dbu.check_connection()
    if ok:
        print(status_messages.status("Connection OK with new settings.", level="success"))
    else:
        print(status_messages.status("Connection still failing. Verify credentials/network.", level="error"))
    prompt_utils.press_enter_to_continue()


def _handle_create_database() -> None:
    try:
        from scytaledroid.Database.db_core import db_config as _dbc
        from scytaledroid.Database.db_core.db_engine import DatabaseEngine
        cfg = _dbc.DB_CONFIG
        db_name = str(cfg.get("database"))
        ok = DatabaseEngine.create_database_if_missing(db_name)
    except Exception:
        ok = False
        db_name = "<unknown>"
    if ok:
        print(status_messages.status(f"Database ensured: {db_name}", level="success"))
    else:
        print(status_messages.status("Failed to create database (insufficient privileges or connection).", level="error"))
    prompt_utils.press_enter_to_continue()


def _handle_run_schema_audit_script() -> None:
    print(status_messages.status("Launching schema audit script…", level="info"))
    try:
        from scytaledroid.Database.tools.schema_audit import run_interactive

        run_interactive()
    except Exception as exc:
        print(status_messages.status(f"Schema audit failed to run: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _handle_detected_summary() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as _core_q
        # Classification totals
        cls_rows = _core_q.run_sql(
            "SELECT COALESCE(classification,'-') AS class, COUNT(*) AS n FROM android_detected_permissions GROUP BY classification ORDER BY n DESC",
            fetch="all",
        )
        # Framework protections
        prot_rows = _core_q.run_sql(
            "SELECT COALESCE(protection,'-') AS prot, COUNT(*) AS n FROM android_detected_permissions WHERE classification='framework' GROUP BY protection ORDER BY n DESC",
            fetch="all",
        )
        # Top vendor namespaces
        ns_rows = _core_q.run_sql(
            "SELECT COALESCE(namespace,'-') AS ns, COUNT(*) AS n FROM android_detected_permissions WHERE classification='vendor' GROUP BY namespace ORDER BY n DESC LIMIT 20",
            fetch="all",
        )
        # Top apps by dangerous frameworks
        app_rows = _core_q.run_sql(
            """
            SELECT ar.package_name, COUNT(*) AS n
            FROM android_detected_permissions dp
            JOIN android_apk_repository ar ON dp.apk_id = ar.apk_id
            WHERE dp.classification='framework' AND dp.protection='dangerous'
            GROUP BY ar.package_name
            ORDER BY n DESC
            LIMIT 20
            """,
            fetch="all",
        )
    except Exception as exc:
        print(status_messages.status(f"Summary query failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_section("Detected: by classification")
    menu_utils.print_table(["Class", "Count"], cls_rows or [])
    print()
    menu_utils.print_section("Framework: by protection")
    menu_utils.print_table(["Protection", "Count"], prot_rows or [])
    print()
    menu_utils.print_section("Vendor: top namespaces")
    menu_utils.print_table(["Namespace", "Count"], ns_rows or [])
    print()
    menu_utils.print_section("Apps: dangerous framework perms")
    menu_utils.print_table(["Package", "Count"], app_rows or [])
    prompt_utils.press_enter_to_continue()
