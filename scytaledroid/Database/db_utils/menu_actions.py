"""Helper actions for the database utilities menu."""

from __future__ import annotations

import os
import socket
import getpass
from datetime import datetime, timezone

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_core import db_config, db_queries as core_q
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.Config import app_config


def show_connection_and_config() -> None:
    """Display database configuration details and test connectivity."""

    try:
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        host = str(cfg.get("host", "<unknown>"))
        port_display = str(cfg.get("port", "<unknown>"))
        database = str(cfg.get("database", "<unknown>"))
        user = str(cfg.get("user", "<unknown>"))
        cfg_source = getattr(db_config, "DB_CONFIG_SOURCE", "default")
    except Exception as exc:
        backend = host = port_display = database = user = "<unknown>"
        cfg_source = "error"
        print(status_messages.status(f"Unable to read DB config: {exc}", level="warn"))

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Database Configuration")
    print(f"    Backend:    {backend}")
    print(f"    Host:       {host}")
    print(f"    Port:       {port_display}")
    print(f"    Database:   {database}")
    print(f"    Username:   {user}")
    print(f"    Config via: {cfg_source}")
    schema_version = diagnostics.get_schema_version()
    print(f"    Schema ver: {schema_version or '<unknown>'}")
    print()

    _section("Test Database Connection")
    success = diagnostics.check_connection()
    if success:
        print("    Connection established successfully")
    else:
        print("    Connection failed. Check logs for details.")
        if backend == "mysql":
            print("    Verify SCYTALEDROID_DB_URL and ensure schema is bootstrapped.")
    prompt_utils.press_enter_to_continue()


def show_db_status() -> None:
    """Show backend/schema status, config source, and env hints."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    host = str(cfg.get("host", "<unknown>"))
    port_display = str(cfg.get("port", "<unknown>"))
    database = str(cfg.get("database", "<unknown>"))
    user = str(cfg.get("user", "<unknown>"))
    cfg_source = getattr(db_config, "DB_CONFIG_SOURCE", "default")
    schema_version = diagnostics.get_schema_version() or "<unknown>"
    db_url_env = os.environ.get("SCYTALEDROID_DB_URL")

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("DB Status (Quick)")
    print(f"    Backend    : {backend}")
    print(f"    Host       : {host}")
    print(f"    Port       : {port_display}")
    print(f"    Database   : {database}")
    print(f"    Username   : {user}")
    print(f"    Schema ver : {schema_version}")
    print(f"    Config via : {cfg_source}")
    print(f"    SCYTALEDROID_DB_URL set: {bool(db_url_env)}")
    print()
    prompt_utils.press_enter_to_continue()


def maybe_clear_screen() -> None:
    """Clear the terminal when UI preferences request it."""

    try:
        from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui

        if _ui.should_clear():
            from scytaledroid.Utils.System.util_actions import clear_screen as _clear

            _clear()
        else:
            print()
    except Exception:
        print()

def seed_paper_dataset_profile() -> None:
    """Create or update the paper dataset profile and assign packages."""

    profile_key = "RESEARCH_DATASET_ALPHA"
    display_name = "Research Dataset Alpha (v1)"
    description = "ScytaleDroid-Dyn-v1 research dataset (Tier 0/1/2 apps)"
    scope_group = "research"
    sort_order = 10
    is_active = 1
    packages = [
        "com.zhiliaoapp.musically",
        "com.instagram.android",
        "com.reddit.frontpage",
        "com.twitter.android",
        "com.snapchat.android",
        "com.facebook.katana",
        "com.facebook.lite",
        "com.linkedin.android",
        "com.whatsapp",
        "org.telegram.messenger",
        "org.thoughtcrime.securesms",
        "com.discord",
        "com.facebook.orca",
        "com.google.android.apps.messaging",
        "com.tinder",
        "tv.twitch.android.app",
        "com.pinterest",
    ]

    print(status_messages.status("Seeding paper dataset profile (DB).", level="info"))
    print(f"Profile key: {profile_key}")
    print(f"Display name: {display_name}")
    print(f"Packages: {len(packages)}")
    if not prompt_utils.prompt_yes_no("Apply these updates now?", default=True):
        return

    profile_sql = """
        INSERT INTO android_app_profiles (
            profile_key,
            display_name,
            description,
            scope_group,
            sort_order,
            is_active
        ) VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            display_name=VALUES(display_name),
            description=VALUES(description),
            scope_group=VALUES(scope_group),
            sort_order=VALUES(sort_order),
            is_active=VALUES(is_active)
    """
    core_q.run_sql_write(
        profile_sql,
        (
            profile_key,
            display_name,
            description,
            scope_group,
            sort_order,
            is_active,
        ),
        query_name="db_utils.seed_paper_profile",
    )

    app_sql = """
        INSERT INTO apps (package_name, profile_key, publisher_key)
        VALUES (%s, %s, 'UNKNOWN')
        ON DUPLICATE KEY UPDATE profile_key=VALUES(profile_key)
    """
    payload = [(pkg, profile_key) for pkg in packages]
    core_q.run_sql_many(app_sql, payload, query_name="db_utils.seed_paper_profile.apps")

    placeholders = ", ".join(["%s"] * len(packages))
    count_sql = f"SELECT COUNT(*) AS matched FROM apps WHERE package_name IN ({placeholders})"
    rows = core_q.run_sql(count_sql, tuple(packages), fetch="one", dictionary=True)
    matched = rows.get("matched") if isinstance(rows, dict) else None
    print(status_messages.status(f"Updated apps: {matched or 0}", level="success"))
    prompt_utils.press_enter_to_continue()


def ensure_dynamic_tier_column(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has a tier column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    if backend != "mysql":
        print(
            status_messages.status(
                "Tier column migration is only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    if "tier" in {col.lower() for col in columns}:
        print(status_messages.status("dynamic_sessions.tier already present.", level="success"))
        return True

    print(status_messages.status("Missing dynamic_sessions.tier column.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN tier)",
        default=True,
    ):
        return False

    sql = "ALTER TABLE dynamic_sessions ADD COLUMN tier VARCHAR(32) DEFAULT NULL"
    core_q.run_sql_write(sql, query_name="db_utils.dynamic_sessions.add_tier")
    print(status_messages.status("Added dynamic_sessions.tier column.", level="success"))
    return True


def ensure_dynamic_network_quality_column(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has a network_signal_quality column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    if backend != "mysql":
        print(
            status_messages.status(
                "network_signal_quality migration is only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    if "network_signal_quality" in {col.lower() for col in columns}:
        print(status_messages.status("dynamic_sessions.network_signal_quality already present.", level="success"))
        return True

    print(status_messages.status("Missing dynamic_sessions.network_signal_quality column.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN network_signal_quality)",
        default=True,
    ):
        return False

    sql = "ALTER TABLE dynamic_sessions ADD COLUMN network_signal_quality VARCHAR(32) DEFAULT NULL"
    core_q.run_sql_write(sql, query_name="db_utils.dynamic_sessions.add_network_signal_quality")
    print(status_messages.status("Added dynamic_sessions.network_signal_quality column.", level="success"))
    return True


def ensure_dynamic_netstats_rows_columns(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has netstats row counters (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    if backend != "mysql":
        print(
            status_messages.status(
                "netstats row counter migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    column_set = {col.lower() for col in columns}
    needed = {"netstats_rows", "netstats_missing_rows"}
    missing = sorted(needed - column_set)
    if not missing:
        print(status_messages.status("dynamic_sessions netstats row columns already present.", level="success"))
        return True

    print(status_messages.status(f"Missing dynamic_sessions columns: {', '.join(missing)}.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN netstats rows)",
        default=True,
    ):
        return False

    if "netstats_rows" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN netstats_rows INT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_netstats_rows",
        )
        print(status_messages.status("Added dynamic_sessions.netstats_rows column.", level="success"))
    if "netstats_missing_rows" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN netstats_missing_rows INT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_netstats_missing_rows",
        )
        print(status_messages.status("Added dynamic_sessions.netstats_missing_rows column.", level="success"))
    return True


def ensure_dynamic_tier_migrations(*, prompt_user: bool = True) -> bool:
    """Apply all Tier-1 dynamic schema migrations in one step."""

    _ensure_db_ops_log_table()
    schema_before = diagnostics.get_schema_version() or "<unknown>"
    started_at = datetime.now(timezone.utc)
    success = False
    error_text = None
    try:
        tier_ok = ensure_dynamic_tier_column(prompt_user=prompt_user)
        quality_ok = ensure_dynamic_network_quality_column(prompt_user=prompt_user)
        netstats_ok = ensure_dynamic_netstats_rows_columns(prompt_user=prompt_user)
        success = tier_ok and quality_ok and netstats_ok
        target_version = _tier1_schema_version()
        if success and schema_before != target_version:
            _record_schema_version(target_version)
        return success
    except Exception as exc:
        error_text = str(exc)
        raise
    finally:
        finished_at = datetime.now(timezone.utc)
        _log_db_op(
            operation="tier1_schema_migrations",
            schema_before=schema_before,
            schema_after=_tier1_schema_version() if success else (diagnostics.get_schema_version() or schema_before),
            started_at=started_at,
            finished_at=finished_at,
            success=success,
            error_text=error_text,
        )


def _tier1_schema_version() -> str:
    return "0.2.3"


def _ensure_db_ops_log_table() -> None:
    sql = """
        CREATE TABLE IF NOT EXISTS db_ops_log (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          operation VARCHAR(64) NOT NULL,
          schema_before VARCHAR(64) DEFAULT NULL,
          schema_after VARCHAR(64) DEFAULT NULL,
          tool_version VARCHAR(32) DEFAULT NULL,
          username VARCHAR(64) DEFAULT NULL,
          hostname VARCHAR(128) DEFAULT NULL,
          pid INT DEFAULT NULL,
          started_at_utc DATETIME DEFAULT NULL,
          finished_at_utc DATETIME DEFAULT NULL,
          success TINYINT(1) DEFAULT NULL,
          error_text TEXT DEFAULT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          KEY idx_db_ops_operation (operation),
          KEY idx_db_ops_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    core_q.run_sql_write(sql, query_name="db_utils.db_ops_log.ensure")


def _record_schema_version(version: str) -> None:
    if not version:
        return
    sql = "INSERT INTO schema_version (version, applied_at_utc) VALUES (%s, %s)"
    core_q.run_sql_write(
        sql,
        (version, datetime.now(timezone.utc)),
        query_name="db_utils.schema_version.insert",
    )


def _log_db_op(
    *,
    operation: str,
    schema_before: str | None,
    schema_after: str | None,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    sql = """
        INSERT INTO db_ops_log (
          operation,
          schema_before,
          schema_after,
          tool_version,
          username,
          hostname,
          pid,
          started_at_utc,
          finished_at_utc,
          success,
          error_text
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    core_q.run_sql_write(
        sql,
        (
            operation,
            schema_before,
            schema_after,
            app_config.APP_VERSION,
            getpass.getuser(),
            socket.gethostname(),
            os.getpid(),
            started_at,
            finished_at,
            1 if success else 0,
            error_text,
        ),
        query_name="db_utils.db_ops_log.insert",
    )


def log_db_op(
    *,
    operation: str,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    """Public wrapper for logging DB operations."""
    _ensure_db_ops_log_table()
    _log_db_op(
        operation=operation,
        schema_before=diagnostics.get_schema_version() or "<unknown>",
        schema_after=diagnostics.get_schema_version() or "<unknown>",
        started_at=started_at,
        finished_at=finished_at,
        success=success,
        error_text=error_text,
    )

__all__ = [
    "maybe_clear_screen",
    "show_connection_and_config",
    "seed_paper_dataset_profile",
    "ensure_dynamic_tier_column",
    "ensure_dynamic_network_quality_column",
    "ensure_dynamic_tier_migrations",
    "log_db_op",
]
