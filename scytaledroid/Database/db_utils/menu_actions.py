"""Helper actions for the database utilities menu."""

from __future__ import annotations

import os

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_core import db_config, db_queries as core_q
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


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

__all__ = [
    "maybe_clear_screen",
    "show_connection_and_config",
    "seed_paper_dataset_profile",
]
