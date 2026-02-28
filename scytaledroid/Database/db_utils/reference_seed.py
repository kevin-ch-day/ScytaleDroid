"""Seed minimal reference rows required by FK-constrained schemas.

Some deployments enforce foreign keys from `apps.profile_key`/`apps.publisher_key`
into `android_app_profiles`/`android_app_publishers`. The canonical schema allows
defaults ('UNCLASSIFIED', 'UNKNOWN'), but older or stricter schemas may add FK
constraints. This module ensures those reference rows exist so operational flows
(harvest, static persistence) don't fail with IntegrityError.
"""

from __future__ import annotations

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_core import run_sql


_DEFAULT_PUBLISHERS: dict[str, tuple[str, str, int]] = {
    "UNKNOWN": ("Unknown", "Default placeholder publisher key", 999),
    "VENDOR_MISC": ("Vendor Misc", "Unmapped vendor/apps bucket", 998),
    # Keys used by fallback publisher rules (publisher_rules.py).
    "ANDROID_AOSP": ("Android (AOSP)", "Android platform / AOSP", 10),
    "GOOGLE": ("Google", "Google apps/services", 20),
    "MOTOROLA": ("Motorola", "Motorola OEM packages", 30),
    "QUALCOMM": ("Qualcomm", "Qualcomm/vendor packages", 40),
    "TMOBILE": ("T-Mobile", "T-Mobile carrier packages", 50),
    "ATT": ("AT&T", "AT&T carrier packages", 60),
    "VERIZON": ("Verizon", "Verizon carrier packages", 70),
}

def _insert_ignore_keyword() -> str:
    """Return the dialect-appropriate INSERT ignore keyword.

    We run SQLite only in unit tests; operator runs are MySQL/MariaDB-backed.
    """

    engine = str(DB_CONFIG.get("engine", "disabled")).lower()
    if engine == "sqlite":
        return "INSERT OR IGNORE"
    return "INSERT IGNORE"


def ensure_default_publishers() -> None:
    """Ensure required publisher keys exist (idempotent)."""

    insert_kw = _insert_ignore_keyword()
    sql = f"""
            {insert_kw} INTO android_app_publishers
                (publisher_key, display_name, description, sort_order, is_active)
            VALUES
                (%s, %s, %s, %s, 1)
            """
    for key, (name, desc, order) in _DEFAULT_PUBLISHERS.items():
        run_sql(
            sql,
            (key, name, desc, int(order)),
            query_name="db_utils.reference_seed.publishers",
        )


def ensure_default_profiles() -> None:
    """Ensure required profile keys exist (idempotent)."""

    # Some legacy/static-ingest code paths still use profile_key='UNKNOWN'. Keep both.
    rows = [
        ("UNCLASSIFIED", "Unclassified", "Default profile bucket", "system", 999),
        ("UNKNOWN", "Unknown", "Legacy placeholder profile key", "system", 1000),
    ]
    insert_kw = _insert_ignore_keyword()
    sql = f"""
            {insert_kw} INTO android_app_profiles
                (profile_key, display_name, description, scope_group, sort_order, is_active)
            VALUES
                (%s, %s, %s, %s, %s, 1)
            """
    for profile_key, name, desc, scope_group, order in rows:
        run_sql(
            sql,
            (profile_key, name, desc, scope_group, int(order)),
            query_name="db_utils.reference_seed.profiles",
        )


def ensure_default_reference_rows() -> None:
    """Ensure all minimal reference dictionaries exist (idempotent)."""

    ensure_default_publishers()
    ensure_default_profiles()


__all__ = [
    "ensure_default_publishers",
    "ensure_default_profiles",
    "ensure_default_reference_rows",
]
