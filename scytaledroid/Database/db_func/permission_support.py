"""Helpers to provision permission analytics support tables."""

from __future__ import annotations

from typing import Callable, Iterable, Mapping

from ..db_core import run_sql
from ..db_queries import permission_support as queries

DEFAULT_SIGNALS: tuple[Mapping[str, object], ...] = (
    {
        "signal_key": "camera",
        "display_name": "Camera access",
        "description": "Apps requesting camera capture capabilities.",
        "default_weight": 1.000,
    },
    {
        "signal_key": "microphone",
        "display_name": "Microphone access",
        "description": "Apps requesting audio recording permissions.",
        "default_weight": 1.000,
    },
    {
        "signal_key": "precise_location",
        "display_name": "Precise location",
        "description": "ACCESS_FINE_LOCATION or equivalent high-precision signals.",
        "default_weight": 1.250,
    },
    {
        "signal_key": "background_location",
        "display_name": "Background location",
        "description": "ACCESS_BACKGROUND_LOCATION or similar always-on tracking.",
        "default_weight": 1.500,
    },
    {
        "signal_key": "overlay",
        "display_name": "Overlay / draw-over",
        "description": "SYSTEM_ALERT_WINDOW style overlays.",
        "default_weight": 1.100,
    },
    {
        "signal_key": "contacts",
        "display_name": "Contacts access",
        "description": "Contact/address book permissions.",
        "default_weight": 0.900,
    },
    {
        "signal_key": "calls",
        "display_name": "Call logs & phone state",
        "description": "Phone state and call log access signals.",
        "default_weight": 0.850,
    },
    {
        "signal_key": "sms",
        "display_name": "SMS access",
        "description": "Outbound or inbound SMS permissions.",
        "default_weight": 0.950,
    },
    {
        "signal_key": "storage_broad",
        "display_name": "Legacy storage",
        "description": "Legacy wide storage permissions (READ/WRITE_EXTERNAL_STORAGE).",
        "default_weight": 1.200,
    },
    {
        "signal_key": "bt_triad",
        "display_name": "Bluetooth stack",
        "description": "Bluetooth scan/advertise/connect access.",
        "default_weight": 0.700,
    },
    {
        "signal_key": "notifications",
        "display_name": "Notifications",
        "description": "POST_NOTIFICATIONS or listener-style access.",
        "default_weight": 0.400,
    },
)


def ensure_signal_catalog() -> bool:
    """Ensure the ``permission_signal_catalog`` table exists."""

    try:
        run_sql(queries.CREATE_SIGNAL_CATALOG)
        return True
    except Exception:
        return False


def ensure_signal_mappings() -> bool:
    """Ensure the ``permission_signal_mappings`` table exists."""

    try:
        run_sql(queries.CREATE_SIGNAL_MAPPINGS)
        return True
    except Exception:
        return False


def ensure_cohort_expectations() -> bool:
    """Ensure the ``permission_cohort_expectations`` table exists."""

    try:
        run_sql(queries.CREATE_COHORT_EXPECTATIONS)
        return True
    except Exception:
        return False


def ensure_audit_snapshots() -> bool:
    """Ensure the ``permission_audit_snapshots`` table exists."""

    try:
        run_sql(queries.CREATE_AUDIT_SNAPSHOTS)
        return True
    except Exception:
        return False


def ensure_audit_apps() -> bool:
    """Ensure the ``permission_audit_apps`` table exists."""

    try:
        run_sql(queries.CREATE_AUDIT_APPS)
        return True
    except Exception:
        return False


def ensure_all() -> dict[str, bool]:
    """Ensure the complete permission analytics schema is present."""

    operations: tuple[tuple[str, Callable[[], bool]], ...] = (
        ("permission_signal_catalog", ensure_signal_catalog),
        ("permission_signal_mappings", ensure_signal_mappings),
        ("permission_cohort_expectations", ensure_cohort_expectations),
        ("permission_audit_snapshots", ensure_audit_snapshots),
        ("permission_audit_apps", ensure_audit_apps),
    )
    results: dict[str, bool] = {}
    for table, func in operations:
        try:
            results[table] = bool(func())
        except Exception:
            results[table] = False
    return results


def seed_signal_catalog(entries: Iterable[Mapping[str, object]] | None = None) -> int:
    """Insert or update default signal catalog rows."""

    payloads = list(entries) if entries is not None else list(DEFAULT_SIGNALS)
    if not payloads:
        return 0

    inserted = 0
    for payload in payloads:
        try:
            run_sql(
                """
                INSERT INTO permission_signal_catalog
                    (signal_key, display_name, description, default_weight)
                VALUES (%(signal_key)s, %(display_name)s, %(description)s, %(default_weight)s)
                ON DUPLICATE KEY UPDATE
                    display_name = VALUES(display_name),
                    description = VALUES(description),
                    default_weight = VALUES(default_weight),
                    updated_at = CURRENT_TIMESTAMP
                """,
                payload,
            )
            inserted += 1
        except Exception:
            continue
    return inserted


def seed_defaults() -> dict[str, int]:
    """Seed baseline catalog data used by permission analytics."""

    return {"permission_signal_catalog": seed_signal_catalog()}


__all__ = [
    "ensure_signal_catalog",
    "ensure_signal_mappings",
    "ensure_cohort_expectations",
    "ensure_audit_snapshots",
    "ensure_audit_apps",
    "ensure_all",
    "seed_signal_catalog",
    "seed_defaults",
]
