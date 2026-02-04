"""Helpers to provision permission analytics support tables."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from math import isclose

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql

_ALLOWED_BANDS = {"critical", "high", "medium", "low", "none"}
_ALLOWED_STAGES = {"declared", "runtime", "policy"}


DEFAULT_SIGNALS: tuple[Mapping[str, object], ...] = (
    {
        "signal_key": "camera",
        "display_name": "Camera access",
        "description": "Apps requesting camera capture capabilities.",
        "default_weight": 1.000,
        "default_band": "high",
    },
    {
        "signal_key": "microphone",
        "display_name": "Microphone access",
        "description": "Apps requesting audio recording permissions.",
        "default_weight": 1.000,
        "default_band": "critical",
    },
    {
        "signal_key": "precise_location",
        "display_name": "Precise location",
        "description": "ACCESS_FINE_LOCATION or equivalent high-precision signals.",
        "default_weight": 1.250,
        "default_band": "critical",
    },
    {
        "signal_key": "background_location",
        "display_name": "Background location",
        "description": "ACCESS_BACKGROUND_LOCATION or similar always-on tracking.",
        "default_weight": 1.500,
        "default_band": "critical",
    },
    {
        "signal_key": "overlay",
        "display_name": "Overlay / draw-over",
        "description": "SYSTEM_ALERT_WINDOW style overlays.",
        "default_weight": 1.100,
        "default_band": "high",
    },
    {
        "signal_key": "contacts",
        "display_name": "Contacts access",
        "description": "Contact/address book permissions.",
        "default_weight": 0.900,
        "default_band": "high",
    },
    {
        "signal_key": "calls",
        "display_name": "Call logs & phone state",
        "description": "Phone state and call log access signals.",
        "default_weight": 0.850,
        "default_band": "high",
    },
    {
        "signal_key": "sms",
        "display_name": "SMS access",
        "description": "Outbound or inbound SMS permissions.",
        "default_weight": 0.950,
        "default_band": "high",
    },
    {
        "signal_key": "storage_broad",
        "display_name": "Legacy storage",
        "description": "Legacy wide storage permissions (READ/WRITE_EXTERNAL_STORAGE).",
        "default_weight": 1.200,
        "default_band": "high",
    },
    {
        "signal_key": "bt_triad",
        "display_name": "Bluetooth stack",
        "description": "Bluetooth scan/advertise/connect access.",
        "default_weight": 0.700,
        "default_band": "medium",
    },
    {
        "signal_key": "notifications",
        "display_name": "Notifications",
        "description": "POST_NOTIFICATIONS or listener-style access.",
        "default_weight": 0.400,
        "default_band": "low",
    },
)


def _normalize_band(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text if text in _ALLOWED_BANDS else None


def _normalize_stage(value: object) -> str:
    if value is None:
        return "declared"
    text = str(value).strip().lower()
    return text if text in _ALLOWED_STAGES else "declared"


def _table_exists(table: str) -> bool:
    try:
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            (table,),
            fetch="one",
        )
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def ensure_signal_catalog() -> bool:
    """Verify the ``permission_signal_catalog`` table exists."""
    ok = _table_exists("permission_signal_catalog")
    if not ok:
        log.warning(
            "permission_signal_catalog missing; run DBA migrations.",
            category="database",
        )
    return ok


def ensure_signal_mappings() -> bool:
    """Verify the ``permission_signal_mappings`` table exists."""
    ok = _table_exists("permission_signal_mappings")
    if not ok:
        log.warning(
            "permission_signal_mappings missing; run DBA migrations.",
            category="database",
        )
    return ok


def ensure_cohort_expectations() -> bool:
    """Verify the ``permission_cohort_expectations`` table exists."""
    ok = _table_exists("permission_cohort_expectations")
    if not ok:
        log.warning(
            "permission_cohort_expectations missing; run DBA migrations.",
            category="database",
        )
    return ok


def ensure_audit_snapshots() -> bool:
    """Verify the ``permission_audit_snapshots`` table exists."""
    ok = _table_exists("permission_audit_snapshots")
    if not ok:
        log.warning(
            "permission_audit_snapshots missing; run DBA migrations.",
            category="database",
        )
    return ok


def ensure_audit_apps() -> bool:
    """Verify the ``permission_audit_apps`` table exists."""
    ok = _table_exists("permission_audit_apps")
    if not ok:
        log.warning(
            "permission_audit_apps missing; run DBA migrations.",
            category="database",
        )
    return ok


def ensure_all() -> dict[str, bool]:
    """Ensure the complete permission analytics schema is present."""

    operations: tuple[tuple[str, Callable[[], bool]], ...] = (
        ("android_permission_dict_aosp", lambda: _table_exists("android_permission_dict_aosp")),
        ("android_permission_dict_oem", lambda: _table_exists("android_permission_dict_oem")),
        ("android_permission_dict_unknown", lambda: _table_exists("android_permission_dict_unknown")),
        ("android_permission_dict_queue", lambda: _table_exists("android_permission_dict_queue")),
        ("android_permission_meta_oem_vendor", lambda: _table_exists("android_permission_meta_oem_vendor")),
        ("android_permission_meta_oem_prefix", lambda: _table_exists("android_permission_meta_oem_prefix")),
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


def seed_signal_catalog(
    entries: Iterable[Mapping[str, object]] | None = None,
) -> dict[str, int]:
    """Insert or update default signal catalog rows.

    Returns a dictionary with ``inserted`` and ``updated`` counts so callers can
    surface idempotent status messages to users.
    """

    payloads = list(entries) if entries is not None else list(DEFAULT_SIGNALS)
    if not payloads:
        return {"inserted": 0, "updated": 0}

    try:
        existing_rows = run_sql(
            """
            SELECT signal_key, display_name, description, default_weight, default_band, stage
            FROM permission_signal_catalog
            """,
            fetch="all",
            dictionary=True,
        )
    except Exception:
        existing_rows = []

    existing = {
        str(row["signal_key"]): row
        for row in existing_rows or []
        if row.get("signal_key") is not None
    }

    inserted = 0
    updated = 0

    for raw_payload in payloads:
        payload = dict(raw_payload)
        key = str(payload.get("signal_key", "")).strip()
        if not key:
            continue

        payload.setdefault("display_name", "")
        payload.setdefault("description", "")
        payload.setdefault("default_weight", 0.0)
        payload["default_band"] = _normalize_band(payload.get("default_band"))
        payload["stage"] = _normalize_stage(payload.get("stage"))

        current = existing.get(key)
        if current is None:
            try:
                run_sql(
                    """
                    INSERT INTO permission_signal_catalog
                        (signal_key, display_name, description, default_weight, default_band, stage)
                    VALUES (%(signal_key)s, %(display_name)s, %(description)s, %(default_weight)s, %(default_band)s, %(stage)s)
                    """,
                    payload,
                )
                inserted += 1
                existing[key] = {
                    "signal_key": key,
                    "display_name": payload["display_name"],
                    "description": payload["description"],
                    "default_weight": payload["default_weight"],
                    "default_band": payload["default_band"],
                    "stage": payload["stage"],
                }
            except Exception:
                continue
            continue

        display_changed = (current.get("display_name") or "") != payload["display_name"]
        description_changed = (current.get("description") or "") != payload["description"]

        try:
            current_weight = float(current.get("default_weight", 0.0))
        except (TypeError, ValueError):
            current_weight = 0.0

        try:
            desired_weight = float(payload["default_weight"])
        except (TypeError, ValueError):
            desired_weight = current_weight

        weight_changed = not isclose(current_weight, desired_weight, rel_tol=1e-9, abs_tol=1e-9)
        band_changed = (current.get("default_band") or None) != payload["default_band"]
        stage_changed = (current.get("stage") or "declared") != payload["stage"]

        if not (display_changed or description_changed or weight_changed or band_changed or stage_changed):
            continue

        try:
            run_sql(
                """
                UPDATE permission_signal_catalog
                SET display_name = %(display_name)s,
                    description = %(description)s,
                    default_weight = %(default_weight)s,
                    default_band = %(default_band)s,
                    stage = %(stage)s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE signal_key = %(signal_key)s
                """,
                payload,
            )
            updated += 1
            existing[key] = {
                "signal_key": key,
                "display_name": payload["display_name"],
                "description": payload["description"],
                "default_weight": desired_weight,
                "default_band": payload["default_band"],
                "stage": payload["stage"],
            }
        except Exception:
            continue

    return {"inserted": inserted, "updated": updated}


def seed_defaults() -> dict[str, dict[str, int]]:
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
