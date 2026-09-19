"""DB helpers for permission dictionary + vendor metadata tables."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

from ...db_core import permission_intel as intel_db
from .current_interpretation import fetch_current_interpretations


@dataclass(frozen=True)
class VendorHint:
    vendor_id: int
    vendor_name: str
    vendor_slug: str


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def fetch_aosp_entries(
    values: Iterable[str], *, case_insensitive: bool = False
) -> dict[str, Mapping[str, object]]:
    items = [v for v in set(values) if isinstance(v, str) and v]
    if not items:
        return {}
    decisions = fetch_current_interpretations(items)
    out: dict[str, Mapping[str, object]] = {}
    for _token, decision in decisions.items():
        if (
            not decision.platform_authority_accepted
            or decision.identifier_recognition != "EXACT_ACCEPTED_CANONICAL"
        ):
            continue
        row = decision.source_row
        constant_value = str(decision.canonical_permission or "").strip()
        if not constant_value:
            continue
        out[constant_value] = {
            "constant_value": constant_value,
            "name": row.get("legacy_name"),
            "protection_level": decision.protection_result,
            "hard_restricted": row.get("hard_restricted"),
            "soft_restricted": row.get("soft_restricted"),
            "not_for_third_party_apps": row.get("not_for_third_party_apps"),
            "is_deprecated": row.get("is_deprecated"),
            "added_in_api_level": row.get("added_in_api_level"),
            "deprecated_in_api_level": row.get("deprecated_in_api_level"),
            "authority_scope": decision.authority_scope,
            "declaration_state": decision.declaration_state,
            "feature_dependency": decision.feature_dependency,
        }
    return out


def fetch_aosp_protection_map(
    short_names: Iterable[str], target_sdk: int | None = None
) -> dict[str, str | None]:
    names = [n for n in set(short_names) if isinstance(n, str) and n]
    if not names:
        return {}
    token_by_name = {name: name if "." in name else f"android.permission.{name}" for name in names}
    decisions = fetch_current_interpretations(list(token_by_name.values()))
    out: dict[str, str | None] = {}
    for name, token in token_by_name.items():
        decision = decisions.get(token)
        if decision is None or not decision.platform_authority_accepted:
            continue
        if decision.identifier_recognition != "EXACT_ACCEPTED_CANONICAL":
            continue
        # This legacy scalar API cannot carry a feature condition, alternatives,
        # or historical availability. Withhold rather than erase those dimensions.
        if decision.declaration_state != "UNCONDITIONAL":
            out[name.upper()] = None
            continue
        row = decision.source_row
        added = row.get("added_in_api_level")
        deprecated = row.get("deprecated_in_api_level")
        if target_sdk is not None:
            try:
                added_int = int(added) if added is not None else None
            except (TypeError, ValueError):
                added_int = None
            try:
                deprecated_int = int(deprecated) if deprecated is not None else None
            except (TypeError, ValueError):
                deprecated_int = None
            if added_int is not None and target_sdk < added_int:
                continue
            if deprecated_int is not None and target_sdk >= deprecated_int:
                pass
        out[name.upper()] = decision.protection_result
    return out


def fetch_oem_entries(values: Iterable[str]) -> dict[str, Mapping[str, object]]:
    items = [v for v in set(values) if isinstance(v, str) and v]
    if not items:
        return {}
    rows = intel_db.fetch_oem_permission_dict_rows(items)
    out: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not row:
            continue
        perm = str(row[0] or "").strip()
        if not perm:
            continue
        out[perm] = {
            "permission_string": perm,
            "vendor_id": row[1],
            "display_name": row[2],
            "protection_level": row[3],
            "confidence": row[4],
            "classification_source": row[5],
        }
    return out


@lru_cache(maxsize=1)
def fetch_vendor_prefix_rules() -> tuple[Mapping[str, object], ...]:
    rows = intel_db.fetch_vendor_prefix_rule_rows()
    return tuple(
        {"vendor_id": row[0], "namespace_prefix": row[1], "match_type": row[2]}
        for row in rows
        if row
    )


@lru_cache(maxsize=1)
def fetch_vendor_meta() -> dict[int, VendorHint]:
    rows = intel_db.fetch_vendor_meta_rows()
    out: dict[int, VendorHint] = {}
    for row in rows:
        if not row or row[0] is None:
            continue
        vendor_id = int(row[0])
        out[vendor_id] = VendorHint(
            vendor_id=vendor_id,
            vendor_name=str(row[1] or ""),
            vendor_slug=str(row[2] or ""),
        )
    return out


def upsert_unknown(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    params.setdefault("first_seen_at_utc", _utc_now())
    params.setdefault("last_seen_at_utc", params["first_seen_at_utc"])
    params.setdefault("seen_count", 1)
    intel_db.upsert_unknown_permission(params)


def insert_queue(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    # A queue candidate is not accepted platform truth. Legacy aliases remain review-only.
    qa = str(params.get("queue_action") or "").strip().lower()
    if qa in {"aosp", "aosp_promote"}:
        params["queue_action"] = "defer"
    now = _utc_now()
    params.setdefault("proposed_bucket", None)
    params.setdefault("proposed_classification", None)
    params.setdefault("triage_status", "new")
    params.setdefault("notes", None)
    params.setdefault("requested_by", "scytaledroid")
    params.setdefault("source_system", "scytaledroid")
    params.setdefault("created_at_utc", now)
    params.setdefault("updated_at_utc", now)
    params.setdefault("status", "queued")
    intel_db.insert_permission_queue(params)


def update_oem_seen(permission_string: str) -> None:
    if not permission_string:
        return
    intel_db.update_oem_permission_seen(permission_string, _utc_now())


__all__ = [
    "VendorHint",
    "fetch_aosp_entries",
    "fetch_aosp_protection_map",
    "fetch_oem_entries",
    "fetch_vendor_prefix_rules",
    "fetch_vendor_meta",
    "upsert_unknown",
    "insert_queue",
    "update_oem_seen",
]
