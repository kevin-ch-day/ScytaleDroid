"""Persistence helpers for per-run permission matrices."""

from __future__ import annotations

import json
from typing import Mapping

from scytaledroid.Database.db_func.static_analysis import static_permission_matrix as matrix_db
from scytaledroid.StaticAnalysis.modules.permissions import load_permission_catalog
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import require_canonical_schema

def _coerce_source(permission: str) -> str:
    if permission.startswith("android."):
        return "framework"
    if permission.startswith("com.google.android.gms."):
        return "play_services"
    namespace = permission.split(".", 1)[0] if "." in permission else permission
    return namespace or "custom"


def _catalog_guardStrength(permission: str) -> str | None:
    try:
        catalog = load_permission_catalog()
        descriptor = catalog.describe(permission)
        if descriptor is None:
            return None
        return descriptor.guard_strength()
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(f"Permission catalog lookup failed for {permission}: {exc}", category="static_analysis")
        return None


def persist_permission_matrix(
    *,
    static_run_id: int | None,
    package_name: str,
    apk_id: int | None,
    permission_profiles: Mapping[str, Mapping[str, object]] | None,
) -> None:
    """Persist permission profile metadata when available."""

    require_canonical_schema()
    if static_run_id is None or not matrix_db.ensure_table():
        return

    if not permission_profiles:
        matrix_db.replace_for_run(int(static_run_id), ())
        return

    rows: list[dict[str, object]] = []
    for name, profile in permission_profiles.items():
        try:
            tokens = profile.get("tokens") if isinstance(profile, Mapping) else None
            token_payload: str | None = None
            if isinstance(tokens, (list, tuple)):
                token_payload = ",".join(str(token) for token in tokens if token)
            elif isinstance(tokens, str):
                token_payload = tokens

            guard_strength = profile.get("guard_strength")
            if guard_strength is None:
                guard_strength = _catalog_guardStrength(name)

            declared_in = profile.get("declared_in") if isinstance(profile, Mapping) else None

            flag_map = {
                key: bool(profile.get(key))
                for key in (
                    "is_runtime_dangerous",
                    "is_signature",
                    "is_privileged",
                    "is_special_access",
                    "is_custom",
                    "is_flagged_normal",
                )
                if isinstance(profile, Mapping)
            }
            catalog_source = profile.get("catalog_source") if isinstance(profile, Mapping) else None
            if catalog_source:
                flag_map["catalog_source"] = catalog_source
            protection_levels = profile.get("protection_levels") if isinstance(profile, Mapping) else None
            if protection_levels:
                if isinstance(protection_levels, (list, tuple, set)):
                    flag_map["protection_levels"] = list(protection_levels)
                else:
                    flag_map["protection_levels"] = protection_levels

            flags = json.dumps(flag_map) if flag_map else None

            severity = profile.get("severity") if isinstance(profile, Mapping) else 0
            try:
                severity_val = int(severity)
            except Exception:
                severity_val = 0

            is_flagged_normal = int(bool(profile.get("is_flagged_normal"))) if isinstance(profile, Mapping) else 0

            row = {
                "run_id": int(static_run_id),
                "apk_id": apk_id,
                "package_name": package_name,
                "permission_name": name,
                "source": profile.get("source") if isinstance(profile, Mapping) else _coerce_source(name),
                "protection": profile.get("protection") if isinstance(profile, Mapping) else None,
                "guard_strength": guard_strength,
                "declared_in": declared_in,
                "tokens": token_payload,
                "severity": severity_val,
                "is_flagged_normal": is_flagged_normal,
                "flags": flags,
                "is_runtime_dangerous": int(bool(profile.get("is_runtime_dangerous"))),
                "is_signature": int(bool(profile.get("is_signature"))),
                "is_privileged": int(bool(profile.get("is_privileged"))),
                "is_special_access": int(bool(profile.get("is_special_access"))),
                "is_custom": int(bool(profile.get("is_custom"))),
            }

            rows.append(row)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug(
                f"Skipping permission matrix row for {package_name}:{name}: {exc}",
                category="static_analysis",
            )

    try:
        matrix_db.replace_for_run(int(static_run_id), rows)
    except Exception as exc:
        log.warning(
            f"Failed to persist permission matrix for {package_name}: {exc}",
            category="static_analysis",
        )


__all__ = ["persist_permission_matrix"]
