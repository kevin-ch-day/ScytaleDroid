"""Persistence helpers for per-run permission matrices.

Contract (matrix vs ``static_permission_risk_vnext``):
    ``static_permission_matrix.permission_name`` is **detector-facing evidence**:
    keys are ``strip()``-normalized, duplicates collapse using a **lowercase canonical
    key** for dedupe only, but the **stored string keeps the first-seen spelling**
    (e.g. ``android.permission.USE_BIOMETRIC`` if that key appeared first). This
    preserves how the manifest/detector surfaced the permission for operators and
    Web cohort rules that still match on the stored string.

    ``static_permission_risk_vnext.permission_name`` is the **canonical lowercase**
    identity used for joins and rollups. Any SQL joining matrix → vnext must align
    on ``LOWER(spm.permission_name)`` (with an explicit collation where MariaDB
    requires it) — see ``risk_actions.backfill_static_permission_risk_vnext``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

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


def _catalog_descriptor(permission: str, catalog=None):
    try:
        active = catalog if catalog is not None else load_permission_catalog()
        return active.describe(permission)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(
            f"Permission catalog lookup failed for {permission}: {exc}",
            category="static_analysis",
        )
        return None


def persist_permission_matrix(
    *,
    static_run_id: int | None,
    package_name: str,
    apk_id: int | None,
    permission_profiles: Mapping[str, Mapping[str, object]] | None,
) -> None:
    """Persist permission profile metadata when available.

    Rows are deduped by lowercase canonical permission string but ``permission_name``
    retains the first profile key spelling after ``strip()`` — not forced lowercase
    (see module docstring).
    """

    require_canonical_schema()
    if static_run_id is None:
        return
    if not matrix_db.ensure_table():
        if permission_profiles:
            log.warning(
                "static_permission_matrix table missing or unreachable; matrix rows not persisted "
                f"(package={package_name} static_run_id={static_run_id}). "
                "Permission risk / vnext may still persist — expect matrix↔vnext skew until schema is fixed.",
                category="static_analysis",
            )
        return

    if not permission_profiles:
        matrix_db.replace_for_run(int(static_run_id), ())
        return

    catalog = None
    catalog_unavailable = False

    def _descriptor(permission: str):
        nonlocal catalog, catalog_unavailable
        if catalog_unavailable:
            return None
        if catalog is None:
            try:
                catalog = load_permission_catalog()
            except Exception as exc:  # pragma: no cover - defensive
                catalog_unavailable = True
                log.debug(
                    f"Permission catalog lookup failed for {permission}: {exc}",
                    category="static_analysis",
                )
                return None
        return _catalog_descriptor(permission, catalog)

    rows: list[dict[str, object]] = []
    seen_canonical: set[str] = set()
    for name, profile in permission_profiles.items():
        try:
            raw_perm = str(name or "").strip()
            if not raw_perm:
                continue
            canon_key = raw_perm.lower()
            if canon_key in seen_canonical:
                log.debug(
                    f"Skipping duplicate static_permission_matrix row after canonicalization ({canon_key}) "
                    f"for {package_name}",
                    category="static_analysis",
                )
                continue
            seen_canonical.add(canon_key)

            tokens = profile.get("tokens") if isinstance(profile, Mapping) else None
            token_payload: str | None = None
            if isinstance(tokens, (list, tuple)):
                token_payload = ",".join(str(token) for token in tokens if token)
            elif isinstance(tokens, str):
                token_payload = tokens

            guard_strength = profile.get("guard_strength")
            catalog_source = profile.get("catalog_source") if isinstance(profile, Mapping) else None
            protection_levels = profile.get("protection_levels") if isinstance(profile, Mapping) else None
            protection = profile.get("protection") if isinstance(profile, Mapping) else None
            group = profile.get("group") if isinstance(profile, Mapping) else None
            background_permission = (
                profile.get("background_permission") if isinstance(profile, Mapping) else None
            )
            authority_class = profile.get("authority_class") if isinstance(profile, Mapping) else None
            feature_dependency = (
                profile.get("feature_dependency") if isinstance(profile, Mapping) else None
            )
            descriptor = None
            if (
                guard_strength is None
                or not catalog_source
                or not protection_levels
                or not protection
                or not group
                or not background_permission
                or not authority_class
                or not feature_dependency
            ):
                descriptor = _descriptor(raw_perm)
            if guard_strength is None and descriptor is not None:
                guard_strength = descriptor.guard_strength()
            if not catalog_source and descriptor is not None:
                catalog_source = descriptor.source
            if not protection_levels and descriptor is not None and descriptor.protection:
                protection_levels = list(descriptor.protection)
            if not protection and descriptor is not None and descriptor.protection:
                protection = "|".join(descriptor.protection)
            if not group and descriptor is not None:
                group = descriptor.permission_group
            if not background_permission and descriptor is not None:
                background_permission = descriptor.background_permission
            if not authority_class and descriptor is not None:
                authority_class = descriptor.authority_class
            if not feature_dependency and descriptor is not None:
                feature_dependency = descriptor.feature_dependency

            declared_in = profile.get("declared_in") if isinstance(profile, Mapping) else None

            extra_only: dict[str, object] = {}
            if catalog_source:
                extra_only["catalog_source"] = catalog_source
            if protection_levels:
                if isinstance(protection_levels, (list, tuple, set)):
                    extra_only["protection_levels"] = list(protection_levels)
                else:
                    extra_only["protection_levels"] = protection_levels
            if group:
                extra_only["permission_group"] = group
            if background_permission:
                extra_only["background_permission"] = background_permission
            if authority_class:
                extra_only["authority_class"] = authority_class
            if feature_dependency:
                extra_only["feature_dependency"] = feature_dependency
            flags = json.dumps(extra_only, default=str) if extra_only else None

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
                "permission_name": raw_perm,
                "source": profile.get("source") if isinstance(profile, Mapping) else _coerce_source(raw_perm),
                "protection": protection,
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
                f"Skipping permission matrix row for {package_name}:{name!r}: {exc}",
                category="static_analysis",
            )

    try:
        matrix_db.replace_for_run(int(static_run_id), rows)
    except Exception as exc:
        log.warning(
            f"Failed to persist permission matrix for {package_name}: {exc}",
            category="static_analysis",
        )
        raise


__all__ = ["persist_permission_matrix"]
