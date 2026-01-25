from __future__ import annotations

from typing import Iterable

from scytaledroid.Utils.LoggingUtils import logging_utils as log
import re


def _normalize_permission_token(raw_value: str) -> tuple[str, str, bool]:
    raw = str(raw_value or "")
    stripped = raw.strip()
    has_internal_ws = bool(re.search(r"\s", stripped))
    return raw, stripped, has_internal_ws


def _valid_permission_token(token: str) -> bool:
    if not token:
        return False
    if re.search(r"\s", token):
        return False
    if len(token) > 255:
        return False
    lowered = token.lower()
    if lowered in {"null", "permission", "none", "undefined"}:
        return False
    return "." in token


_GHOSTAOSP_BROADCAST_PERMS = {
    "android.permission.BROADCAST_PACKAGE_ADDED",
    "android.permission.BROADCAST_PACKAGE_REPLACED",
    "android.permission.BROADCAST_PACKAGE_CHANGED",
}

_MALFORMED_PREFIXES = (
    "android.premission.",
)


def persist_declared_permissions(
    *,
    package_name: str | None,
    version_name: str | None,
    version_code: str | None,
    target_sdk: int | None = None,
    sha256: str | None,
    artifact_label: str | None,
    declared: Iterable[str],
    custom_declared: Iterable[str] | None = None,
) -> dict:
    """Persist OEM/unknown permissions observed in a StaticAnalysisReport.

    - OEM/custom: non-framework permissions in declared uses.
    - Unknown: malformed/odd permissions (no namespace dot) observed in uses.
    """
    try:
        from scytaledroid.Database.db_func.permissions import permission_dicts as _pd
    except Exception as exc:  # pragma: no cover - DB not configured
        log.warning(f"DB modules unavailable for permission persistence: {exc}", category="static_analysis")
        return {"aosp": 0, "oem": 0, "app_defined": 0, "unknown": 0}

    # Deduplicate permission names to avoid double-counting (e.g., sdk-23 tag)
    declared_names: Iterable[str] = tuple(sorted(set(declared or ())))
    custom_set: set[str] = set(custom_declared or ())
    aosp_candidates = [
        str(n) for n in declared_names if isinstance(n, str) and n.lower().startswith("android.permission.")
    ]
    try:
        aosp_entries = _pd.fetch_aosp_entries(aosp_candidates, case_insensitive=True)
    except Exception:
        aosp_entries = {}
    aosp_lower = {key.lower(): value for key, value in aosp_entries.items()}

    try:
        oem_entries = _pd.fetch_oem_entries(declared_names)
    except Exception:
        oem_entries = {}

    try:
        vendor_prefix_rules = _pd.fetch_vendor_prefix_rules()
    except Exception:
        vendor_prefix_rules = []

    counts = {"aosp": 0, "oem": 0, "app_defined": 0, "unknown": 0}
    for name in declared_names:
        if not isinstance(name, str) or not name.strip():
            continue
        raw, norm, has_internal_ws = _normalize_permission_token(name)
        lowered_norm = norm.lower()
        malformed_prefix = any(lowered_norm.startswith(prefix) for prefix in _MALFORMED_PREFIXES)
        if has_internal_ws or malformed_prefix or not _valid_permission_token(norm):
            try:
                note_parts = []
                if raw.strip() != norm:
                    note_parts.append(f"[auto] normalized from {raw.strip()} to {norm}")
                if has_internal_ws:
                    note_parts.append("[auto] rejected internal whitespace")
                if malformed_prefix:
                    note_parts.append("[auto] malformed android permission prefix")
                notes = "; ".join(note_parts) if note_parts else None
                _pd.upsert_unknown(
                    {
                        "permission_string": norm,
                        "triage_status": "malformed",
                        "notes": notes,
                        "example_package_name": package_name,
                        "example_sample_id": None,
                    }
                )
            except Exception as exc:
                log.warning(f"Malformed permission persist failed for {name}: {exc}", category="static_analysis")
            counts["unknown"] += 1
            continue

        is_android = lowered_norm.startswith("android.permission.")
        aosp_hit = aosp_lower.get(lowered_norm) if is_android else None
        if aosp_hit:
            counts["aosp"] += 1
            continue

        if norm in oem_entries:
            try:
                _pd.update_oem_seen(norm)
            except Exception:
                pass
            counts["oem"] += 1
            continue

        if norm in custom_set:
            try:
                _pd.upsert_unknown(
                    {
                        "permission_string": norm,
                        "triage_status": "app_defined",
                        "notes": None,
                        "example_package_name": package_name,
                        "example_sample_id": None,
                    }
                )
            except Exception as exc:
                log.warning(f"App-defined permission persist failed for {name}: {exc}", category="static_analysis")
            counts["app_defined"] += 1
            continue

        vendor_hint_prefix = None
        if not is_android:
            for rule in vendor_prefix_rules:
                pattern = str(rule.get("namespace_prefix") or "")
                if not pattern:
                    continue
                match_type = str(rule.get("match_type") or "prefix").lower()
                if match_type == "regex":
                    try:
                        if re.search(pattern, norm):
                            vendor_hint_prefix = pattern
                            break
                    except re.error:
                        continue
                else:
                    if norm.startswith(pattern):
                        vendor_hint_prefix = pattern
                        break

        triage_status = "oem_candidate" if vendor_hint_prefix else ("aosp_missing" if is_android else "new")
        note_parts = []
        if raw.strip() != norm:
            note_parts.append(f"[auto] normalized from {raw.strip()} to {norm}")
        if has_internal_ws:
            note_parts.append("[auto] normalized internal whitespace")
        if is_android and norm.upper() in _GHOSTAOSP_BROADCAST_PERMS:
            note_parts.append("[GhostAOSP] broadcast-only permission")
        if vendor_hint_prefix:
            note_parts.append(f"[hint] prefix match {vendor_hint_prefix}")
        notes = "; ".join(note_parts) if note_parts else None

        try:
            _pd.upsert_unknown(
                {
                    "permission_string": norm,
                    "triage_status": triage_status,
                    "notes": notes,
                    "example_package_name": package_name,
                    "example_sample_id": None,
                }
            )
            if triage_status == "aosp_missing":
                _pd.insert_queue(
                    {
                        "permission_string": norm,
                        "queue_action": "aosp_promote",
                        "triage_status": triage_status,
                        "notes": notes,
                        "requested_by": "static-analysis",
                        "source_system": "static-analysis",
                    }
                )
        except Exception as exc:
            log.warning(f"Unknown permission persist failed for {name}: {exc}", category="static_analysis")
        counts["unknown"] += 1
    return counts


def persist_permissions_to_db(report) -> None:
    """Wrapper to persist declared permissions using a full report object."""
    try:
        package_name = getattr(report.manifest, "package_name", None)
        version_name = getattr(report.manifest, "version_name", None)
        version_code = getattr(report.manifest, "version_code", None)
        target_sdk = getattr(report.manifest, "target_sdk", None)
    except Exception:
        package_name = version_name = version_code = target_sdk = None
    try:
        sha = (report.hashes or {}).get("sha256")
    except Exception:
        sha = None
    artifact_label = getattr(report, "file_name", None)
    declared = tuple(getattr(report.permissions, "declared", ()) or ())
    custom = tuple(getattr(report.permissions, "custom", ()) or ())
    persist_declared_permissions(
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        target_sdk=target_sdk,
        sha256=sha,
        artifact_label=artifact_label,
        declared=declared,
        custom_declared=custom,
    )


__all__ = ["persist_permissions_to_db"]
