from __future__ import annotations

import os
import re
from collections.abc import Iterable

from scytaledroid.Database.db_core import permission_intel
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def permission_intel_mutation_authorized(explicit: bool | None = None) -> bool:
    """Ordinary static analysis is Permission Intel read-only unless explicitly opted in."""

    if explicit is not None:
        return bool(explicit)
    value = str(os.environ.get("SCYTALEDROID_PERMISSION_INTEL_MUTATION_AUTHORIZED") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


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

_MALFORMED_PREFIXES = ("android.premission.",)


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
    database_mutation_authorized: bool | None = None,
) -> dict:
    """Classify declared permissions; mutate Permission Intel only when authorized.

    Ordinary static analysis is Permission Intel read-only. Unknown-dictionary,
    queue, and OEM ``seen_count`` writes require ``database_mutation_authorized=True``
    or ``SCYTALEDROID_PERMISSION_INTEL_MUTATION_AUTHORIZED``. Classification counts
    and local report evidence still emit when mutation is disabled.

    ``declared`` is the legacy name for manifest permission requests.  Exact
    ``<permission>`` definitions arrive separately in ``custom_declared`` and
    must remain visible even when the defining APK does not also request them.

    - OEM/custom: non-framework permissions in requests or exact definitions.
    - Unknown: malformed/odd permissions (no namespace dot) observed in uses.
    """
    try:
        from scytaledroid.Database.db_func.permissions import permission_dicts as _pd
    except Exception as exc:  # pragma: no cover - DB not configured
        log.warning(
            f"DB modules unavailable for permission persistence: {exc}", category="static_analysis"
        )
        return {"aosp": 0, "oem": 0, "app_defined": 0, "unknown": 0}

    # Permission Intel string identities are case-insensitive. Collapse case
    # variants before writing so one manifest cannot increment the same ledger
    # row twice. Definition spelling wins over request spelling because the
    # exact <permission> element is the stronger source for an app-defined name.
    def _display_names_by_identity(values: Iterable[str]) -> dict[str, str]:
        names = sorted(
            {
                str(name).strip()
                for name in values
                if isinstance(name, str) and str(name).strip()
            },
            key=lambda value: (value.casefold(), value),
        )
        indexed: dict[str, str] = {}
        for name in names:
            indexed.setdefault(name.casefold(), name)
        return indexed

    requested_by_identity = _display_names_by_identity(declared or ())
    custom_by_identity = _display_names_by_identity(custom_declared or ())
    combined_by_identity = {**requested_by_identity, **custom_by_identity}
    declared_names: Iterable[str] = tuple(
        combined_by_identity[key] for key in sorted(combined_by_identity)
    )
    aosp_candidates = [
        str(n)
        for n in declared_names
        if isinstance(n, str) and n.lower().startswith("android.permission.")
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
    mutation_authorized = permission_intel_mutation_authorized(database_mutation_authorized)
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
                if mutation_authorized:
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
                log.warning(
                    f"Malformed permission persist failed for {name}: {exc}",
                    category="static_analysis",
                )
            counts["unknown"] += 1
            continue

        is_android = lowered_norm.startswith("android.permission.")
        aosp_hit = aosp_lower.get(lowered_norm) if is_android else None
        if aosp_hit:
            counts["aosp"] += 1
            continue

        if norm in oem_entries:
            try:
                if mutation_authorized:
                    _pd.update_oem_seen(norm)
            except Exception:
                pass
            counts["oem"] += 1
            continue

        if norm.casefold() in custom_by_identity:
            try:
                if mutation_authorized:
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
                log.warning(
                    f"App-defined permission persist failed for {name}: {exc}",
                    category="static_analysis",
                )
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

        triage_status = (
            "oem_candidate" if vendor_hint_prefix else ("aosp_missing" if is_android else "new")
        )
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
            if mutation_authorized:
                _pd.upsert_unknown(
                    {
                        "permission_string": norm,
                        "triage_status": triage_status,
                        "notes": notes,
                        "example_package_name": package_name,
                        "example_sample_id": None,
                    }
                )
        except Exception as exc:
            log.warning(
                f"Unknown permission upsert failed for {name}: {exc}",
                category="static_analysis",
                extra={
                    "event": "permission_unknown.upsert_failed",
                    "package_name": package_name,
                    "permission_name": norm,
                    "triage_status": triage_status,
                    "table": permission_intel.UNKNOWN_DICT_TABLE,
                    "error_class": exc.__class__.__name__,
                },
            )
            counts["unknown"] += 1
            continue
        if triage_status == "aosp_missing":
            try:
                if mutation_authorized:
                    _pd.insert_queue(
                        {
                            "permission_string": norm,
                            "queue_action": "defer",
                            "proposed_bucket": None,
                            "proposed_classification": None,
                            "triage_status": triage_status,
                            "notes": notes,
                            "requested_by": "static-analysis",
                            "source_system": "static-analysis",
                        }
                    )
            except Exception as exc:
                log.warning(
                    f"Permission queue insert failed for {name}: {exc}",
                    category="static_analysis",
                    extra={
                        "event": "permission_unknown.queue_failed",
                        "package_name": package_name,
                        "permission_name": norm,
                        "triage_status": triage_status,
                        "queue_action": "defer",
                        "table": permission_intel.QUEUE_DICT_TABLE,
                        "error_class": exc.__class__.__name__,
                    },
                )
        counts["unknown"] += 1
    return counts


def persist_permissions_to_db(report) -> dict:
    """Classify declared permissions from a full report.

    This ordinary static path does not authorize Permission Intel mutation.
    Unknown evidence stays in the report/provenance; dictionary/queue/OEM writes
    remain behind the explicit opt-in on ``persist_declared_permissions``.
    """
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
    counts = persist_declared_permissions(
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        target_sdk=target_sdk,
        sha256=sha,
        artifact_label=artifact_label,
        declared=declared,
        custom_declared=custom,
    )
    return counts


__all__ = ["persist_permissions_to_db", "permission_intel_mutation_authorized"]
