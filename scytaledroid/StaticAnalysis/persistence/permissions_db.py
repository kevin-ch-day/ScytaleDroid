from __future__ import annotations

from typing import Iterable, Mapping, Optional

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from pathlib import Path
import hashlib


def _ns_from_perm(perm_name: str) -> Optional[str]:
    parts = (perm_name or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return parts[0] if parts else None


def _first_seen_token(report) -> Optional[str]:
    pkg = getattr(report.manifest, "package_name", None)
    ver = getattr(report.manifest, "version_name", None) or getattr(report.manifest, "version_code", None)
    if pkg and ver:
        return f"{pkg}:{ver}"
    try:
        return report.hashes.get("sha256")
    except Exception:
        return None


def _file_sha256(path: str | Path) -> str | None:
    try:
        h = hashlib.sha256()
        with Path(path).open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def persist_declared_permissions(
    *,
    package_name: str | None,
    version_name: str | None,
    version_code: str | None,
    sha256: str | None,
    artifact_label: str | None,
    declared: Iterable[str],
    custom_declared: Iterable[str] | None = None,
) -> dict:
    """Persist vendor/unknown permissions observed in a StaticAnalysisReport.

    - Vendor/custom: non-framework permissions in declared uses.
    - Unknown: malformed/odd permissions (no namespace dot) observed in uses.
    """
    try:
        from scytaledroid.Database.db_func import (
            vendor_permissions as _vp,
            unknown_permissions as _up,
            detected_permissions as _dp,
        )
    except Exception as exc:  # pragma: no cover - DB not configured
        log.warning(f"DB modules unavailable for permission persistence: {exc}", category="static_analysis")
        return {"framework": 0, "vendor": 0, "unknown": 0}

    # Deduplicate permission names to avoid double-counting (e.g., sdk-23 tag)
    declared_names: Iterable[str] = tuple(sorted(set(declared or ())))
    custom_set: set[str] = set(custom_declared or ())
    first_seen = sha256

    # Ensure tables (best-effort)
    try:
        _vp.ensure_table()
        _up.ensure_table()
        _dp.ensure_table()
    except Exception:
        pass

    # Prefetch framework protections by short name (uppercase)
    framework_map = {}
    try:
        short_keys = [str(n).split('.')[-1].upper() for n in declared_names if isinstance(n, str) and n.startswith('android.permission.')]
        framework_map = _dp.framework_protection_map(short_keys)
    except Exception:
        framework_map = {}

    counts = {"framework": 0, "vendor": 0, "unknown": 0}
    for name in declared_names:
        if not isinstance(name, str) or not name.strip():
            continue
        # Detected permission record with classification
        is_android_prefix = name.startswith("android.permission.")
        short_key = name.split('.')[-1].upper() if is_android_prefix else None
        prot = framework_map.get(short_key) if short_key else None
        # Classify as framework only when present in the framework catalog
        in_framework_catalog = bool(short_key and short_key in framework_map)
        is_framework = bool(is_android_prefix and in_framework_catalog)
        classification = "framework" if is_framework else ("vendor" if "." in name and not is_android_prefix else "unknown")
        ns = 'android.permission' if is_android_prefix else _ns_from_perm(name)
        detected_payload = {
            "package_name": package_name,
            "artifact_label": artifact_label,
            # Store short (uppercase) for framework; vendor keeps full name
            "perm_name": short_key if is_framework else name,
            "namespace": ns,
            "classification": classification,
            "protection": prot,
            "source": "static-analysis",
        }
        # Prefer apk_id-based schema; resolve from repository by sha256
        apk_id: int | None = None
        if first_seen:
            try:
                from scytaledroid.Database.db_func.apk_repository import get_apk_by_sha256

                row = get_apk_by_sha256(first_seen)
                if row and isinstance(row, dict) and row.get("apk_id"):
                    apk_id = int(row["apk_id"])
            except Exception:
                apk_id = None
        if apk_id is not None:
            detected_payload["apk_id"] = apk_id
        else:
            # Legacy schema fallback: provide version + sha256 fields
            detected_payload.update(
                {
                    "version_name": version_name,
                    "version_code": version_code,
                    "sha256": first_seen or "",
                }
            )
        try:
            _dp.upsert_detected(detected_payload)
        except Exception as exc:
            log.warning(f"Detected permission persist failed for {name}: {exc}", category="static_analysis")
        else:
            counts[classification] = counts.get(classification, 0) + 1
        if is_framework:
            continue  # framework usage tracked via detected table only
        # Unknown: no dot namespace pattern
        if "." not in name or (is_android_prefix and not in_framework_catalog):
            try:
                _up.upsert_unknown_permission(
                    {
                        # For android.permission.* entries that aren't in catalog, persist the short token
                        "perm_name": (short_key or name),
                        "notes": None,
                    }
                )
            except Exception as exc:
                log.warning(f"Unknown permission persist failed for {name}: {exc}", category="static_analysis")
            continue

        # Vendor/custom observed (exclude android.permission namespace — treat those as unknowns above)
        namespace = _ns_from_perm(name)
        if namespace == 'android.permission':
            continue
        declaring_pkg = package_name if name in custom_set else None
        try:
            _vp.upsert_vendor_permission(
                {
                    "perm_name": name,
                    "namespace": namespace,
                    "declaring_pkg": declaring_pkg,
                    "protection": None,
                    "summary": None,
                    "doc_url": None,
                    "source": "static-analysis",
                }
            )
        except Exception as exc:
            log.warning(f"Vendor permission persist failed for {name}: {exc}", category="static_analysis")
        else:
            counts["vendor"] = counts.get("vendor", 0) + 1
    return counts


def persist_permissions_to_db(report) -> None:
    """Wrapper to persist declared permissions using a full report object."""
    try:
        package_name = getattr(report.manifest, "package_name", None)
        version_name = getattr(report.manifest, "version_name", None)
        version_code = getattr(report.manifest, "version_code", None)
    except Exception:
        package_name = version_name = version_code = None
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
        sha256=sha,
        artifact_label=artifact_label,
        declared=declared,
        custom_declared=custom,
    )


__all__ = ["persist_permissions_to_db"]
