"""Data-source helpers for Dynamic App Queue preparation."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
    extract_version_code_details_from_dump,
    read_observed_version_code_details,
)
from scytaledroid.DynamicAnalysis.plan_selection import load_plan_candidates


def resolve_live_build_drift_map(
    packages: list[str],
    *,
    device_serial: str | None,
) -> dict[str, dict[str, str]]:
    if not str(device_serial or "").strip():
        return {}
    out: dict[str, dict[str, str]] = {}
    for package_name in packages:
        pkg = str(package_name or "").strip()
        if not pkg:
            continue
        try:
            candidates, _note = load_plan_candidates(pkg)
        except Exception:
            continue
        if not candidates:
            continue
        newest = sorted(candidates, key=lambda row: row.get("generated_at") or "", reverse=True)[0]
        identity = newest.get("identity") if isinstance(newest.get("identity"), dict) else {}
        expected_vc = str(identity.get("version_code") or newest.get("version_code") or "").strip()
        if not expected_vc:
            continue
        try:
            observed = read_observed_version_code_details(
                str(device_serial).strip(),
                pkg,
                run_shell_fn=lambda serial, command: adb_shell.run_shell(serial, list(command)),
                extract_details_fn=extract_version_code_details_from_dump,
            )
        except Exception:
            continue
        observed_vc = str(observed.get("version_code") or "").strip()
        if not observed_vc or observed_vc == expected_vc:
            continue
        static_run_id = (
            str(newest.get("static_run_id") or "").strip()
            or str(identity.get("static_run_id") or "").strip()
        )
        out[pkg.lower()] = {
            "expected_version_code": expected_vc,
            "expected_version_name": str(newest.get("version_name") or "").strip(),
            "observed_version_code": observed_vc,
            "static_run_id": static_run_id,
        }
    return out


def resolve_db_dynamic_lineage_context_map(
    packages: list[str],
) -> dict[str, dict[str, int]]:
    normalized = sorted({str(package or "").strip().lower() for package in packages if str(package or "").strip()})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.DynamicAnalysis.tracker_scope import resolve_active_package_identity
    except Exception:
        return {}

    target_set = set(normalized)
    base_rows = [
        row
        for row in (lineage.fetch_base_rows(core_q, package_name=None) or [])
        if str(row.get("package_name") or "").strip().lower() in target_set
    ]
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    out: dict[str, dict[str, int]] = {}
    for row in base_rows:
        package = str(row.get("package_name") or "").strip().lower()
        sha = str(row.get("base_apk_sha256") or "").strip().lower()
        if not package or not sha:
            continue
        dynamic_sessions = int((dynamic_by_hash.get(sha) or {}).get("dynamic_sessions") or 0)
        if dynamic_sessions <= 0:
            continue
        version_code = str(row.get("version_code") or "").strip()
        active_vc, active_sha = resolve_active_package_identity(package)
        active_vc = str(active_vc or "").strip()
        active_sha = str(active_sha or "").strip().lower()
        is_active = sha == active_sha if active_sha else (version_code == active_vc if active_vc else False)
        bucket = out.setdefault(
            package,
            {
                "db_active_sessions": 0,
                "db_historical_sessions": 0,
                "db_total_sessions": 0,
            },
        )
        bucket["db_total_sessions"] += dynamic_sessions
        if is_active:
            bucket["db_active_sessions"] += dynamic_sessions
        else:
            bucket["db_historical_sessions"] += dynamic_sessions
    return out
