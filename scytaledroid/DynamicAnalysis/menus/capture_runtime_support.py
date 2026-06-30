"""Capture/runtime status helpers for Dynamic Analysis menu flows."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_core import run_sql
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis.adb import status as adb_status
from scytaledroid.DynamicAnalysis.services.observer_service import (
    select_observers as _service_select_observers,
)
from scytaledroid.Utils.DisplayUtils import status_messages


def select_observers(device_serial: str, *, mode: str) -> list[str]:
    return _service_select_observers(device_serial, mode=mode, prompt_enabled=False)


def print_device_badge(
    device_serial: str,
    device_label: str,
    *,
    device_status_cache: dict[str, dict[str, str]],
) -> None:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        root_label = "yes"
    elif root_state == "NO":
        root_label = "no"
    else:
        root_label = "unknown"

    net_label = "unknown"
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
        if "not connected" in status:
            net_label = "not_connected"
        elif "not_vpn" in status or "not vpn" in status:
            net_label = "not_vpn"
        elif "validated" in status:
            net_label = "validated"
    except Exception:
        net_label = "unknown"

    badge = f"Device: {device_label} | root: {root_label} | net: {net_label}"
    cached = device_status_cache.get(device_serial, {})
    if cached.get("badge") != badge:
        print(status_messages.status(badge, level="info"))
        cached["badge"] = badge
        device_status_cache[device_serial] = cached


def print_root_status(
    device_serial: str,
    *,
    force: bool = False,
    device_status_cache: dict[str, dict[str, str]],
) -> bool:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        message = "Device root: YES (advanced capture available)."
        level = "success"
        is_rooted = True
    elif root_state == "NO":
        message = "Device root: NO (non-root mode)."
        level = "info"
        is_rooted = False
    else:
        message = "Device root: Unknown."
        level = "warn"
        is_rooted = False
    cached = device_status_cache.get(device_serial, {})
    if force or cached.get("root") != message:
        print(status_messages.status(message, level=level))
        cached["root"] = message
        device_status_cache[device_serial] = cached
    return is_rooted


def print_network_status(
    device_serial: str,
    *,
    force: bool = False,
    device_status_cache: dict[str, dict[str, str]],
) -> None:
    details = []
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    except Exception:
        print(status_messages.status("Network status: unable to read connectivity state.", level="warn"))
        return
    if "validated" in status:
        details.append("validated")
    if "not_vpn" in status or "not vpn" in status:
        details.append("not_vpn")
    if "not connected" in status:
        print(status_messages.status("Network status: not connected.", level="warn"))
        return
    label = "Network status: " + (", ".join(details) if details else "unknown")
    cached = device_status_cache.get(device_serial, {})
    if force or cached.get("network") != label:
        print(status_messages.status(label, level="info"))
        cached["network"] = label
        device_status_cache[device_serial] = cached


def print_tier1_qa_result(dynamic_run_id: str) -> None:
    try:
        row = run_sql(
            """
            SELECT
              ds.dynamic_run_id,
              ds.status,
              ds.tier,
              ds.sampling_rate_s,
              ds.expected_samples,
              ds.captured_samples,
              ds.sample_max_gap_s,
              MAX(CASE WHEN i.issue_code = 'telemetry_partial_samples' THEN 1 ELSE 0 END) AS telemetry_partial
            FROM dynamic_sessions ds
            LEFT JOIN dynamic_session_issues i
              ON i.dynamic_run_id = ds.dynamic_run_id
            WHERE ds.dynamic_run_id = %s
            GROUP BY ds.dynamic_run_id, ds.status, ds.tier, ds.sampling_rate_s,
                     ds.expected_samples, ds.captured_samples, ds.sample_max_gap_s
            """,
            (dynamic_run_id,),
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Tier-1 QA unavailable (DB error: {exc}).", level="warn"))
        return
    if not row:
        print(status_messages.status("Tier-1 QA gate: NOT ENFORCED (dynamic).", level="info"))
        return

    failures = []
    if row.get("tier") != "dataset":
        failures.append("tier_not_dataset")
    if row.get("status") != "success":
        failures.append("status_not_success")
    ratio = _safe_ratio(row.get("captured_samples"), row.get("expected_samples"))
    if ratio is None:
        failures.append("missing_capture_ratio")
    elif ratio < 0.90:
        failures.append("low_capture_ratio")
    try:
        sampling_rate = float(row.get("sampling_rate_s"))
        max_gap = float(row.get("sample_max_gap_s"))
        if max_gap > (sampling_rate * 2):
            failures.append("max_gap_exceeded")
    except (TypeError, ValueError):
        failures.append("missing_gap_stats")
    if row.get("telemetry_partial"):
        failures.append("telemetry_partial_samples")

    blocking_failures = {"tier_not_dataset", "status_not_success"}
    if failures:
        if any(code in blocking_failures for code in failures):
            message = (
                f"Tier-1 QA: FAIL ({', '.join(failures)}) "
                "[quality gate; does not override technical dataset validity]"
            )
        else:
            message = (
                f"Tier-1 QA: advisory ({', '.join(failures)}) "
                "[quality gate attention; run can still remain technically valid]"
            )
        print(
            status_messages.status(
                message,
                level="warn",
            )
        )
    else:
        print(status_messages.status("Tier-1 QA: PASS", level="success"))


def _safe_ratio(captured: object, expected: object) -> float | None:
    try:
        cap = float(captured)
        exp = float(expected)
    except (TypeError, ValueError):
        return None
    if exp == 0:
        return None
    return cap / exp
