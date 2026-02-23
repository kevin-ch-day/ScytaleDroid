"""Guided dataset run controller."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.core.run_specs import build_dynamic_run_spec
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    MESSAGING_PACKAGES,
    load_dataset_packages,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools
from scytaledroid.DynamicAnalysis.plan_selection import (
    ensure_plan_or_error,
    print_plan_selection_banner,
)
from scytaledroid.DynamicAnalysis.run_dynamic_analysis import execute_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.DynamicAnalysis.scenarios.manual import preview_script_template_for_package
from scytaledroid.DynamicAnalysis.templates.category_map import (
    category_for_package,
    resolved_template_for_package,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
    dataset_tracker_counts,
    delete_dynamic_evidence_packs,
    find_dynamic_run_dirs,
    recent_tracker_runs,
    reset_package_dataset_tracker,
)
from scytaledroid.StaticAnalysis.core.repository import group_artifacts
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_BATTERY_WARN_PCT = 30
_BATTERY_BLOCK_PCT = 20
_STORAGE_BLOCK_GB = 1.5
_CLOCK_WARN_S = 5
_CLOCK_BLOCK_S = 30
_STABILIZATION_WAIT_S = 15
_META_FAMILY_PACKAGES = {
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "com.whatsapp",
}


def _is_messaging_package_or_category(package_name: str) -> bool:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return False
    category = str(category_for_package(pkg_lc) or "").strip().lower()
    if category == "messaging":
        return True
    # Backstop for legacy mappings while category maps are evolving.
    return pkg_lc in {p.lower() for p in MESSAGING_PACKAGES}


def _canonical_baseline_profile_for_package(package_name: str) -> str:
    if _is_messaging_package_or_category(package_name):
        return "baseline_connected"
    return "baseline_idle"


def _is_messaging_connected_baseline(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
) -> bool:
    return (
        _is_messaging_package_or_category(package_name)
        and str(run_profile or "").strip().lower() == "baseline_connected"
        and str(messaging_activity or "").strip().lower() in {"", "connected_idle"}
    )


def _messaging_baseline_connected_insufficient_duration_streak(
    recent_runs: list[Any],
    *,
    package_name: str,
) -> int:
    if not _is_messaging_package_or_category(package_name):
        return 0
    streak = 0
    for r in recent_runs:
        prof = str(getattr(r, "run_profile", "") or "").strip().lower()
        reason = str(getattr(r, "invalid_reason_code", "") or "").strip().upper()
        if prof == "baseline_connected" and getattr(r, "valid", None) is False and reason == "INSUFFICIENT_DURATION":
            streak += 1
            continue
        break
    return streak


def _intent_counts_toward_quota(
    *,
    run_profile: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    cfg: Any,
) -> bool:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return int(baseline_valid_runs) < int(cfg.baseline_required)
    if profile.startswith("interaction_") or "interactive" in profile:
        return int(interactive_valid_runs) < int(cfg.interactive_required)
    return False


def _is_interactive_profile(profile: str) -> bool:
    p = str(profile or "").strip().lower()
    return ("interaction" in p) or ("interactive" in p) or ("script" in p)


def _apply_messaging_baseline_countability_policy(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
    counts_toward_completion: bool,
) -> tuple[bool, str | None]:
    """Messaging baseline policy: baseline is baseline_connected by default."""
    if not counts_toward_completion:
        return counts_toward_completion, None
    if not _is_messaging_package_or_category(package_name):
        return counts_toward_completion, None
    if not str(run_profile or "").strip().lower().startswith("baseline"):
        return counts_toward_completion, None
    activity = str(messaging_activity or "").strip().lower()
    if activity in {"", "none"}:
        return False, "MESSAGING_BASELINE_NONE_EXPLORATORY"
    return counts_toward_completion, None


def _print_paper_mode_constants() -> None:
    try:
        import numpy as _np

        numpy_version = str(getattr(_np, "__version__", "unknown"))
    except Exception:
        numpy_version = "unknown"
    try:
        import sklearn as _sk

        sklearn_version = str(getattr(_sk, "__version__", "unknown"))
    except Exception:
        sklearn_version = "unknown"

    menu_utils.print_section("ML Parameters (Paper #2 Locked)")
    rows = [
        ("Window size", f"{int(paper2_config.WINDOW_SIZE_S)}s"),
        ("Stride", f"{int(paper2_config.WINDOW_STRIDE_S)}s"),
        ("Min sampling time", f"{int(getattr(paper2_config, 'MIN_SAMPLING_SECONDS', 180))}s"),
        ("Recommended time", f"{int(getattr(paper2_config, 'RECOMMENDED_SAMPLING_SECONDS', 240))}s"),
        ("Percentile threshold", f"{int(paper2_config.THRESHOLD_PERCENTILE)}"),
        ("Percentile method", str(getattr(paper2_config, "NP_PERCENTILE_METHOD", "linear"))),
        ("Min PCAP bytes", f"{int(paper2_config.MIN_PCAP_BYTES)}"),
        ("Models", "Isolation Forest + OC-SVM"),
        ("Baseline-only training", "YES"),
        ("NumPy version", numpy_version),
        ("scikit-learn version", sklearn_version),
    ]
    menu_utils.print_table(["Parameter", "Value"], rows)


def _load_plan_identity(plan_path: str) -> dict[str, str]:
    payload = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    run_identity = (
        payload.get("run_identity")
        if isinstance(payload, dict) and isinstance(payload.get("run_identity"), dict)
        else {}
    )
    return {
        "package_name_lc": str(
            run_identity.get("package_name_lc") or payload.get("package_name") or ""
        ).strip().lower(),
        "version_code": str(
            run_identity.get("version_code") or payload.get("version_code") or ""
        ).strip(),
        "base_apk_sha256": str(run_identity.get("base_apk_sha256") or "").strip().lower(),
        "artifact_set_hash": str(run_identity.get("artifact_set_hash") or "").strip().lower(),
        "signer_set_hash": str(
            run_identity.get("signer_set_hash") or run_identity.get("signer_digest") or ""
        ).strip().lower(),
    }


def _read_battery_level(device_serial: str) -> int | None:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "battery"])
    m = re.search(r"level:\s*(\d+)", out)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _read_storage_free_gb(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["df", "-k", "/data"])
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    parts = lines[-1].split()
    if len(parts) < 4:
        return None
    try:
        avail_kb = int(parts[3])
        return round(avail_kb / (1024 * 1024), 2)
    except Exception:
        return None


def _read_clock_drift_seconds(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["date", "+%s"]).strip()
    try:
        device_epoch = int(out)
    except Exception:
        return None
    host_epoch = int(datetime.now(UTC).timestamp())
    return float(abs(host_epoch - device_epoch))


def _read_vpn_state(device_serial: str) -> str:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    if "not_vpn" in out or "not vpn" in out:
        return "not_vpn"
    if "vpn" in out:
        return "vpn"
    return "unknown"


def _extract_route_interface(route_output: str) -> str | None:
    for line in route_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Common forms:
        # - default via 192.168.1.1 dev wlan0
        # - 10.0.0.0/8 dev rmnet_data0 scope link
        if " dev " not in line:
            continue
        m = re.search(r"\bdev\s+(\S+)", line)
        if not m:
            continue
        iface = m.group(1).strip()
        if iface and iface not in {"lo"}:
            return iface
    return None


def _read_capture_interface(device_serial: str) -> str | None:
    # 1) Route-based detection (preferred).
    for cmd in (
        ["ip", "route"],
        ["ip", "-o", "route", "show"],
        ["ip", "route", "show", "table", "all"],
        ["/system/bin/ip", "route"],
    ):
        try:
            out = adb_shell.run_shell(device_serial, cmd)
        except Exception:
            out = ""
        iface = _extract_route_interface(out or "")
        if iface:
            return iface

    # 2) Connectivity service fallback.
    try:
        conn = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"])
    except Exception:
        conn = ""
    for pattern in (
        r"\binterfaceName[:=]\s*([a-zA-Z0-9_.:-]+)",
        r"\bIface[:=]\s*([a-zA-Z0-9_.:-]+)",
    ):
        m = re.search(pattern, conn or "", flags=re.IGNORECASE)
        if m:
            iface = m.group(1).strip()
            if iface and iface != "lo":
                return iface

    # 3) Property fallback for OEM/network stacks.
    for prop in ("wifi.interface", "vendor.wifi.interface", "persist.vendor.wifi.interface"):
        try:
            val = adb_shell.run_shell(device_serial, ["getprop", prop]).strip()
        except Exception:
            val = ""
        if val and val != "[]":
            return val
    return None


def _read_observed_version_code(device_serial: str, package_name: str) -> str | None:
    details = _read_observed_version_code_details(device_serial, package_name)
    return details.get("version_code")


def _read_observed_version_code_details(device_serial: str, package_name: str) -> dict[str, str]:
    cmd_primary = ["dumpsys", "package", "--user", "0", package_name]
    out = adb_shell.run_shell(device_serial, cmd_primary)
    if out and "Unknown option" not in out and "Bad argument" not in out:
        dump = out
        command_used = " ".join(cmd_primary)
    else:
        cmd_fallback = ["dumpsys", "package", package_name]
        dump = adb_shell.run_shell(device_serial, cmd_fallback)
        command_used = " ".join(cmd_fallback)
    parsed = _extract_version_code_details_from_dump(dump, package_name)
    return {
        "version_code": parsed.get("version_code", ""),
        "command": command_used,
        "pattern": parsed.get("pattern", ""),
        "matched_line": parsed.get("matched_line", ""),
    }


def _extract_version_code_from_dump(dump: str, package_name: str) -> str | None:
    details = _extract_version_code_details_from_dump(dump, package_name)
    value = details.get("version_code")
    return value or None


def _extract_version_code_details_from_dump(dump: str, package_name: str) -> dict[str, str]:
    text = str(dump or "")
    if not text:
        return {}
    pkg = str(package_name or "").strip()

    # Prefer parsing from the package's own block to avoid accidental matches.
    scoped = text
    if pkg:
        marker = f"Package [{pkg}]"
        start = text.find(marker)
        if start >= 0:
            next_match = re.search(r"(?m)^\s*Package \[", text[start + len(marker) :])
            if next_match:
                end = start + len(marker) + next_match.start()
                scoped = text[start:end]
            else:
                scoped = text[start:]

    patterns = (
        # Canonical line form in dumpsys package output for the selected package.
        ("versionCode+minSdk", r"(?m)^\s*(versionCode=(\d+)\s+minSdk=.*)$"),
        # Fallback to a versionCode line start (avoids versionCodeMajor noise).
        ("versionCode-line", r"(?m)^\s*(versionCode=(\d+)\b.*)$"),
        # Last-resort broad match.
        ("versionCode-any", r"(versionCode=(\d+)\b)"),
    )
    for source_name, source in (("scoped", scoped), ("full", text)):
        for pattern_name, pat in patterns:
            m = re.search(pat, source)
            if m:
                value = m.group(2).strip() if len(m.groups()) >= 2 else ""
                matched_line = ""
                try:
                    matched_line = m.group(1).strip()
                except Exception:
                    matched_line = ""
                return {
                    "version_code": value,
                    "pattern": f"{source_name}:{pattern_name}",
                    "matched_line": matched_line,
                }
    return {}


def _read_observed_signer_set_hash(device_serial: str, package_name: str) -> str | None:
    out = adb_shell.run_shell(
        device_serial,
        ["dumpsys", "package", "--user", "0", package_name],
    )
    if out and "Unknown option" not in out and "Bad argument" not in out:
        dump = out
    else:
        dump = adb_shell.run_shell(device_serial, ["dumpsys", "package", package_name])
    digests: list[str] = []
    for line in dump.splitlines():
        low = line.lower()
        if ("sha-256" not in low) and ("sha256" not in low) and ("sign" not in low):
            continue
        for match in re.finditer(r"([0-9A-Fa-f:]{64,95})", line):
            raw = match.group(1).replace(":", "").strip().lower()
            if len(raw) == 64 and all(ch in "0123456789abcdef" for ch in raw):
                digests.append(raw)
    unique = sorted(set(digests))
    if not unique:
        return None
    return hashlib.sha256("|".join(unique).encode("utf-8")).hexdigest()


def _pre_run_scientific_checks(
    *,
    device_serial: str,
    package_name: str,
    plan_path: str,
    observer_ids: list[str],
) -> bool:
    hard_failures: list[str] = []
    warnings: list[str] = []
    rows: list[list[str]] = []

    missing = missing_required_tools(tier="dataset")
    if missing:
        hard_failures.append(f"Missing host tools: {', '.join(missing)}")
        rows.append(["Host tools", "FAIL", ", ".join(missing)])
    else:
        rows.append(["Host tools", "OK", "tshark + capinfos"])

    try:
        with tempfile.NamedTemporaryFile(
            prefix="scytaledroid-preflight-",
            dir=app_config.DATA_DIR,
            delete=True,
        ):
            pass
        rows.append(["PCAP tool test write", "OK", app_config.DATA_DIR])
    except Exception as exc:
        hard_failures.append("PCAP tool test write failed")
        rows.append(["PCAP tool test write", "FAIL", str(exc)])

    capture_iface = _read_capture_interface(device_serial)
    if not capture_iface:
        hard_failures.append("Capture interface unavailable")
        rows.append(["Capture interface", "FAIL", "no default route device"])
    else:
        rows.append(["Capture interface", "OK", capture_iface])

    vpn_state = _read_vpn_state(device_serial)
    if vpn_state != "not_vpn":
        hard_failures.append(f"VPN state mismatch: expected not_vpn, got {vpn_state}")
        rows.append(["VPN state", "FAIL", vpn_state])
    else:
        rows.append(["VPN state", "OK", vpn_state])

    battery = _read_battery_level(device_serial)
    if battery is None:
        warnings.append("Battery level unavailable")
        rows.append(["Battery", "WARN", "unavailable"])
    elif battery < _BATTERY_BLOCK_PCT:
        hard_failures.append(f"Battery too low ({battery}%)")
        rows.append(["Battery", "FAIL", f"{battery}% (<{_BATTERY_BLOCK_PCT}%)"])
    elif battery < _BATTERY_WARN_PCT:
        warnings.append(f"Battery below recommended threshold ({battery}%)")
        rows.append(["Battery", "WARN", f"{battery}% (<{_BATTERY_WARN_PCT}%)"])
    else:
        rows.append(["Battery", "OK", f"{battery}%"])

    storage_gb = _read_storage_free_gb(device_serial)
    if storage_gb is None:
        hard_failures.append("Storage check unavailable")
        rows.append(["Free storage", "FAIL", "unable to read /data free space"])
    elif storage_gb < _STORAGE_BLOCK_GB:
        hard_failures.append(f"Insufficient free storage ({storage_gb:.2f} GB)")
        rows.append(
            ["Free storage", "FAIL", f"{storage_gb:.2f} GB (<{_STORAGE_BLOCK_GB:.1f} GB)"]
        )
    else:
        rows.append(["Free storage", "OK", f"{storage_gb:.2f} GB"])

    clock_drift = _read_clock_drift_seconds(device_serial)
    if clock_drift is None:
        warnings.append("Clock drift unavailable")
        rows.append(["Clock drift", "WARN", "unavailable"])
    elif clock_drift > _CLOCK_BLOCK_S:
        hard_failures.append(f"Clock drift too high ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "FAIL", f"{clock_drift:.1f}s (>{_CLOCK_BLOCK_S}s)"])
    elif clock_drift > _CLOCK_WARN_S:
        warnings.append(f"Clock drift above recommended threshold ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "WARN", f"{clock_drift:.1f}s (>{_CLOCK_WARN_S}s)"])
    else:
        rows.append(["Clock drift", "OK", f"{clock_drift:.1f}s"])

    plan_identity = _load_plan_identity(plan_path)
    observed_details = _read_observed_version_code_details(device_serial, package_name)
    observed_vc = (observed_details.get("version_code") or "").strip()
    expected_vc = plan_identity.get("version_code") or ""
    if not expected_vc:
        hard_failures.append("Plan missing version_code")
        rows.append(["Build identity", "FAIL", "plan missing version_code"])
    elif not observed_vc:
        hard_failures.append("Observed identity parse failed (version_code unavailable)")
        rows.append(["Build identity", "FAIL", "observed version_code unavailable"])
        rows.append(["Identity source", "INFO", observed_details.get("command") or "unknown"])
        rows.append(["Identity parser", "INFO", observed_details.get("pattern") or "no-match"])
        rows.append(["Identity line", "INFO", observed_details.get("matched_line") or "no-match"])
    elif observed_vc != expected_vc:
        hard_failures.append(
            f"Build identity drift: version_code {observed_vc or 'unknown'} != {expected_vc}"
        )
        rows.append(
            ["Build identity", "FAIL", f"observed={observed_vc or 'unknown'} expected={expected_vc}"]
        )
        rows.append(["Identity source", "INFO", observed_details.get("command") or "unknown"])
        rows.append(["Identity parser", "INFO", observed_details.get("pattern") or "no-match"])
        rows.append(["Identity line", "INFO", observed_details.get("matched_line") or "no-match"])
    else:
        rows.append(["Build identity", "OK", f"version_code={expected_vc}"])

    expected_signer = str(plan_identity.get("signer_set_hash") or "").strip().lower()
    observed_signer = _read_observed_signer_set_hash(device_serial, package_name) or ""
    if expected_signer:
        if not observed_signer:
            hard_failures.append("Signer identity missing on device")
            rows.append(["Signer identity", "FAIL", "unable to derive signer_set_hash"])
        elif observed_signer != expected_signer:
            hard_failures.append("Signer identity drift detected")
            rows.append(
                [
                    "Signer identity",
                    "FAIL",
                    f"observed={observed_signer[:12]} expected={expected_signer[:12]}",
                ]
            )
        else:
            rows.append(["Signer identity", "OK", expected_signer[:12]])

    if "pcapdroid_capture" not in observer_ids:
        hard_failures.append("Required observer missing: pcapdroid_capture")
        rows.append(["Capture observer", "FAIL", "pcapdroid_capture required"])
    else:
        rows.append(["Capture observer", "OK", "pcapdroid_capture"])

    print()
    menu_utils.print_header("Dynamic Environment Validation")
    menu_utils.print_table(["Check", "Status", "Details"], rows)
    for msg in warnings:
        print(status_messages.status(msg, level="warn"))
    if hard_failures:
        for msg in hard_failures:
            print(status_messages.status(msg, level="error"))
        print(
            status_messages.status(
                "Pre-run scientific checks failed. Run blocked in paper mode.",
                level="error",
            )
        )
        return False
    print(status_messages.status("Status: READY", level="success"))
    return True


def _device_preflight_checks(device_serial: str) -> bool:
    hard_failures: list[str] = []
    warnings: list[str] = []
    rows: list[list[str]] = []

    missing = missing_required_tools(tier="dataset")
    if missing:
        hard_failures.append(f"Missing host tools: {', '.join(missing)}")
        rows.append(["Host tools", "FAIL", ", ".join(missing)])
    else:
        rows.append(["Host tools", "OK", "tshark + capinfos"])

    try:
        with tempfile.NamedTemporaryFile(
            prefix="scytaledroid-preflight-",
            dir=app_config.DATA_DIR,
            delete=True,
        ):
            pass
        rows.append(["PCAP tool test write", "OK", app_config.DATA_DIR])
    except Exception as exc:
        hard_failures.append("PCAP tool test write failed")
        rows.append(["PCAP tool test write", "FAIL", str(exc)])

    capture_iface = _read_capture_interface(device_serial)
    if not capture_iface:
        hard_failures.append("Capture interface unavailable")
        rows.append(["Capture interface", "FAIL", "no default route device"])
    else:
        rows.append(["Capture interface", "OK", capture_iface])

    vpn_state = _read_vpn_state(device_serial)
    if vpn_state != "not_vpn":
        hard_failures.append(f"VPN state mismatch: expected not_vpn, got {vpn_state}")
        rows.append(["VPN state", "FAIL", vpn_state])
    else:
        rows.append(["VPN state", "OK", vpn_state])

    battery = _read_battery_level(device_serial)
    if battery is None:
        warnings.append("Battery level unavailable")
        rows.append(["Battery", "WARN", "unavailable"])
    elif battery < _BATTERY_BLOCK_PCT:
        hard_failures.append(f"Battery too low ({battery}%)")
        rows.append(["Battery", "FAIL", f"{battery}% (<{_BATTERY_BLOCK_PCT}%)"])
    elif battery < _BATTERY_WARN_PCT:
        warnings.append(f"Battery below recommended threshold ({battery}%)")
        rows.append(["Battery", "WARN", f"{battery}% (<{_BATTERY_WARN_PCT}%)"])
    else:
        rows.append(["Battery", "OK", f"{battery}%"])

    storage_gb = _read_storage_free_gb(device_serial)
    if storage_gb is None:
        hard_failures.append("Storage check unavailable")
        rows.append(["Free storage", "FAIL", "unable to read /data free space"])
    elif storage_gb < _STORAGE_BLOCK_GB:
        hard_failures.append(f"Insufficient free storage ({storage_gb:.2f} GB)")
        rows.append(
            ["Free storage", "FAIL", f"{storage_gb:.2f} GB (<{_STORAGE_BLOCK_GB:.1f} GB)"]
        )
    else:
        rows.append(["Free storage", "OK", f"{storage_gb:.2f} GB"])

    clock_drift = _read_clock_drift_seconds(device_serial)
    if clock_drift is None:
        warnings.append("Clock drift unavailable")
        rows.append(["Clock drift", "WARN", "unavailable"])
    elif clock_drift > _CLOCK_BLOCK_S:
        hard_failures.append(f"Clock drift too high ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "FAIL", f"{clock_drift:.1f}s (>{_CLOCK_BLOCK_S}s)"])
    elif clock_drift > _CLOCK_WARN_S:
        warnings.append(f"Clock drift above recommended threshold ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "WARN", f"{clock_drift:.1f}s (>{_CLOCK_WARN_S}s)"])
    else:
        rows.append(["Clock drift", "OK", f"{clock_drift:.1f}s"])

    print()
    menu_utils.print_header("Dynamic Environment Validation")
    menu_utils.print_table(["Check", "Status", "Details"], rows)
    for msg in warnings:
        print(status_messages.status(msg, level="warn"))
    if hard_failures:
        for msg in hard_failures:
            print(status_messages.status(msg, level="error"))
        print(
            status_messages.status(
                "Environment checks failed. Resolve issues before selecting an app.",
                level="error",
            )
        )
        return False
    print(status_messages.status("Status: READY", level="success"))
    return True


def _post_run_integrity_check(result) -> None:
    if not result.dynamic_run_id or not result.evidence_path:
        return
    run_dir = Path(result.evidence_path)
    manifest_path = run_dir / "run_manifest.json"
    report_path = run_dir / "analysis" / "pcap_report.json"
    features_path = run_dir / "analysis" / "pcap_features.json"
    summary_path = run_dir / "analysis" / "summary.json"

    dataset_valid = None
    invalid_reason = None
    pcap_size = None
    capinfos_ok = False
    tshark_ok = False
    features_ok = False
    window_count = None
    report: dict[str, object] = {}
    dataset: dict[str, object] = {}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        dataset = (
            manifest.get("dataset")
            if isinstance(manifest, dict) and isinstance(manifest.get("dataset"), dict)
            else {}
        )
        dataset_valid = dataset.get("valid_dataset_run")
        invalid_reason = dataset.get("invalid_reason_code")
        pcap_size = dataset.get("pcap_size_bytes")
        try:
            window_count = int(dataset.get("window_count")) if dataset.get("window_count") not in (None, "") else None
        except Exception:
            window_count = None
    except Exception:
        pass

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        parsed = (
            (report.get("capinfos") or {}).get("parsed")
            if isinstance(report.get("capinfos"), dict)
            else {}
        )
        capinfos_ok = isinstance(parsed, dict) and parsed.get("packet_count") is not None
        tshark_ok = str(report.get("report_status") or "").lower() == "ok"
        if pcap_size is None:
            pcap_size = report.get("pcap_size_bytes")
    except Exception:
        pass

    # Fallback for degraded runs where report may be skipped but summary capture
    # still records observed PCAP size.
    if pcap_size is None:
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            capture = summary.get("capture") if isinstance(summary, dict) else {}
            if isinstance(capture, dict):
                pcap_size = capture.get("pcap_size_bytes")
        except Exception:
            pass

    try:
        features = json.loads(features_path.read_text(encoding="utf-8"))
        features_ok = (
            isinstance(features, dict)
            and isinstance(features.get("metrics"), dict)
            and isinstance(features.get("proxies"), dict)
        )
        ts = features.get("timeseries")
        if isinstance(ts, dict):
            wb = ts.get("windowing")
            if isinstance(wb, dict):
                try:
                    window_count = int(wb.get("window_count")) if wb.get("window_count") not in (None, "") else window_count
                except Exception:
                    pass
    except Exception:
        pass

    try:
        pcap_size_int = int(pcap_size or 0)
    except Exception:
        pcap_size_int = 0
    pcap_size_ok = pcap_size_int >= int(paper2_config.MIN_PCAP_BYTES)
    min_windows = int(getattr(paper2_config, "MIN_WINDOWS_PER_RUN", 20))
    window_count_ok = window_count is not None and int(window_count) >= int(min_windows)
    verdict = (
        "VALID"
        if (dataset_valid is True and pcap_size_ok and capinfos_ok and tshark_ok and features_ok and window_count_ok)
        else "INVALID"
    )
    rows = [
        [
            "PCAP size",
            "OK" if pcap_size_ok else "FAIL",
            f"{pcap_size_int} bytes (min {int(paper2_config.MIN_PCAP_BYTES)})",
        ],
        [
            "capinfos parse",
            "OK" if capinfos_ok else "FAIL",
            ("parsed packet metadata" if capinfos_ok else "packet metadata unavailable"),
        ],
        [
            "tshark parse",
            "OK" if tshark_ok else "FAIL",
            f"report_status={report.get('report_status') if isinstance(report, dict) else 'missing'}",
        ],
        ["Feature extraction", "OK" if features_ok else "FAIL", "analysis/pcap_features.json"],
        [
            "Window count",
            "OK" if window_count_ok else "FAIL",
            (
                f"{window_count} (min {min_windows})"
                if window_count is not None
                else f"unavailable (min {min_windows})"
            ),
        ],
        ["Run verdict", "OK" if verdict == "VALID" else "FAIL", verdict],
    ]
    print()
    menu_utils.print_header("Post-Run Integrity")
    menu_utils.print_table(["Check", "Status", "Details"], rows)
    if verdict != "VALID":
        print(
            status_messages.status(
                f"Dataset validity: INVALID ({invalid_reason or 'PCAP_PARSE_ERROR'})",
                level="error",
            )
        )
    else:
        print(status_messages.status("Dataset validity: VALID", level="success"))


def _auto_run_static_for_package(package_name: str) -> bool:
    """Dataset-mode helper: run static analysis quietly to produce a dynamic plan.

    This is non-interactive and intended only to unblock dataset collection.
    """

    from scytaledroid.Config import app_config
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp

    groups = group_artifacts()
    group = next((g for g in groups if (g.package_name or "").lower() == package_name.lower()), None)
    if not group:
        print(status_messages.status("No APK artifacts found locally for this package.", level="error"))
        return False

    session_stamp = normalize_session_stamp(f"{make_session_stamp()}-{group.package_name}")
    selection = ScopeSelection(scope="app", label=group.package_name, groups=(group,))
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        session_stamp=session_stamp,
        show_split_summaries=False,
        # Noninteractive run: never prompt on collisions.
        canonical_action="append",
    )
    base_dir = Path(app_config.DATA_DIR) / "device_apks"

    buffer_out = io.StringIO()
    buffer_err = io.StringIO()
    with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
        spec = build_static_run_spec(
            selection=selection,
            params=params,
            base_dir=base_dir,
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        execute_run_spec(spec)
    return True


def run_guided_dataset_run(
    *,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
) -> None:
    print()
    menu_utils.print_header("Guided Dataset Run")
    _print_paper_mode_constants()
    selected = select_device()
    if not selected:
        return
    device_serial, device_label = selected
    print_device_badge(device_serial, device_label)
    if not _device_preflight_checks(device_serial):
        prompt_utils.press_enter_to_continue()
        return

    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Dataset (guided)"

    groups = group_artifacts()
    dataset_pkgs = {pkg.lower() for pkg in load_dataset_packages()}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        return

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group
        for group in groups
        if group.package_name
        and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                "No APK artifacts available for Research Dataset Alpha. Pull APKs or use Custom package name.",
                level="warn",
            )
        )
        return

    package_name = select_package_from_groups(scoped_groups, title="Research Dataset Alpha apps")
    if not package_name:
        return
    pkg_lc = str(package_name or "").strip().lower()
    print(
        status_messages.status(
            f"Selected package key: {package_name} (quota/accounting is package-specific).",
            level="info",
        )
    )
    if pkg_lc in _META_FAMILY_PACKAGES:
        print(
            status_messages.status(
                "Meta-family app detected. Note: Facebook, Messenger, Instagram, and WhatsApp are tracked as separate apps.",
                level="info",
            )
        )

    # Per-app run menu: operators can run in any order and as many times as needed.
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import peek_next_run_protocol

    next_protocol = peek_next_run_protocol(package_name, tier="dataset") or {}
    suggested_profile = (next_protocol.get("run_profile") or "interaction_scripted").strip()
    if str(suggested_profile).strip().lower() == "baseline_idle":
        suggested_profile = _canonical_baseline_profile_for_package(package_name)
    suggested_slot = next_protocol.get("run_sequence")
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    cfg = DatasetTrackerConfig()
    total_required = int(cfg.baseline_required) + int(cfg.interactive_required)
    counts = dataset_tracker_counts(package_name)
    fs_runs = find_dynamic_run_dirs(package_name)
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

        tracker_payload = load_dataset_tracker()
        tracker_apps = tracker_payload.get("apps") if isinstance(tracker_payload, dict) else {}
        tracker_entry = tracker_apps.get(package_name) if isinstance(tracker_apps, dict) else {}
        tracker_rows = tracker_entry.get("runs") if isinstance(tracker_entry, dict) else []
    except Exception:
        tracker_rows = []
    paper_eligible_local = 0
    quota_counted_local = 0
    exclusion_reason_local: dict[str, int] = {}
    if isinstance(tracker_rows, list):
        for row in tracker_rows:
            if not isinstance(row, dict):
                continue
            if row.get("valid_dataset_run") is not True:
                continue
            if row.get("paper_eligible") is True:
                paper_eligible_local += 1
            if row.get("counts_toward_quota") is True:
                quota_counted_local += 1
            if row.get("paper_eligible") is False:
                reason = str(row.get("paper_exclusion_primary_reason_code") or "EXCLUDED_UNKNOWN").strip()
                exclusion_reason_local[reason] = int(exclusion_reason_local.get(reason, 0)) + 1

    print()
    print("Runs recorded:")
    print(
        f"  tracker={counts.total_runs}\ttracker_countable={counts.valid_runs}/{total_required}\n"
        f"  paper_eligible(local)={paper_eligible_local}\tquota_counted(local)={quota_counted_local}/{total_required}\n"
        f"  baseline={counts.baseline_valid_runs}/{cfg.baseline_required}\t"
        f"interactive={counts.interactive_valid_runs}/{cfg.interactive_required}\n"
        f"  quota_met={int(counts.quota_met)}\tlocal_evidence={len(fs_runs)}"
    )
    if exclusion_reason_local:
        top_reasons = sorted(exclusion_reason_local.items(), key=lambda kv: (-int(kv[1]), kv[0]))[:3]
        reason_line = ", ".join([f"{k}={v}" for k, v in top_reasons])
        print(f"  local_exclusion_top: {reason_line}")
    if counts.quota_met:
        # Once quota is met, runs are still allowed, but they're "extra" and don't change completion.
        print("Quota met. Additional runs are allowed and will be tracked as extra (do not change completion).")
        suggested_slot = None
    elif suggested_slot:
        # Do not imply an ordering constraint. Operators may run in any order;
        # the tracker deterministically counts the first N valid baseline/interactive runs.
        print(f"Suggested by quota (counts toward completion): {suggested_profile}")

    print(f"Paper cohort quota: baseline={cfg.baseline_required}, interaction={cfg.interactive_required}.")
    baseline_recommended = max(
        int(cfg.baseline_required),
        int(getattr(app_config, "DYNAMIC_DATASET_BASELINE_RECOMMENDED_RUNS", 3)),
    )
    if baseline_recommended > int(cfg.baseline_required):
        print(
            "Baseline replicates recommended: "
            f"{baseline_recommended} (extras are retained for exploratory/baseline stability analysis)."
        )
    suggested_counts = _intent_counts_toward_quota(
        run_profile=suggested_profile,
        baseline_valid_runs=int(counts.baseline_valid_runs),
        interactive_valid_runs=int(counts.interactive_valid_runs),
        cfg=cfg,
    )
    if counts.quota_met:
        print("This run will be EXTRA (not countable) by default.")
    else:
        print(
            "Default suggestion countability: "
            + ("COUNTABLE" if suggested_counts else "EXTRA (not countable)")
            + f" ({suggested_profile})."
        )
    print()

    suggested_is_interactive = _is_interactive_profile(suggested_profile)

    def _badge_for(key: str) -> str | None:
        if not suggested_slot:
            return None
        return "suggested" if key == ("2" if suggested_is_interactive else "1") else None

    can_reset = len(fs_runs) > 0
    protocol_options = [
        menu_utils.MenuOption(
            "1",
            "Baseline",
            description=(
                "Purpose: baseline-only training. run_profile="
                + _canonical_baseline_profile_for_package(package_name)
                + " | "
                + (
                    "Counts toward quota: YES (if VALID)"
                    if int(counts.baseline_valid_runs) < int(cfg.baseline_required)
                    else "Counts toward quota: NO (baseline quota met; saved as EXTRA)"
                )
            ),
            badge=_badge_for("1"),
        ),
        menu_utils.MenuOption(
            "2",
            "Scripted Interaction",
            description=(
                "Purpose: repeatable stimulus. run_profile=interaction_scripted | "
                + (
                    "Counts toward quota: YES (if VALID)"
                    if int(counts.interactive_valid_runs) < int(cfg.interactive_required)
                    else "Counts toward quota: NO (interactive quota met; saved as EXTRA)"
                )
            ),
            badge=_badge_for("2"),
        ),
        menu_utils.MenuOption(
            "3",
            "Manual Interaction",
            description=(
                "Purpose: operator-driven stimulus. run_profile=interaction_manual | "
                + (
                    "Counts toward quota: YES (if VALID)"
                    if int(counts.interactive_valid_runs) < int(cfg.interactive_required)
                    else "Counts toward quota: NO (interactive quota met; saved as EXTRA)"
                )
            ),
            badge=None,
        ),
        menu_utils.MenuOption("4", "Test app (Dry Run/No Saving)", description="no capture; checks plan + tools", badge=None),
        menu_utils.MenuOption(
            "D",
            "Reset app (dangerous)",
            description=(
                "delete local evidence packs + reset tracker for this app"
                if can_reset
                else "disabled: no local evidence packs in this workspace"
            ),
            badge=None,
            disabled=(not can_reset),
        ),
    ]

    menu_utils.print_header("Select Run Intent")
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=protocol_options,
            default="2" if suggested_is_interactive else "1",
            exit_label="Exit",
            show_exit=True,
            show_descriptions=True,
            compact=True,
        )
    )
    selected_protocol = prompt_utils.get_choice(
        menu_utils.selectable_keys(protocol_options, include_exit=True),
        default="2" if suggested_is_interactive else "1",
        casefold=True,
        invalid_message="Choose 0-4 or D.",
        disabled=[option.key for option in protocol_options if option.disabled],
    )
    selected_protocol = selected_protocol.upper()
    if selected_protocol == "0":
        return
    if selected_protocol == "D":
        local = find_dynamic_run_dirs(package_name)
        print(
            status_messages.status(
                f"Local dynamic runs for {package_name}: {len(local)} evidence pack(s).",
                level="warn",
            )
        )
        if not local:
            print(
                status_messages.status(
                    "Delete is blocked: local evidence packs are missing in this workspace. Resetting tracker-only state is unsafe in paper mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return
        confirmed = prompt_utils.prompt_yes_no(
            f"Delete local evidence packs AND reset dataset tracker entry for {package_name}?",
            default=False,
        )
        if not confirmed:
            return
        deleted = delete_dynamic_evidence_packs(package_name)
        reset_package_dataset_tracker(package_name)
        remaining = len(find_dynamic_run_dirs(package_name))
        print(
            status_messages.status(
                f"Deleted {deleted} evidence pack(s). Remaining={remaining}. Tracker entry reset.",
                level="info",
            )
        )
        prompt_utils.press_enter_to_continue()
        return
    if selected_protocol == "4":
        # Preflight-only test: do not capture or write evidence packs.
        missing = missing_required_tools(tier="dataset")
        tools = collect_host_tools()
        if missing:
            print(
                status_messages.status(
                    f"Preflight FAIL: missing host tools: {', '.join(missing)}",
                    level="error",
                )
            )
        else:
            print(status_messages.status("Preflight OK: host tools present.", level="success"))
        print(status_messages.status(f"Host tools: {tools}", level="info"))
        # Also ensure a plan exists (offer to run static once, as normal).
        plan_selection = ensure_plan_or_error(
            package_name,
            prompt_run_static=True,
            deterministic=True,
            run_static_callback=_auto_run_static_for_package,
        )
        if plan_selection:
            print(status_messages.status(f"Plan OK: {plan_selection['plan_path']}", level="success"))
        mapped = resolved_template_for_package(package_name)
        if mapped:
            try:
                template_id, steps = preview_script_template_for_package(package_name=package_name)
                print()
                menu_utils.print_section("Dry Run Script Preview")
                print(status_messages.status(f"Template: {template_id}", level="info"))
                rows = [[str(i), sid, str(sexp)] for i, (sid, _sdesc, sexp) in enumerate(steps, start=1)]
                menu_utils.print_table(["#", "Step ID", "Expected (s)"], rows)
                print(status_messages.status("Dry run validates plan/tools only; no capture or saving is performed.", level="info"))
            except Exception as exc:
                print(status_messages.status(f"Template preview unavailable: {exc}", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    # Show recent history before starting capture so operator can sanity-check state.
    recent = recent_tracker_runs(package_name, limit=5)
    baseline_connected_insufficient_streak = 0
    if recent:
        rows = []
        for r in recent:
            if r.valid is True:
                status = "VALID"
                if str(r.run_profile or "").strip().lower() == "baseline_idle" and r.low_signal is True:
                    status += " (LOW_SIGNAL_IDLE)"
            elif r.valid is False:
                status = f"INVALID:{r.invalid_reason_code or 'UNKNOWN'}"
                if (
                    str(r.run_profile or "").strip().lower() == "baseline_idle"
                    and str(r.invalid_reason_code or "").strip().upper() == "PCAP_MISSING"
                    and str(getattr(r, "messaging_activity", "") or "").strip().lower() in {"none", ""}
                ):
                    status += " (LOW_SIGNAL_IDLE)"
            else:
                status = "UNKNOWN"
            rows.append(
                [
                    (r.ended_at or "—")[:19],
                    (r.run_profile or "—"),
                    (r.interaction_level or "—"),
                    (getattr(r, "messaging_activity", None) or "—"),
                    status,
                    (r.run_id or "—")[:8],
                ]
            )
        print()
        menu_utils.print_section("Recent Tracker Runs (informational)")
        menu_utils.print_table(
            ["Ended", "Profile", "Interaction", "Msg", "Status", "Run ID"],
            rows,
        )
        # Operator guidance: repeated baseline PCAP_MISSING usually indicates
        # low-signal app-idle behavior; suggest a warm baseline or scripted run.
        pcap_missing_streak = 0
        low_signal_idle_streak = 0
        for r in recent:
            prof = str(r.run_profile or "").strip().lower()
            reason = str(r.invalid_reason_code or "").strip().upper()
            if prof == "baseline_idle" and r.valid is False and reason == "PCAP_MISSING":
                pcap_missing_streak += 1
                continue
            if prof == "baseline_idle" and r.valid is True and r.low_signal is True:
                low_signal_idle_streak += 1
                continue
            break
        if pcap_missing_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_idle runs repeatedly failed with PCAP_MISSING. "
                    "If idle traffic stays low, try a minimal warm baseline (open chats list briefly) "
                    "or collect scripted interaction first.",
                    level="warn",
                )
            )
        if low_signal_idle_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_idle runs were VALID but LOW_SIGNAL_IDLE. "
                    "For messaging/chat-like apps, collect scripted interaction next to avoid non-countable baselines.",
                    level="warn",
                )
            )
        baseline_connected_insufficient_streak = _messaging_baseline_connected_insufficient_duration_streak(
            recent,
            package_name=package_name,
        )
        if baseline_connected_insufficient_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_connected runs failed with INSUFFICIENT_DURATION. "
                    "Policy: switch to scripted-first for this app/build; baseline remains pending.",
                    level="warn",
                )
            )
            suggested_profile = "interaction_scripted"

    # Capture modes.
    tier = "dataset"
    if selected_protocol == "1":
        run_profile = _canonical_baseline_profile_for_package(package_name)
        interaction_level = "minimal"
    elif selected_protocol == "2":
        run_profile = "interaction_scripted"
        interaction_level = "scripted"
    else:
        run_profile = "interaction_manual"
        interaction_level = "manual"
    counts_toward_completion = _intent_counts_toward_quota(
        run_profile=run_profile,
        baseline_valid_runs=int(counts.baseline_valid_runs),
        interactive_valid_runs=int(counts.interactive_valid_runs),
        cfg=cfg,
    )
    suggested_key = "2" if suggested_is_interactive else "1"
    if selected_protocol in {"1", "2"} and selected_protocol != suggested_key and not counts_toward_completion:
        print(
            status_messages.status(
                "Selected intent is not quota-suggested and will be saved as EXTRA (not countable).",
                level="warn",
            )
        )
        proceed = prompt_utils.prompt_yes_no("Proceed with EXTRA run anyway?", default=False)
        if not proceed:
            print(status_messages.status("Run canceled. Choose the suggested intent to fill quota.", level="info"))
            return

    # Manual runs can be quota-counted (by policy), so do not gate behind an
    # "EXPLORATORY" confirmation.
    messaging_activity: str | None = None
    if _is_messaging_package_or_category(package_name):
        # PM lock: messaging activity is a tag describing what happened. In manual mode, it
        # must never affect countability. In scripted mode, it selects a deterministic
        # template (template policy then determines cohort eligibility).
        if str(run_profile or "").strip().lower().startswith("baseline"):
            # Keep baseline deterministic: messaging baselines are baseline_connected and the
            # activity is "connected_idle" by definition. Do not offer a menu that can
            # accidentally select known-low-signal "home idle" baselines.
            messaging_activity = "connected_idle"
            print()
            print(status_messages.status("Messaging Activity tag: Idle (baseline_connected).", level="info"))
        else:
            print()
            menu_utils.print_header("Messaging Activity (Tag)")
            messaging_options = [
                menu_utils.MenuOption("1", "Idle", description="browse thread/list surfaces; no sending/calls/media"),
                menu_utils.MenuOption(
                    "2",
                    "Text",
                    description="send 2 fixed text messages (no media). Use Meta AI/Saved/Note-to-self if needed.",
                ),
                menu_utils.MenuOption("3", "Voice Call", description="start call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("4", "Video Call", description="start video call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("5", "Mixed", description="text + call (exploratory-only; non-cohort)"),
            ]
            menu_utils.render_menu(
                menu_utils.MenuSpec(
                    items=messaging_options,
                    default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                    exit_label=None,
                    show_exit=False,
                    show_descriptions=True,
                    compact=True,
                )
            )
            valid_choices = menu_utils.selectable_keys(messaging_options, include_exit=False)
            choice = prompt_utils.get_choice(
                valid_choices,
                default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                invalid_message=f"Choose {valid_choices[0]}-{valid_choices[-1]}.",
                disabled=[option.key for option in messaging_options if option.disabled],
            )
            messaging_activity = {
                "1": "idle",
                "2": "text_only",
                "3": "voice_call",
                "4": "video_call",
                "5": "mixed",
            }[choice]
    else:
        # Non-messaging apps: leave unset so downstream can distinguish "not applicable" vs "none".
        messaging_activity = None

    counts_toward_completion, policy_reason = _apply_messaging_baseline_countability_policy(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    if policy_reason == "MESSAGING_BASELINE_NONE_EXPLORATORY":
        print(
            status_messages.status(
                "Messaging baseline with 'none/home idle' is exploratory. "
                "Use 'Connected idle' (open thread, no send/call) for countable messaging baseline.",
                level="warn",
            )
        )
        if prompt_utils.prompt_yes_no("Switch to connected-idle baseline now?", default=True):
            messaging_activity = "connected_idle"
            run_profile = "baseline_connected"
            counts_toward_completion = _intent_counts_toward_quota(
                run_profile=run_profile,
                baseline_valid_runs=int(counts.baseline_valid_runs),
                interactive_valid_runs=int(counts.interactive_valid_runs),
                cfg=cfg,
            )
            print(status_messages.status("Using messaging baseline_connected behavior.", level="info"))

    if _is_messaging_connected_baseline(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
    ):
        can_open_thread = prompt_utils.prompt_yes_no(
            "Can you open an existing conversation thread now? (required for baseline_connected)",
            default=True,
        )
        if not can_open_thread:
            print(
                status_messages.status(
                    "Without an existing thread, messaging baseline is likely low-signal and may be excluded.",
                    level="warn",
                )
            )
            if prompt_utils.prompt_yes_no("Switch to scripted interaction now?", default=True):
                run_profile = "interaction_scripted"
                interaction_level = "scripted"
                messaging_activity = "none"
                counts_toward_completion = _intent_counts_toward_quota(
                    run_profile=run_profile,
                    baseline_valid_runs=int(counts.baseline_valid_runs),
                    interactive_valid_runs=int(counts.interactive_valid_runs),
                    cfg=cfg,
                )
                print(status_messages.status("Switched to scripted interaction.", level="info"))
            else:
                print(
                    status_messages.status(
                        "Run canceled to avoid low-signal baseline. Start again when a thread is available.",
                        level="info",
                    )
                )
                return

    # Template policy determines scripted countability (messaging activity is only a tag).
    if _is_messaging_package_or_category(package_name) and str(run_profile or "").strip().lower() == "interaction_scripted":
        try:
            tmpl_id, _steps = preview_script_template_for_package(
                package_name=str(package_name or "").strip().lower(),
                messaging_activity=str(messaging_activity or "").strip().lower(),
            )
            print(status_messages.status(f"Script template selected: {tmpl_id}", level="info"))
            if str(tmpl_id) == "messaging_call_basic_v1":
                print(
                    status_messages.status(
                        "Template policy: Mixed/call template is exploratory-only (will NOT count toward paper quota).",
                        level="warn",
                    )
                )
                counts_toward_completion = False
        except Exception:
            # If preview fails, keep behavior unchanged; capture can still proceed and will
            # be evaluated evidence-first post-run.
            pass

    # Operator-facing paper quota impact label (avoid generic "countable" wording).
    prof_lc = str(run_profile or "").strip().lower()
    if "manual" in prof_lc:
        paper_impact_label = "Paper quota impact: NO (manual is exploratory by policy)"
    elif counts_toward_completion:
        paper_impact_label = "Paper quota impact: YES (if VALID)"
    else:
        paper_impact_label = "Paper quota impact: NO (extra run / policy)"

    print(
        paper_impact_label
    )

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="guided")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return

    # Dataset mode is deterministic about plan choice, but interactive about gating:
    # if no plan exists yet, offer a single prompt to run static now.
    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=True,
        run_static_callback=_auto_run_static_for_package,
    )
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    if not _pre_run_scientific_checks(
        device_serial=device_serial,
        package_name=package_name,
        plan_path=plan_path,
        observer_ids=observer_ids,
    ):
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Stabilizing environment ({_STABILIZATION_WAIT_S}s)...", level="info"))
    time.sleep(_STABILIZATION_WAIT_S)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)
    if run_profile == "interaction_scripted":
        mapped = resolved_template_for_package(package_name)
        if not mapped:
            print(
                status_messages.status(
                    f"BLOCKED_UNKNOWN_CATEGORY: no scripted template mapping for {package_name} in paper mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

    spec = build_dynamic_run_spec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=scenario_id,
        tier=tier,
        duration_seconds=duration_seconds,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
        interactive=True,
        # Dataset tier is strict; exploratory runs are allowed to proceed with best-effort
        # schema/persistence while still producing an evidence pack.
        require_dynamic_schema=(tier == "dataset"),
        observer_prompts_enabled=bool(observer_prompts_enabled),
        pcapdroid_api_key=pcapdroid_api_key,
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    result = execute_dynamic_run_spec(spec)
    print_run_summary(result, label)
    _post_run_integrity_check(result)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)
    _capture_protocol_fit_feedback(result=result, run_profile=run_profile, package_name=package_name)


def _capture_protocol_fit_feedback(*, result, run_profile: str, package_name: str | None) -> None:
    if run_profile != "interaction_scripted":
        return
    if not result or str(getattr(result, "status", "")).lower() != "success":
        return
    run_id = str(getattr(result, "dynamic_run_id", "") or "").strip()
    if not run_id:
        return
    print()
    menu_utils.print_header("Protocol Fit (Optional)")
    fit_options = [
        menu_utils.MenuOption("1", "Great", description="Steps matched app flow well."),
        menu_utils.MenuOption("2", "Okay", description="Mostly good; minor mismatch."),
        menu_utils.MenuOption("3", "Poor", description="Steps did not fit app well."),
    ]
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=fit_options,
            default="2",
            show_exit=False,
            show_descriptions=True,
            compact=True,
        )
    )
    fit_choice = prompt_utils.get_choice(["1", "2", "3"], default="2", invalid_message="Choose 1-3.")
    fit_label = {"1": "great", "2": "okay", "3": "poor"}.get(fit_choice, "okay")

    step_ref = ""
    replacement_note = ""
    if fit_label == "poor":
        step_ref = prompt_utils.prompt_text(
            "Which step number felt wrong? (optional, e.g., 2)",
            required=False,
        ).strip()
        replacement_note = prompt_utils.prompt_text(
            "Suggested replacement step (optional one-line note)",
            required=False,
        ).strip()
        print(
            status_messages.status(
                "Rerun recommended with the correct template/protocol before counting this app for paper cohort.",
                level="warn",
            )
        )

    # Messaging templates may legitimately send messages (text-mode templates). Only flag
    # "send" as a protocol violation when it was not expected by the selected template.
    send_detected = False

    event = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "event": "protocol_fit_feedback",
        "run_id": run_id,
        "run_profile": run_profile,
        "fit": fit_label,
        "step_ref": step_ref or None,
        "replacement_note": replacement_note or None,
        "script_protocol_send": bool(send_detected),
    }
    run_dir = resolve_evidence_path(getattr(result, "evidence_path", None)) if getattr(result, "evidence_path", None) else None
    if not run_dir:
        return
    manifest_path = Path(run_dir) / "run_manifest.json"
    events_path = Path(run_dir) / "notes" / "run_events.jsonl"
    try:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    except Exception:
        return
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            operator_existing = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            observed_template = str(operator_existing.get("template_id_actual") or operator_existing.get("template_id") or "").strip()
            is_text_template = observed_template.endswith("_text_v1") or observed_template in {"messaging_text_v1", "whatsapp_text_v1"}
            if _is_messaging_package_or_category(str(package_name or "").strip().lower()) and not is_text_template:
                send_detected = prompt_utils.prompt_yes_no(
                    "Did this scripted run send messages outside of the template steps? (protocol violation)",
                    default=False,
                )
            operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            operator["protocol_fit"] = fit_label
            operator["protocol_fit_step_ref"] = step_ref or None
            operator["protocol_fit_replacement_note"] = replacement_note or None
            operator["script_protocol_send"] = bool(send_detected)
            payload["operator"] = operator
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass
    print(status_messages.status("Protocol fit feedback saved.", level="info"))


__all__ = ["run_guided_dataset_run"]
