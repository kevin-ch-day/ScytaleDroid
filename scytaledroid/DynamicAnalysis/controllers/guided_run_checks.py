"""Validation and integrity helpers for guided dynamic runs."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from pathlib import Path

from scytaledroid.DeviceAnalysis.adb import package_manager as adb_package_manager
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _infer_pcap_failure_detail(run_dir: Path, *, pcap_size_int: int) -> str | None:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import dataset_pcap_failure_detail

    return dataset_pcap_failure_detail(run_dir, pcap_size_int=pcap_size_int)


def _derive_pcap_failure_summary(run_dir: Path, *, pcap_size_int: int) -> tuple[str | None, str | None]:
    detail = _infer_pcap_failure_detail(run_dir, pcap_size_int=pcap_size_int)
    summary = _read_json(run_dir / "analysis" / "summary.json") or {}
    telemetry = summary.get("telemetry") if isinstance(summary.get("telemetry"), dict) else {}
    stats = telemetry.get("stats") if isinstance(telemetry.get("stats"), dict) else {}
    try:
        netstats_total_bytes = int(stats.get("netstats_bytes_in_total") or 0) + int(stats.get("netstats_bytes_out_total") or 0)
    except Exception:
        netstats_total_bytes = 0
    timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json") or {}
    timeline_available = bool(timeline)
    timeline_complete = timeline.get("timeline_complete") if isinstance(timeline, dict) else None
    if netstats_total_bytes > 0:
        base = "Network traffic was observed by Android netstats, but the PCAP capture artifact is empty or unavailable."
    else:
        base = "PCAP capture artifact is empty or unavailable."
    if timeline_available:
        if timeline_complete is False:
            base += " Scripted interaction timeline is present but incomplete."
        else:
            base += " Scripted interaction timeline is still available for protocol validation."
    return detail, base


def _pcap_observer_notes(run_dir: Path) -> list[str]:
    meta = _read_json(run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json") or {}
    if not isinstance(meta, dict):
        return []
    notes: list[str] = []
    status = meta.get("status_check") if isinstance(meta.get("status_check"), dict) else {}
    status_error = str(status.get("error") or "").strip()
    status_source = str(status.get("source") or "").strip()
    if status_error:
        notes.append(f"PCAPdroid status: {status_error}")
    elif status_source == "unavailable":
        notes.append("PCAPdroid status probe unavailable; capture was judged from artifacts.")

    diagnostics = meta.get("failure_diagnostics") if isinstance(meta.get("failure_diagnostics"), dict) else {}
    expected_exists = diagnostics.get("expected_device_path_exists")
    delayed_expected_exists = diagnostics.get("delayed_expected_device_path_exists")
    delayed_expected_size = diagnostics.get("delayed_expected_device_path_size_bytes")
    fallback_path = str(diagnostics.get("latest_fallback_path") or "").strip()
    delayed_fallback_path = str(diagnostics.get("delayed_latest_fallback_path") or "").strip()
    if expected_exists is False and delayed_expected_exists is True:
        try:
            delayed_size = int(delayed_expected_size or 0)
        except Exception:
            delayed_size = 0
        if delayed_size <= 0:
            notes.append("Observer note: named device file appeared after stop but remained empty.")
        else:
            notes.append("Observer note: named device file appeared after stop; local pull should be reviewed.")
    elif expected_exists is False and not fallback_path and not delayed_fallback_path:
        notes.append("Observer note: named device file was not visible on device at stop time.")
    return notes[:3]


def read_observed_version_code_details(
    device_serial: str,
    package_name: str,
    *,
    run_shell_fn,
    extract_details_fn,
) -> dict[str, str]:
    result, command = adb_package_manager.read_supported_metadata_dump(
        device_serial,
        package_name,
        run_command=lambda current: run_shell_fn(device_serial, list(current)),
        is_successful=lambda value: bool(str(value or "").strip()),
        extract_text=lambda value: str(value or ""),
        accept_text=lambda text: adb_package_manager.output_looks_package_specific(text, package_name),
    )
    if result is None or command is None:
        command = ["dumpsys", "package", package_name]
        dump = run_shell_fn(device_serial, command)
    else:
        dump = str(result or "")
    command_used = " ".join(command)
    parsed = extract_details_fn(dump, package_name)
    return {
        "version_code": parsed.get("version_code", ""),
        "command": command_used,
        "pattern": parsed.get("pattern", ""),
        "matched_line": parsed.get("matched_line", ""),
    }


def extract_version_code_details_from_dump(dump: str, package_name: str) -> dict[str, str]:
    text = str(dump or "")
    if not text:
        return {}
    pkg = str(package_name or "").strip()

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
        ("versionCode+minSdk", r"(?m)^\s*(versionCode=(\d+)\s+minSdk=.*)$"),
        ("versionCode-line", r"(?m)^\s*(versionCode=(\d+)\b.*)$"),
        ("versionCode-any", r"(versionCode=(\d+)\b)"),
    )
    for source_name, source in (("scoped", scoped), ("full", text)):
        for pattern_name, pat in patterns:
            matches = list(re.finditer(pat, source))
            if not matches:
                continue
            best_match = None
            best_value = None
            for match in matches:
                try:
                    candidate = int(match.group(2).strip()) if len(match.groups()) >= 2 else None
                except Exception:
                    candidate = None
                if candidate is None:
                    continue
                if best_value is None or candidate > best_value:
                    best_match = match
                    best_value = candidate
            if best_match is None or best_value is None:
                continue
            matched_line = ""
            try:
                matched_line = best_match.group(1).strip()
            except Exception:
                matched_line = ""
            return {
                "version_code": str(best_value),
                "pattern": f"{source_name}:{pattern_name}",
                "matched_line": matched_line,
            }
    return {}


def read_observed_signer_set_hash(
    device_serial: str,
    package_name: str,
    *,
    run_shell_fn,
) -> str | None:
    result, command = adb_package_manager.read_supported_metadata_dump(
        device_serial,
        package_name,
        run_command=lambda current: run_shell_fn(device_serial, list(current)),
        is_successful=lambda value: bool(str(value or "").strip()),
        extract_text=lambda value: str(value or ""),
        accept_text=lambda text: adb_package_manager.output_looks_package_specific(text, package_name),
    )
    if result is None or command is None:
        dump = run_shell_fn(device_serial, ["dumpsys", "package", package_name])
    else:
        dump = str(result or "")
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


def pre_run_scientific_checks(
    *,
    device_serial: str,
    package_name: str,
    plan_path: str,
    observer_ids: list[str],
    data_dir: str,
    battery_block_pct: int,
    battery_warn_pct: int,
    storage_block_gb: float,
    clock_block_s: int,
    clock_warn_s: int,
    missing_required_tools_fn,
    read_capture_interface_fn,
    read_vpn_state_fn,
    read_battery_level_fn,
    read_storage_free_gb_fn,
    read_clock_drift_seconds_fn,
    load_plan_identity_fn,
    read_observed_version_code_details_fn,
    known_signer_hash_fn,
    read_observed_signer_set_hash_fn,
) -> bool:
    hard_failures: list[str] = []
    warnings: list[str] = []
    rows: list[list[str]] = []

    missing = missing_required_tools_fn(tier="dataset")
    if missing:
        hard_failures.append(f"Missing host tools: {', '.join(missing)}")
        rows.append(["Host tools", "FAIL", ", ".join(missing)])
    else:
        rows.append(["Host tools", "OK", "tshark + capinfos"])

    try:
        with tempfile.NamedTemporaryFile(
            prefix="scytaledroid-preflight-",
            dir=data_dir,
            delete=True,
        ):
            pass
        rows.append(["PCAP tool test write", "OK", data_dir])
    except Exception as exc:
        hard_failures.append("PCAP tool test write failed")
        rows.append(["PCAP tool test write", "FAIL", str(exc)])

    capture_iface = read_capture_interface_fn(device_serial)
    if not capture_iface:
        hard_failures.append("Capture interface unavailable")
        rows.append(["Capture interface", "FAIL", "no default route device"])
    else:
        rows.append(["Capture interface", "OK", capture_iface])

    vpn_state = read_vpn_state_fn(device_serial)
    if vpn_state != "not_vpn":
        hard_failures.append(f"VPN state mismatch: expected not_vpn, got {vpn_state}")
        rows.append(["VPN state", "FAIL", vpn_state])
    else:
        rows.append(["VPN state", "OK", vpn_state])

    battery = read_battery_level_fn(device_serial)
    if battery is None:
        warnings.append("Battery level unavailable")
        rows.append(["Battery", "WARN", "unavailable"])
    elif battery < battery_block_pct:
        hard_failures.append(f"Battery too low ({battery}%)")
        rows.append(["Battery", "FAIL", f"{battery}% (<{battery_block_pct}%)"])
    elif battery < battery_warn_pct:
        warnings.append(f"Battery below recommended threshold ({battery}%)")
        rows.append(["Battery", "WARN", f"{battery}% (<{battery_warn_pct}%)"])
    else:
        rows.append(["Battery", "OK", f"{battery}%"])

    storage_gb = read_storage_free_gb_fn(device_serial)
    if storage_gb is None:
        hard_failures.append("Storage check unavailable")
        rows.append(["Free storage", "FAIL", "unable to read /data free space"])
    elif storage_gb < storage_block_gb:
        hard_failures.append(f"Insufficient free storage ({storage_gb:.2f} GB)")
        rows.append(["Free storage", "FAIL", f"{storage_gb:.2f} GB (<{storage_block_gb:.1f} GB)"])
    else:
        rows.append(["Free storage", "OK", f"{storage_gb:.2f} GB"])

    clock_drift = read_clock_drift_seconds_fn(device_serial)
    if clock_drift is None:
        warnings.append("Clock drift unavailable")
        rows.append(["Clock drift", "WARN", "unavailable"])
    elif clock_drift > clock_block_s:
        hard_failures.append(f"Clock drift too high ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "FAIL", f"{clock_drift:.1f}s (>{clock_block_s}s)"])
    elif clock_drift > clock_warn_s:
        warnings.append(f"Clock drift above recommended threshold ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "WARN", f"{clock_drift:.1f}s (>{clock_warn_s}s)"])
    else:
        rows.append(["Clock drift", "OK", f"{clock_drift:.1f}s"])

    plan_identity = load_plan_identity_fn(plan_path)
    observed_details = read_observed_version_code_details_fn(device_serial, package_name)
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
        hard_failures.append(f"Build identity drift: version_code {observed_vc or 'unknown'} != {expected_vc}")
        rows.append(["Build identity", "FAIL", f"observed={observed_vc or 'unknown'} expected={expected_vc}"])
        rows.append(["Identity source", "INFO", observed_details.get("command") or "unknown"])
        rows.append(["Identity parser", "INFO", observed_details.get("pattern") or "no-match"])
        rows.append(["Identity line", "INFO", observed_details.get("matched_line") or "no-match"])
    else:
        rows.append(["Build identity", "OK", f"version_code={expected_vc}"])

    expected_signer = known_signer_hash_fn(plan_identity.get("signer_set_hash"))
    observed_signer = read_observed_signer_set_hash_fn(device_serial, package_name) or ""
    if expected_signer:
        if not observed_signer:
            hard_failures.append("Signer identity missing on device")
            rows.append(["Signer identity", "FAIL", "unable to derive signer_set_hash"])
        elif observed_signer != expected_signer:
            hard_failures.append("Signer identity drift detected")
            rows.append(["Signer identity", "FAIL", f"observed={observed_signer[:12]} expected={expected_signer[:12]}"])
        else:
            rows.append(["Signer identity", "OK", expected_signer[:12]])
    elif observed_signer:
        rows.append(["Signer identity", "INFO", f"observed={observed_signer[:12]} (plan unavailable; drift check skipped)"])
    else:
        rows.append(["Signer identity", "INFO", "plan and device signer unavailable"])

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
        print(status_messages.status("Pre-run scientific checks failed. Run blocked in freeze/profile mode.", level="error"))
        return False
    print(status_messages.status("Status: READY", level="success"))
    return True


def device_preflight_checks(
    device_serial: str,
    *,
    data_dir: str,
    battery_block_pct: int,
    battery_warn_pct: int,
    storage_block_gb: float,
    clock_block_s: int,
    clock_warn_s: int,
    ui_level: str,
    missing_required_tools_fn,
    read_capture_interface_fn,
    read_vpn_state_fn,
    read_battery_level_fn,
    read_storage_free_gb_fn,
    read_clock_drift_seconds_fn,
) -> bool:
    hard_failures: list[str] = []
    warnings: list[str] = []
    rows: list[list[str]] = []

    missing = missing_required_tools_fn(tier="dataset")
    if missing:
        hard_failures.append(f"Missing host tools: {', '.join(missing)}")
        rows.append(["Host tools", "FAIL", ", ".join(missing)])
    else:
        rows.append(["Host tools", "OK", "tshark + capinfos"])

    try:
        with tempfile.NamedTemporaryFile(
            prefix="scytaledroid-preflight-",
            dir=data_dir,
            delete=True,
        ):
            pass
        rows.append(["PCAP tool test write", "OK", data_dir])
    except Exception as exc:
        hard_failures.append("PCAP tool test write failed")
        rows.append(["PCAP tool test write", "FAIL", str(exc)])

    capture_iface = read_capture_interface_fn(device_serial)
    if not capture_iface:
        hard_failures.append("Capture interface unavailable")
        rows.append(["Capture interface", "FAIL", "no default route device"])
    else:
        rows.append(["Capture interface", "OK", capture_iface])

    vpn_state = read_vpn_state_fn(device_serial)
    if vpn_state != "not_vpn":
        hard_failures.append(f"VPN state mismatch: expected not_vpn, got {vpn_state}")
        rows.append(["VPN state", "FAIL", vpn_state])
    else:
        rows.append(["VPN state", "OK", vpn_state])

    battery = read_battery_level_fn(device_serial)
    if battery is None:
        warnings.append("Battery level unavailable")
        rows.append(["Battery", "WARN", "unavailable"])
    elif battery < battery_block_pct:
        hard_failures.append(f"Battery too low ({battery}%)")
        rows.append(["Battery", "FAIL", f"{battery}% (<{battery_block_pct}%)"])
    elif battery < battery_warn_pct:
        warnings.append(f"Battery below recommended threshold ({battery}%)")
        rows.append(["Battery", "WARN", f"{battery}% (<{battery_warn_pct}%)"])
    else:
        rows.append(["Battery", "OK", f"{battery}%"])

    storage_gb = read_storage_free_gb_fn(device_serial)
    if storage_gb is None:
        hard_failures.append("Storage check unavailable")
        rows.append(["Free storage", "FAIL", "unable to read /data free space"])
    elif storage_gb < storage_block_gb:
        hard_failures.append(f"Insufficient free storage ({storage_gb:.2f} GB)")
        rows.append(["Free storage", "FAIL", f"{storage_gb:.2f} GB (<{storage_block_gb:.1f} GB)"])
    else:
        rows.append(["Free storage", "OK", f"{storage_gb:.2f} GB"])

    clock_drift = read_clock_drift_seconds_fn(device_serial)
    if clock_drift is None:
        warnings.append("Clock drift unavailable")
        rows.append(["Clock drift", "WARN", "unavailable"])
    elif clock_drift > clock_block_s:
        hard_failures.append(f"Clock drift too high ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "FAIL", f"{clock_drift:.1f}s (>{clock_block_s}s)"])
    elif clock_drift > clock_warn_s:
        warnings.append(f"Clock drift above recommended threshold ({clock_drift:.1f}s)")
        rows.append(["Clock drift", "WARN", f"{clock_drift:.1f}s (>{clock_warn_s}s)"])
    else:
        rows.append(["Clock drift", "OK", f"{clock_drift:.1f}s"])

    verbose = ui_level == "debug"
    print()
    menu_utils.print_header("Dynamic Environment Validation")
    if verbose or warnings or hard_failures:
        menu_utils.print_table(["Check", "Status", "Details"], rows)
    else:
        omit = {"Battery", "Free storage"}
        for check, _status, detail in rows:
            if check in omit:
                continue
            if check == "VPN state" and str(detail).strip().lower() == "not_vpn":
                detail = "not_vpn (No VPN)"
            print(f"{check}={detail}")
    for msg in warnings:
        print(status_messages.status(msg, level="warn"))
    if hard_failures:
        for msg in hard_failures:
            print(status_messages.status(msg, level="error"))
        print(status_messages.status("Environment checks failed. Resolve issues before selecting an app.", level="error"))
        return False
    print(status_messages.status("Status: READY", level="success"))
    return True


def post_run_integrity_check(
    result,
    *,
    min_pcap_bytes: int,
    min_windows: int,
    ui_level: str,
) -> None:
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
    features_detail = "analysis/pcap_features.json"
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
        parsed = ((report.get("capinfos") or {}).get("parsed") if isinstance(report.get("capinfos"), dict) else {})
        capinfos_ok = isinstance(parsed, dict) and parsed.get("packet_count") is not None
        tshark_ok = str(report.get("report_status") or "").lower() == "ok"
        if pcap_size is None:
            pcap_size = report.get("pcap_size_bytes")
    except Exception:
        parsed = {}

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
        features_structured = (
            isinstance(features, dict)
            and isinstance(features.get("metrics"), dict)
            and isinstance(features.get("proxies"), dict)
        )
        quality = features.get("quality") if isinstance(features, dict) else {}
        if not isinstance(quality, dict):
            quality = {}
        feature_report_status = str(quality.get("report_status") or "").strip().lower()
        enrichment = quality.get("pcap_enrichment") if isinstance(quality.get("pcap_enrichment"), dict) else {}
        enrichment_status = str(enrichment.get("status") or "").strip().lower()
        enrichment_reason = str(enrichment.get("reason") or "").strip()
        features_ok = features_structured and feature_report_status == "ok" and enrichment_status != "skipped"
        detail_parts = ["analysis/pcap_features.json"]
        if feature_report_status:
            detail_parts.append(f"report={feature_report_status}")
        if enrichment_status:
            detail_parts.append(f"enrichment={enrichment_status}")
        if enrichment_reason:
            detail_parts.append(f"reason={enrichment_reason}")
        features_detail = " | ".join(detail_parts)
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
    pcap_size_ok = pcap_size_int >= int(min_pcap_bytes)
    window_count_ok = window_count is not None and int(window_count) >= int(min_windows)
    verdict = (
        "VALID"
        if (dataset_valid is True and pcap_size_ok and capinfos_ok and tshark_ok and features_ok and window_count_ok)
        else "INVALID"
    )
    rows = [
        ["PCAP size", "OK" if pcap_size_ok else "FAIL", f"{pcap_size_int} bytes (min {int(min_pcap_bytes)})"],
        ["capinfos parse", "OK" if capinfos_ok else "FAIL", ("parsed packet metadata" if capinfos_ok else "packet metadata unavailable")],
        ["tshark parse", "OK" if tshark_ok else "FAIL", f"report_status={report.get('report_status') if isinstance(report, dict) else 'missing'}"],
        ["Feature extraction", "OK" if features_ok else "FAIL", features_detail],
        ["Window count", "OK" if window_count_ok else "FAIL", (f"{window_count} (min {min_windows})" if window_count is not None else f"unavailable (min {min_windows})")],
        ["Run verdict", "OK" if verdict == "VALID" else "FAIL", verdict],
    ]
    print()
    menu_utils.print_header("Post-Run Integrity")
    verbose = ui_level == "debug"
    if verdict == "VALID" and not verbose:
        print(status_messages.status(f"VALID (pcap={pcap_size_int}B, windows={window_count}, dur={parsed.get('capture_duration_s') if isinstance(parsed, dict) else 'n/a'}s)", level="success"))
    else:
        menu_utils.print_table(["Check", "Status", "Details"], rows)
    if verdict != "VALID":
        print(status_messages.status(f"Dataset validity: INVALID ({invalid_reason or 'PCAP_PARSE_ERROR'})", level="error"))
        pcap_failure_summary = str(dataset.get("pcap_failure_summary") or "").strip()
        pcap_failure_detail = str(dataset.get("pcap_failure_detail") or "").strip()
        if not pcap_failure_summary and str(invalid_reason or "").startswith("PCAP_"):
            pcap_failure_detail, pcap_failure_summary = _derive_pcap_failure_summary(
                run_dir,
                pcap_size_int=pcap_size_int,
            )
        if pcap_failure_summary:
            print(status_messages.status(pcap_failure_summary, level="warn"))
            print(status_messages.status("This run is excluded from dataset quota.", level="warn"))
            print(status_messages.status("Recommended action: verify PCAPdroid capture/export and recollect.", level="warn"))
            if pcap_failure_detail:
                print(status_messages.status(f"PCAP failure detail: {pcap_failure_detail}", level="warn"))
            for note in _pcap_observer_notes(run_dir):
                print(status_messages.status(note, level="warn"))
    else:
        print(status_messages.status("Dataset validity: VALID", level="success"))
