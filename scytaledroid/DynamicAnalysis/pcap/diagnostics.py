"""Shared PCAP failure diagnostics helpers for dynamic evidence readers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def extract_verify_issue_codes(verify_row: Mapping[str, Any] | None) -> tuple[str, ...]:
    seen: list[str] = []
    if not isinstance(verify_row, Mapping):
        return ()
    for issue in verify_row.get("issues") or []:
        if not isinstance(issue, Mapping):
            continue
        code = str(issue.get("code") or "").strip()
        if code and code not in seen:
            seen.append(code)
    return tuple(seen)


def verify_issue_codes_csv(verify_row: Mapping[str, Any] | None) -> str:
    return ";".join(extract_verify_issue_codes(verify_row))


def canonical_pcap_failure_code(
    *,
    artifact_rel: str = "",
    artifact_exists: bool | None = None,
    pcap_size_bytes: int | None = None,
    report_status: str = "",
    invalid_reason_code: str = "",
    verify_row: Mapping[str, Any] | None = None,
) -> str:
    issue_codes = set(extract_verify_issue_codes(verify_row))
    invalid_reason = str(invalid_reason_code or "").strip().upper()
    report_state = str(report_status or "").strip().lower()
    rel = str(artifact_rel or "").strip()
    size = int(pcap_size_bytes or 0)

    if not rel and "pcap_artifact_missing" in issue_codes:
        return "artifact_missing"
    if rel and artifact_exists is False and "pcap_file_missing" in issue_codes:
        return "local_file_missing"
    if rel and artifact_exists is False:
        return "local_file_missing"
    if rel and artifact_exists and size <= 0:
        return "local_file_empty"
    if "pcap_artifact_missing" in issue_codes:
        return "artifact_missing"
    if "pcap_file_missing" in issue_codes:
        return "local_file_missing"
    if invalid_reason == "PCAP_PARSE_ERROR":
        return "parse_failed"
    if invalid_reason == "PCAP_MISSING":
        return "missing_generic"
    if report_state == "ok":
        return "ok"
    if report_state in {"skip", "partial"} and size > 0:
        return "parse_failed"
    return "unknown"


def deep_audit_pcap_failure_detail(canonical_code: str) -> str:
    mapping = {
        "artifact_missing": "PCAP_MISSING",
        "missing_generic": "PCAP_MISSING",
        "local_file_missing": "PCAP_LOCAL_FILE_MISSING",
        "local_file_empty": "PCAP_LOCAL_FILE_EMPTY",
        "parse_failed": "PCAP_PARSE_FAILED",
        "ok": "",
        "unknown": "",
    }
    return mapping.get(str(canonical_code or "").strip(), "")


def export_pcap_failure_detail(canonical_code: str) -> str:
    mapping = {
        "artifact_missing": "invalid_pcap_artifact_missing",
        "missing_generic": "invalid_pcap_missing",
        "local_file_missing": "invalid_pcap_file_missing",
        "local_file_empty": "invalid_pcap_local_file_empty",
        "parse_failed": "invalid_pcap_parse_error",
        "ok": "",
        "unknown": "",
    }
    return mapping.get(str(canonical_code or "").strip(), "")


def raw_pcap_failure_detail_from_canonical(canonical_code: str) -> str:
    mapping = {
        "artifact_missing": "PCAP_ARTIFACT_MISSING",
        "missing_generic": "PCAP_MISSING",
        "local_file_missing": "PCAP_LOCAL_FILE_MISSING",
        "local_file_empty": "PCAP_LOCAL_FILE_EMPTY",
        "parse_failed": "PCAP_PARSE_FAILED",
        "ok": "",
        "unknown": "",
    }
    return mapping.get(str(canonical_code or "").strip(), "")


def canonical_pcap_failure_code_from_raw_detail(raw_detail: str) -> str:
    mapping = {
        "PCAP_ARTIFACT_MISSING": "artifact_missing",
        "PCAP_DEVICE_FILE_MISSING": "artifact_missing",
        "PCAP_DEVICE_FILE_EMPTY": "missing_generic",
        "PCAP_MISSING": "missing_generic",
        "PCAP_PULL_FAILED": "local_file_missing",
        "PCAP_LOCAL_FILE_MISSING": "local_file_missing",
        "PCAP_LOCAL_FILE_EMPTY": "local_file_empty",
        "PCAP_PARSE_FAILED": "parse_failed",
    }
    return mapping.get(str(raw_detail or "").strip().upper(), "")


def dataset_pcap_failure_detail(run_dir: Path, *, pcap_size_int: int = 0) -> str | None:
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    local_pcaps = sorted(path for path in capture_dir.glob("*.pcap*") if path.is_file())
    if local_pcaps:
        try:
            if max(int(path.stat().st_size) for path in local_pcaps) <= 0:
                return "PCAP_LOCAL_FILE_EMPTY"
        except OSError:
            return "PCAP_LOCAL_FILE_EMPTY"
        if int(pcap_size_int or 0) > 0:
            return "PCAP_PARSE_FAILED"
    meta = _read_json(capture_dir / "pcapdroid_capture_meta.json")
    if not isinstance(meta, dict):
        return None
    diagnostics = meta.get("failure_diagnostics") if isinstance(meta.get("failure_diagnostics"), dict) else {}
    expected_exists = diagnostics.get("expected_device_path_exists")
    expected_size = diagnostics.get("expected_device_path_size_bytes")
    fallback_exists = diagnostics.get("latest_fallback_exists")
    fallback_size = diagnostics.get("latest_fallback_size_bytes")
    delayed_expected_exists = diagnostics.get("delayed_expected_device_path_exists")
    delayed_expected_size = diagnostics.get("delayed_expected_device_path_size_bytes")
    delayed_fallback_exists = diagnostics.get("delayed_latest_fallback_exists")
    delayed_fallback_size = diagnostics.get("delayed_latest_fallback_size_bytes")

    def _classify_device_surface(exists: object, size: object) -> str | None:
        if exists is not True:
            return None
        try:
            if int(size or 0) <= 0:
                return "PCAP_DEVICE_FILE_EMPTY"
        except Exception:
            return "PCAP_DEVICE_FILE_EMPTY"
        if not local_pcaps:
            return "PCAP_PULL_FAILED"
        return None

    direct_device_result = _classify_device_surface(expected_exists, expected_size)
    if direct_device_result:
        return direct_device_result
    fallback_device_result = _classify_device_surface(fallback_exists, fallback_size)
    if fallback_device_result:
        return fallback_device_result
    delayed_device_result = _classify_device_surface(delayed_expected_exists, delayed_expected_size)
    if delayed_device_result:
        return delayed_device_result
    delayed_fallback_result = _classify_device_surface(delayed_fallback_exists, delayed_fallback_size)
    if delayed_fallback_result:
        return delayed_fallback_result

    if expected_exists is True:
        return "PCAP_PULL_FAILED" if not local_pcaps else None
    if fallback_exists is True:
        return "PCAP_PULL_FAILED" if not local_pcaps else None
    if delayed_expected_exists is True:
        return "PCAP_PULL_FAILED" if not local_pcaps else None
    if delayed_fallback_exists is True:
        return "PCAP_PULL_FAILED" if not local_pcaps else None
    if int(pcap_size_int or 0) > 0:
        return "PCAP_PARSE_FAILED"
    delayed_fallback_path = diagnostics.get("delayed_latest_fallback_path")
    if (
        expected_exists is False
        and not diagnostics.get("latest_fallback_path")
        and delayed_expected_exists is not True
        and not delayed_fallback_path
    ):
        return "PCAP_DEVICE_FILE_MISSING"
    return "PCAP_LOCAL_FILE_MISSING"


def security_surface_issue_codes(report: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return conservative issue codes for security_surface health on one pcap_report."""
    if not isinstance(report, Mapping):
        return ("security_surface_missing",)
    if str(report.get("report_status") or "").lower() not in {"ok", "success"}:
        return ()
    surface = report.get("security_surface")
    if not isinstance(surface, dict):
        return ("security_surface_missing",)
    status = str(surface.get("status") or "").strip().lower()
    if status == "ok":
        codes: list[str] = []
        cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
        if cleartext.get("http_observed"):
            codes.append("cleartext_http_observed")
        if _safe_int_surface(cleartext.get("decoded_stream_count")) > 0:
            codes.append("decoded_cleartext_streams_observed")
        for flag in surface.get("risk_flags") or []:
            text = str(flag or "").strip()
            if text:
                codes.append(text)
        return tuple(dict.fromkeys(codes))
    if status in {"failed", "skipped"}:
        return (f"security_surface_{status}",)
    return ("security_surface_missing",)


def _safe_int_surface(value: object) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


__all__ = [
    "canonical_pcap_failure_code",
    "canonical_pcap_failure_code_from_raw_detail",
    "dataset_pcap_failure_detail",
    "deep_audit_pcap_failure_detail",
    "export_pcap_failure_detail",
    "raw_pcap_failure_detail_from_canonical",
    "extract_verify_issue_codes",
    "security_surface_issue_codes",
    "verify_issue_codes_csv",
]
