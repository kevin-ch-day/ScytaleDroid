"""Static handoff v1 payload builder and exporter."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.cli.core import masvs_mapper
from scytaledroid.StaticAnalysis.core import StaticAnalysisReport


def _as_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def _identity_mode(*, base_apk_sha256: str | None, version_code: int | None) -> str:
    if base_apk_sha256:
        return "full_hash"
    if version_code is not None:
        return "pkg_ver_only"
    return "pkg_only"


def _masvs_status(severity_by_category: Mapping[str, Mapping[str, int]], category: str) -> str:
    row = severity_by_category.get(category, {})
    if not isinstance(row, Mapping) or not row:
        return "na"
    high = int(row.get("High", 0) or row.get("HIGH", 0) or 0)
    medium = int(row.get("Medium", 0) or row.get("MEDIUM", 0) or 0)
    low = int(row.get("Low", 0) or row.get("LOW", 0) or 0)
    info = int(row.get("Info", 0) or row.get("INFO", 0) or 0)
    if high > 0:
        return "fail"
    if medium > 0 or low > 0 or info > 0:
        return "partial"
    return "pass"


def _masvs_mapping_fingerprint() -> tuple[str, str]:
    canonical = json.dumps(
        {
            "rule_to_control": dict(sorted(masvs_mapper.RULE_TO_CONTROL.items())),
            "status_precedence": dict(sorted(masvs_mapper.STATUS_PRECEDENCE.items())),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "v1", hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _collect_string_samples(
    string_data: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]], Mapping[str, int]]:
    selected = string_data.get("selected_samples")
    if not isinstance(selected, Mapping):
        selected = string_data.get("samples", {})
    selected = selected if isinstance(selected, Mapping) else {}
    hints: list[dict[str, object]] = []
    secrets: list[dict[str, object]] = []
    counts = {
        "urls_count": 0,
        "domains_count": 0,
        "ip_literals_count": 0,
        "http_cleartext_url_count": 0,
        "high_entropy_token_count": 0,
        "api_key_like_count": 0,
    }
    for bucket_name, entries in selected.items():
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
            continue
        key = str(bucket_name)
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            value = str(entry.get("value_masked") or "").strip()
            root = str(entry.get("root_domain") or "").strip()
            sample_hash = str(entry.get("sample_hash") or "").strip()
            tag = str(entry.get("tag") or "").strip()
            src = str(entry.get("src") or "").strip()
            if key in {"endpoints", "http_cleartext"}:
                counts["urls_count"] += 1
            if key == "http_cleartext":
                counts["http_cleartext_url_count"] += 1
            if key == "api_keys":
                counts["api_key_like_count"] += 1
            if key == "high_entropy":
                counts["high_entropy_token_count"] += 1
            if root:
                counts["domains_count"] += 1
                if len(hints) < 25:
                    hints.append({"domain": root, "tag": tag or None, "src": src or None})
            if key in {"api_keys", "high_entropy"} and len(secrets) < 25:
                secrets.append(
                    {
                        "type": "api_key" if key == "api_keys" else "token_candidate",
                        "value_redacted": value,
                        "value_hash": sample_hash or None,
                        "context_ref": src or None,
                    }
                )
    return hints, secrets, counts


def build_static_handoff(
    *,
    report: StaticAnalysisReport,
    string_data: Mapping[str, object],
    package_name: str,
    version_code: int | None,
    base_apk_sha256: str | None,
    artifact_set_hash: str | None,
    static_run_id: int,
    session_label: str,
    tool_semver: str,
    tool_git_commit: str | None,
    schema_version: str,
) -> dict[str, object]:
    declared = set(report.permissions.declared or ())
    dangerous = set(report.permissions.dangerous or ())
    matrices = report.analysis_matrices if isinstance(report.analysis_matrices, Mapping) else {}
    sev_by_cat = matrices.get("severity_by_category") if isinstance(matrices, Mapping) else {}
    sev_by_cat = sev_by_cat if isinstance(sev_by_cat, Mapping) else {}
    detector_metrics = report.detector_metrics if isinstance(report.detector_metrics, Mapping) else {}
    ipc_metrics = detector_metrics.get("ipc_components") if isinstance(detector_metrics, Mapping) else {}
    ipc_metrics = ipc_metrics if isinstance(ipc_metrics, Mapping) else {}
    provider_metrics = detector_metrics.get("provider_acl") if isinstance(detector_metrics, Mapping) else {}
    provider_metrics = provider_metrics if isinstance(provider_metrics, Mapping) else {}
    storage_metrics = detector_metrics.get("storage_surface") if isinstance(detector_metrics, Mapping) else {}
    storage_metrics = storage_metrics if isinstance(storage_metrics, Mapping) else {}
    nsc_metrics = detector_metrics.get("network_surface") if isinstance(detector_metrics, Mapping) else {}
    nsc_metrics = nsc_metrics if isinstance(nsc_metrics, Mapping) else {}
    hints, secrets, string_counts = _collect_string_samples(string_data if isinstance(string_data, Mapping) else {})
    categories = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    statuses = {name: _masvs_status(sev_by_cat, name) for name in categories}
    pass_count = sum(1 for value in statuses.values() if value == "pass")
    mapping_version, mapping_hash = _masvs_mapping_fingerprint()
    mode = _identity_mode(base_apk_sha256=base_apk_sha256, version_code=version_code)
    has_contacts = "android.permission.READ_CONTACTS" in declared or "android.permission.WRITE_CONTACTS" in declared
    has_location = (
        "android.permission.ACCESS_FINE_LOCATION" in declared
        or "android.permission.ACCESS_COARSE_LOCATION" in declared
    )
    has_camera = "android.permission.CAMERA" in declared
    has_mic = "android.permission.RECORD_AUDIO" in declared
    has_storage_legacy = (
        "android.permission.READ_EXTERNAL_STORAGE" in declared
        or "android.permission.WRITE_EXTERNAL_STORAGE" in declared
        or bool(report.manifest_flags.request_legacy_external_storage)
    )
    has_internet = "android.permission.INTERNET" in declared

    return {
        "schema": "static_handoff_v1",
        "identity": {
            "package_name_lc": str(package_name or "").strip().lower(),
            "version_code": int(version_code) if version_code is not None else None,
            "base_apk_sha256": base_apk_sha256,
            "artifact_set_hash": artifact_set_hash,
            "identity_mode": mode,
            "identity_conflict_flag": False,
        },
        "permissions": {
            "dangerous_permission_count": len(dangerous),
            "has_contacts": has_contacts,
            "has_location": has_location,
            "has_camera": has_camera,
            "has_mic": has_mic,
            "has_storage_legacy": has_storage_legacy,
            "has_internet": has_internet,
            "unknown_permission_count": 0,
        },
        "masvs": {
            "masvs_network_status": statuses["NETWORK"],
            "masvs_platform_status": statuses["PLATFORM"],
            "masvs_privacy_status": statuses["PRIVACY"],
            "masvs_storage_status": statuses["STORAGE"],
            "masvs_pass_pct": round((pass_count / 4.0) * 100.0, 2),
            "masvs_mapping_version": mapping_version,
            "masvs_mapping_hash": mapping_hash,
        },
        "exposure_surface": {
            "exported_activity_count": len(report.exported_components.activities),
            "exported_service_count": len(report.exported_components.services),
            "exported_receiver_count": len(report.exported_components.receivers),
            "exported_provider_count": len(report.exported_components.providers),
            "exported_without_permission_count": int(ipc_metrics.get("exported_without_permission", 0) or 0),
            "unprotected_provider_count": int(provider_metrics.get("without_permissions", 0) or 0),
            "fileprovider_count": int(storage_metrics.get("fileproviders", 0) or 0),
        },
        "network_storage_policy": {
            "uses_cleartext_traffic": _as_bool(report.manifest_flags.uses_cleartext_traffic),
            "has_nsc": bool(report.manifest_flags.network_security_config),
            "nsc_cleartext_permitted": bool(nsc_metrics.get("cleartext_permitted", False)),
            "nsc_domain_override_count": int(nsc_metrics.get("cleartext_domain_count", 0) or 0),
            "request_legacy_external_storage": _as_bool(report.manifest_flags.request_legacy_external_storage),
            "allow_backup": _as_bool(report.manifest_flags.allow_backup),
        },
        "strings": {
            **string_counts,
            "endpoint_hints_top": hints,
            "secret_candidates_redacted": secrets,
        },
        "provenance": {
            "tool_semver": tool_semver,
            "tool_git_commit": tool_git_commit,
            "schema_version": schema_version,
            "static_run_id": int(static_run_id),
            "session_label": session_label,
        },
    }


def persist_static_handoff(*, static_run_id: int, handoff_payload: Mapping[str, object]) -> str:
    identity_patch: dict[str, object] = {}
    try:
        row = core_q.run_sql(
            """
            SELECT identity_mode, identity_conflict_flag
            FROM static_analysis_runs
            WHERE id=%s
            """,
            (int(static_run_id),),
            fetch="one",
        )
        if row:
            identity_patch = {
                "identity_mode": row[0] if row[0] else None,
                "identity_conflict_flag": bool(int(row[1] or 0)),
            }
    except Exception:
        identity_patch = {}

    base_payload = dict(handoff_payload)
    identity_value = base_payload.get("identity")
    if isinstance(identity_value, Mapping) and identity_patch:
        identity_copy = dict(identity_value)
        identity_copy.update({k: v for k, v in identity_patch.items() if v is not None})
        base_payload["identity"] = identity_copy

    canonical = json.dumps(base_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    handoff_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    out_dir = Path("evidence") / "static_runs" / str(static_run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "static_handoff.json"
    materialized = dict(base_payload)
    provenance = materialized.get("provenance")
    if isinstance(provenance, Mapping):
        provenance_dict = dict(provenance)
        provenance_dict["static_handoff_hash"] = handoff_hash
        materialized["provenance"] = provenance_dict
    out_path.write_text(json.dumps(materialized, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    return handoff_hash


__all__ = ["build_static_handoff", "persist_static_handoff"]
