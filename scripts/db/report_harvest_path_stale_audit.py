#!/usr/bin/env python3
"""Read-only audit of harvest path-stale behavior from artifact evidence.

Builds an artifact-first audit bundle over harvest receipts and package
manifests to measure stale-path frequency, replan outcomes, and whether a
runtime behavior change is justified.

Examples:

  PYTHONPATH=. python scripts/db/report_harvest_path_stale_audit.py
  PYTHONPATH=. python scripts/db/report_harvest_path_stale_audit.py --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

OUTCOME_CATEGORIES: tuple[str, ...] = (
    "path_stale_refreshed_and_retried",
    "path_stale_package_updated_since_inventory",
    "path_stale_package_paths_changed_since_inventory",
    "path_stale_blocked_before_pull",
    "path_stale_package_no_longer_accessible",
    "path_stale_replan_failed",
    "legacy_or_unknown_path_stale",
)

REPLAN_SUCCESS_OUTCOMES = {
    "path_stale_refreshed_and_retried",
    "path_stale_package_updated_since_inventory",
    "path_stale_package_paths_changed_since_inventory",
    "path_stale_blocked_before_pull",
}
PACKAGE_RECOVERED_OUTCOMES = {"path_stale_refreshed_and_retried"}
REPLAN_FAILED_OUTCOMES = {
    "path_stale_package_no_longer_accessible",
    "path_stale_replan_failed",
}
SNAPSHOT_AGE_BUCKETS: tuple[str, ...] = (
    "unknown",
    "0-15m",
    "15m-1h",
    "1h-6h",
    "6h-24h",
    "24h+",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/harvest_path_stale/<stamp>/.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _parse_dt(value: Any) -> datetime | None:
    text = _norm_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _repo_rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(_REPO_ROOT.resolve()))
    except Exception:
        return str(path)


def _resolve_repo_path(value: Any) -> Path | None:
    text = _norm_text(value)
    if not text:
        return None
    path = Path(text)
    if path.is_absolute():
        return path
    return _REPO_ROOT / text


def _receipt_paths(data_dir: Path) -> list[Path]:
    return sorted((data_dir / "receipts" / "harvest").rglob("*.json"))


def _manifest_paths(data_dir: Path) -> list[Path]:
    return sorted((data_dir / "device_apks").rglob("harvest_package_manifest.json"))


def _inventory_snapshot_index(data_dir: Path) -> dict[tuple[str, int], str]:
    index: dict[tuple[str, int], str] = {}
    for meta_path in sorted((data_dir / "state").glob("*/inventory/*.meta.json")):
        payload = _read_json(meta_path)
        if not isinstance(payload, Mapping):
            continue
        snapshot_id = _safe_int(payload.get("snapshot_id"))
        serial = meta_path.parents[1].name
        if snapshot_id is None or not serial:
            continue
        if meta_path.name.endswith(".meta.json"):
            json_name = meta_path.name[:-10] + ".json"
        else:
            json_name = meta_path.stem + ".json"
        json_path = meta_path.with_name(json_name)
        if json_path.exists():
            index[(serial, snapshot_id)] = _repo_rel(json_path) or str(json_path)
    return index


def _extract_session_id(payload: Mapping[str, Any], source_path: Path) -> str:
    package_block = payload.get("package")
    if isinstance(package_block, Mapping):
        session_label = _norm_text(package_block.get("session_label"))
        if session_label:
            return session_label
    if "receipts/harvest" in source_path.as_posix():
        return source_path.parent.name
    parts = source_path.parts
    if "runs" in parts:
        idx = parts.index("runs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return source_path.parent.name


def _has_path_stale_text(payload: Mapping[str, Any]) -> bool:
    try:
        text = json.dumps(payload).lower()
    except Exception:
        return False
    return "path_stale" in text or "path stale" in text


def _path_stale_outcome(payload: Mapping[str, Any]) -> str | None:
    execution = payload.get("execution")
    if isinstance(execution, Mapping):
        stale_replan = execution.get("stale_replan")
        if isinstance(stale_replan, Mapping):
            outcome = _norm_text(stale_replan.get("outcome"))
            if outcome in OUTCOME_CATEGORIES:
                return outcome
            if stale_replan.get("required") or stale_replan.get("details"):
                return "legacy_or_unknown_path_stale"
        for item in execution.get("errors") or []:
            if isinstance(item, Mapping):
                reason = _norm_text(item.get("reason"))
                if reason == "path_stale":
                    return "legacy_or_unknown_path_stale"
        for item in execution.get("runtime_skips") or []:
            if _norm_text(item) in {"path_stale", "path stale"}:
                return "legacy_or_unknown_path_stale"
    if _has_path_stale_text(payload):
        return "legacy_or_unknown_path_stale"
    return None


def _path_stale_reason(payload: Mapping[str, Any]) -> str | None:
    execution = payload.get("execution")
    if not isinstance(execution, Mapping):
        return None
    stale_replan = execution.get("stale_replan")
    if isinstance(stale_replan, Mapping):
        details = stale_replan.get("details")
        if isinstance(details, Mapping):
            drift_reasons = details.get("drift_reasons")
            if isinstance(drift_reasons, Sequence) and not isinstance(drift_reasons, (str, bytes)):
                joined = ", ".join(_norm_text(item) for item in drift_reasons if _norm_text(item))
                if joined:
                    return joined
            refreshed_skip = _norm_text(details.get("refreshed_skip_reason"))
            if refreshed_skip:
                return refreshed_skip
        outcome = _norm_text(stale_replan.get("outcome"))
        if outcome:
            return outcome
    for item in execution.get("errors") or []:
        if isinstance(item, Mapping):
            reason = _norm_text(item.get("reason"))
            if reason and reason != "path_stale":
                return reason
    return None


def _planned_base_path(payload: Mapping[str, Any]) -> str | None:
    planning = payload.get("planning")
    if isinstance(planning, Mapping):
        entries = planning.get("expected_artifacts")
        if isinstance(entries, Sequence):
            for entry in entries:
                if isinstance(entry, Mapping) and bool(entry.get("is_base")):
                    return _norm_text_or_none(entry.get("planned_source_path"))
            for entry in entries:
                if isinstance(entry, Mapping):
                    candidate = _norm_text_or_none(entry.get("planned_source_path"))
                    if candidate:
                        return candidate
    inventory = payload.get("inventory")
    if isinstance(inventory, Mapping):
        return _norm_text_or_none(inventory.get("primary_path"))
    return None


def _planned_split_count(payload: Mapping[str, Any]) -> int | None:
    inventory = payload.get("inventory")
    if isinstance(inventory, Mapping):
        split_count = _safe_int(inventory.get("split_count"))
        if split_count is not None:
            return split_count
        apk_paths = inventory.get("apk_paths")
        if isinstance(apk_paths, Sequence) and not isinstance(apk_paths, (str, bytes)):
            return len([item for item in apk_paths if _norm_text(item)])
    return None


def _refresh_details(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    execution = payload.get("execution")
    if not isinstance(execution, Mapping):
        return {}
    stale_replan = execution.get("stale_replan")
    if not isinstance(stale_replan, Mapping):
        return {}
    details = stale_replan.get("details")
    return details if isinstance(details, Mapping) else {}


def _split_shape(planned_split_count: int | None, refreshed_split_count: int | None) -> str:
    counts = [count for count in (planned_split_count, refreshed_split_count) if count is not None]
    if not counts:
        return "unknown"
    if max(counts) > 1:
        return "base_plus_splits"
    return "base_only"


def _snapshot_age_bucket(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "unknown"
    if seconds < 15 * 60:
        return "0-15m"
    if seconds < 60 * 60:
        return "15m-1h"
    if seconds < 6 * 60 * 60:
        return "1h-6h"
    if seconds < 24 * 60 * 60:
        return "6h-24h"
    return "24h+"


def _event_row(
    *,
    payload: Mapping[str, Any],
    source_kind: str,
    source_path: Path,
    inventory_index: Mapping[tuple[str, int], str],
) -> dict[str, Any] | None:
    outcome = _path_stale_outcome(payload)
    if outcome is None:
        return None

    package_block = payload.get("package") if isinstance(payload.get("package"), Mapping) else {}
    inventory_block = payload.get("inventory") if isinstance(payload.get("inventory"), Mapping) else {}
    status_block = payload.get("status") if isinstance(payload.get("status"), Mapping) else {}
    details = _refresh_details(payload)
    session_id = _extract_session_id(payload, source_path)
    device_serial = _norm_text_or_none(package_block.get("device_serial"))
    snapshot_id = _safe_int(package_block.get("snapshot_id"))
    generated_at = _parse_dt(payload.get("generated_at_utc"))
    snapshot_captured_at = _parse_dt(package_block.get("snapshot_captured_at"))
    snapshot_age_seconds = None
    if generated_at and snapshot_captured_at:
        snapshot_age_seconds = (generated_at - snapshot_captured_at).total_seconds()

    version_code_before = _norm_text_or_none(package_block.get("version_code"))
    version_name_before = _norm_text_or_none(package_block.get("version_name"))
    version_code_after = _norm_text_or_none(details.get("refreshed_version_code"))
    version_name_after = _norm_text_or_none(details.get("refreshed_version_name"))
    planned_base_path = _planned_base_path(payload)
    refreshed_base_path = _norm_text_or_none(details.get("refreshed_primary_path"))
    planned_split_count = _planned_split_count(payload)
    refreshed_split_count = _safe_int(details.get("refreshed_split_count"))
    refreshed_apk_paths = details.get("refreshed_apk_paths")
    drift_reasons = details.get("drift_reasons")
    drift_list = []
    if isinstance(drift_reasons, Sequence) and not isinstance(drift_reasons, (str, bytes)):
        drift_list = [_norm_text(item) for item in drift_reasons if _norm_text(item)]

    path_set_changed = bool(
        outcome == "path_stale_package_paths_changed_since_inventory"
        or "artifact_set_changed" in drift_list
        or (
            isinstance(refreshed_apk_paths, Sequence)
            and not isinstance(refreshed_apk_paths, (str, bytes))
            and set(_norm_text(item) for item in refreshed_apk_paths if _norm_text(item))
            != set(_norm_text(item) for item in inventory_block.get("apk_paths", []) if _norm_text(item))
        )
    )
    version_code_changed = bool(
        outcome == "path_stale_package_updated_since_inventory"
        or "version_code_changed" in drift_list
        or (
            version_code_before is not None
            and version_code_after is not None
            and version_code_before != version_code_after
        )
    )
    version_name_changed = bool(
        version_name_before is not None
        and version_name_after is not None
        and version_name_before != version_name_after
    )

    receipt_path = source_path if source_kind == "receipt" else _resolve_repo_path(payload.get("paths", {}).get("receipt_path"))
    manifest_path = source_path if source_kind == "manifest" else _resolve_repo_path(payload.get("paths", {}).get("legacy_manifest_path"))
    inventory_snapshot_path = None
    if device_serial and snapshot_id is not None:
        inventory_snapshot_path = inventory_index.get((device_serial, snapshot_id))

    return {
        "harvest_session_id": session_id,
        "device_serial": device_serial,
        "package_name": _norm_text_or_none(package_block.get("package_name")),
        "display_name": _norm_text_or_none(package_block.get("app_label")),
        "receipt_path": _repo_rel(receipt_path),
        "manifest_path": _repo_rel(manifest_path),
        "inventory_snapshot_path": inventory_snapshot_path,
        "inventory_snapshot_age_seconds": round(snapshot_age_seconds, 3) if snapshot_age_seconds is not None else None,
        "version_code_before": version_code_before,
        "version_code_after": version_code_after,
        "version_name_before": version_name_before,
        "version_name_after": version_name_after,
        "planned_base_path": planned_base_path,
        "refreshed_base_path": refreshed_base_path,
        "planned_split_count": planned_split_count,
        "refreshed_split_count": refreshed_split_count,
        "path_set_changed": int(path_set_changed),
        "version_code_changed": int(version_code_changed),
        "version_name_changed": int(version_name_changed),
        "split_apk_package": int(_split_shape(planned_split_count, refreshed_split_count) == "base_plus_splits"),
        "package_shape": _split_shape(planned_split_count, refreshed_split_count),
        "stale_replan_outcome": outcome,
        "stale_replan_reason": _path_stale_reason(payload),
        "replan_attempted": 1,
        "replan_success": int(outcome in REPLAN_SUCCESS_OUTCOMES),
        "replan_failed": int(outcome in REPLAN_FAILED_OUTCOMES),
        "package_recovered_after_replan": int(outcome in PACKAGE_RECOVERED_OUTCOMES),
        "final_package_status": _norm_text_or_none(status_block.get("capture_status")),
    }


def _record_summary_row(
    *,
    payload: Mapping[str, Any],
    source_kind: str,
    source_path: Path,
) -> dict[str, Any]:
    package_block = payload.get("package") if isinstance(payload.get("package"), Mapping) else {}
    planning = payload.get("planning") if isinstance(payload.get("planning"), Mapping) else {}
    status_block = payload.get("status") if isinstance(payload.get("status"), Mapping) else {}
    inventory = payload.get("inventory") if isinstance(payload.get("inventory"), Mapping) else {}
    session_id = _extract_session_id(payload, source_path)
    generated_at = _parse_dt(payload.get("generated_at_utc"))
    snapshot_captured_at = _parse_dt(package_block.get("snapshot_captured_at"))
    snapshot_age_seconds = None
    if generated_at and snapshot_captured_at:
        snapshot_age_seconds = (generated_at - snapshot_captured_at).total_seconds()
    planned_split_count = _planned_split_count(payload)
    return {
        "source_kind": source_kind,
        "source_path": _repo_rel(source_path),
        "harvest_session_id": session_id,
        "device_serial": _norm_text_or_none(package_block.get("device_serial")),
        "package_name": _norm_text_or_none(package_block.get("package_name")),
        "display_name": _norm_text_or_none(package_block.get("app_label")),
        "generated_at": generated_at.isoformat().replace("+00:00", "Z") if generated_at else None,
        "snapshot_age_seconds": snapshot_age_seconds,
        "preflight_reason": _norm_text_or_none(planning.get("preflight_reason")),
        "capture_status": _norm_text_or_none(status_block.get("capture_status")),
        "planned_split_count": planned_split_count,
        "package_shape": _split_shape(planned_split_count, None),
        "event_outcome": _path_stale_outcome(payload),
        "research_status": _norm_text_or_none(status_block.get("research_status")),
        "path_stale_known": int(_path_stale_outcome(payload) is not None),
        "observed_artifact_count": len((payload.get("execution") or {}).get("observed_artifacts") or []),
        "snapshot_id": _safe_int(package_block.get("snapshot_id")),
        "version_code": _norm_text_or_none(package_block.get("version_code")),
        "version_name": _norm_text_or_none(package_block.get("version_name")),
        "apk_paths_count": len([item for item in inventory.get("apk_paths", []) if _norm_text(item)]),
    }


def _load_source_payloads(data_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    payloads: dict[tuple[str, str], dict[str, Any]] = {}

    for receipt_path in _receipt_paths(data_dir):
        payload = _read_json(receipt_path)
        if payload is None:
            warnings.append(f"malformed_receipt:{_repo_rel(receipt_path)}")
            continue
        row = _record_summary_row(payload=payload, source_kind="receipt", source_path=receipt_path)
        key = (row["harvest_session_id"] or "", row["package_name"] or "")
        payloads[key] = {
            "payload": payload,
            "source_kind": "receipt",
            "source_path": receipt_path,
            "summary": row,
        }

    for manifest_path in _manifest_paths(data_dir):
        payload = _read_json(manifest_path)
        if payload is None:
            warnings.append(f"malformed_manifest:{_repo_rel(manifest_path)}")
            continue
        row = _record_summary_row(payload=payload, source_kind="manifest", source_path=manifest_path)
        key = (row["harvest_session_id"] or "", row["package_name"] or "")
        payloads.setdefault(
            key,
            {
                "payload": payload,
                "source_kind": "manifest",
                "source_path": manifest_path,
                "summary": row,
            },
        )

    return list(payloads.values()), sorted(set(warnings))


def _build_recommendation(
    *,
    records: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    package_rows: Sequence[Mapping[str, Any]],
    age_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    total_events = len(events)
    total_scanned = len(records)
    if total_events < 3:
        return {
            "recommended_action": "collect_more_live_harvest_evidence",
            "rationale": "Too few path-stale events were observed to justify a runtime behavior change.",
        }

    event_rate = total_events / max(total_scanned, 1)
    resolved_count = sum(int(row.get("replan_success") or 0) for row in events)
    resolved_rate = resolved_count / max(total_events, 1)
    package_counts = sorted(
        (int(row.get("event_count") or 0) for row in package_rows),
        reverse=True,
    )
    top_package_share = sum(package_counts[:3]) / max(total_events, 1)

    bucket_map = {str(row.get("snapshot_age_bucket")): row for row in age_rows}
    old_bucket = bucket_map.get("24h+") or {}
    fresh_bucket = bucket_map.get("0-15m") or {}
    old_events = int(old_bucket.get("path_stale_events") or 0)
    fresh_events = int(fresh_bucket.get("path_stale_events") or 0)
    old_rate = float(old_bucket.get("path_stale_rate") or 0.0)
    fresh_rate = float(fresh_bucket.get("path_stale_rate") or 0.0)

    if top_package_share >= 0.5:
        return {
            "recommended_action": "investigate_specific_packages",
            "rationale": "Path-stale events cluster around a small set of packages more than they indicate a broad policy problem.",
            "top_package_share": round(top_package_share, 4),
        }
    if old_events >= 2 and old_rate > 0 and fresh_rate > 0 and old_rate >= fresh_rate * 2:
        return {
            "recommended_action": "tighten_inventory_snapshot_age_warning",
            "rationale": "Older inventory snapshots show a materially higher path-stale rate than fresher snapshots.",
            "old_snapshot_rate": round(old_rate, 4),
            "fresh_snapshot_rate": round(fresh_rate, 4),
        }
    if event_rate >= 0.05 and resolved_rate >= 0.7:
        return {
            "recommended_action": "add_selective_pre_pull_refresh",
            "rationale": "Path-stale events are common enough to matter and lazy replan usually resolves them, suggesting selective pre-pull refresh may be worth the extra adb cost.",
            "event_rate": round(event_rate, 4),
            "resolved_rate": round(resolved_rate, 4),
        }
    if event_rate <= 0.02 and resolved_rate >= 0.7:
        return {
            "recommended_action": "keep_lazy_replan_only",
            "rationale": "Path-stale events are relatively rare and current lazy replan behavior usually resolves them.",
            "event_rate": round(event_rate, 4),
            "resolved_rate": round(resolved_rate, 4),
        }
    return {
        "recommended_action": "collect_more_live_harvest_evidence",
        "rationale": "Current evidence is mixed and does not yet justify a new runtime behavior policy.",
        "event_rate": round(event_rate, 4),
        "resolved_rate": round(resolved_rate, 4),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    data_dir = _REPO_ROOT / "data"
    output_root = _REPO_ROOT / "output"
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    audit_output_dir = Path(args.output_dir) if args.output_dir else output_root / "audit" / "harvest_path_stale" / stamp
    audit_output_dir.mkdir(parents=True, exist_ok=True)

    _log(args.verbose, f"[harvest-path-stale] scanning receipts under {data_dir / 'receipts' / 'harvest'}")
    source_payloads, warnings = _load_source_payloads(data_dir)
    inventory_index = _inventory_snapshot_index(data_dir)
    _log(args.verbose, f"[harvest-path-stale] package_records={len(source_payloads)}")

    record_rows = [item["summary"] for item in source_payloads]
    event_rows: list[dict[str, Any]] = []
    limitations: list[str] = []
    for item in source_payloads:
        event_row = _event_row(
            payload=item["payload"],
            source_kind=item["source_kind"],
            source_path=item["source_path"],
            inventory_index=inventory_index,
        )
        if event_row is not None:
            event_rows.append(event_row)

    if not event_rows:
        limitations.append("no_path_stale_events_detected_in_scanned_artifacts")

    package_counter: dict[str, Counter[str]] = defaultdict(Counter)
    package_sessions: dict[str, set[str]] = defaultdict(set)
    package_display: dict[str, str | None] = {}
    package_event_details: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in event_rows:
        package_name = _norm_text(row.get("package_name")).lower()
        if not package_name:
            continue
        outcome = _norm_text(row.get("stale_replan_outcome")) or "legacy_or_unknown_path_stale"
        package_counter[package_name][outcome] += 1
        package_sessions[package_name].add(_norm_text(row.get("harvest_session_id")))
        package_display.setdefault(package_name, _norm_text_or_none(row.get("display_name")))
        package_event_details[package_name].append(row)

    package_rows: list[dict[str, Any]] = []
    for package_name, counter in sorted(package_counter.items(), key=lambda item: (-sum(item[1].values()), item[0])):
        rows = package_event_details[package_name]
        recommendations = []
        if any(_norm_text(row.get("stale_replan_outcome")) in REPLAN_FAILED_OUTCOMES for row in rows):
            recommendations.append("inspect failing receipts/manifests")
        if len(rows) > 1:
            recommendations.append("repeat stale-path package")
        package_rows.append(
            {
                "package_name": package_name,
                "display_name": package_display.get(package_name),
                "event_count": sum(counter.values()),
                "session_count": len(package_sessions[package_name]),
                "first_seen_session": min(package_sessions[package_name]) if package_sessions[package_name] else None,
                "last_seen_session": max(package_sessions[package_name]) if package_sessions[package_name] else None,
                "outcome_distribution": json.dumps(dict(sorted(counter.items())), sort_keys=True),
                "replan_success_count": sum(int(row.get("replan_success") or 0) for row in rows),
                "replan_failed_count": sum(int(row.get("replan_failed") or 0) for row in rows),
                "path_set_changed_count": sum(int(row.get("path_set_changed") or 0) for row in rows),
                "version_changed_count": sum(int(row.get("version_code_changed") or 0) for row in rows),
                "split_apk_involved": int(any(int(row.get("split_apk_package") or 0) for row in rows)),
                "recommendation": "; ".join(recommendations) or "observe",
            }
        )

    session_groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in record_rows:
        session_groups[_norm_text(row.get("harvest_session_id"))].append(row)
    event_groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in event_rows:
        event_groups[_norm_text(row.get("harvest_session_id"))].append(row)

    session_rows: list[dict[str, Any]] = []
    for session_id, rows in sorted(session_groups.items()):
        attempted = sum(1 for row in rows if not _norm_text(row.get("preflight_reason")))
        harvested = sum(1 for row in rows if int(row.get("observed_artifact_count") or 0) > 0)
        event_list = event_groups.get(session_id, [])
        ages = [float(row.get("snapshot_age_seconds")) for row in rows if row.get("snapshot_age_seconds") is not None]
        notes = []
        if event_list and not ages:
            notes.append("snapshot_age_unknown_for_stale_events")
        session_rows.append(
            {
                "harvest_session_id": session_id,
                "device_serial": next((row.get("device_serial") for row in rows if row.get("device_serial")), None),
                "session_started_at": next((row.get("generated_at") for row in rows if row.get("generated_at")), None),
                "packages_reviewed": len(rows),
                "packages_attempted": attempted,
                "packages_harvested": harvested,
                "path_stale_count": len(event_list),
                "replan_success_count": sum(int(row.get("replan_success") or 0) for row in event_list),
                "replan_failed_count": sum(int(row.get("replan_failed") or 0) for row in event_list),
                "stale_rate_per_attempted": round(len(event_list) / attempted, 6) if attempted else None,
                "inventory_snapshot_age_seconds": round(sum(ages) / len(ages), 3) if ages else None,
                "notes": "; ".join(notes) or None,
            }
        )

    outcome_rows = []
    outcome_counter = Counter(_norm_text(row.get("stale_replan_outcome")) or "legacy_or_unknown_path_stale" for row in event_rows)
    for outcome in OUTCOME_CATEGORIES:
        count = outcome_counter.get(outcome, 0)
        if outcome in PACKAGE_RECOVERED_OUTCOMES:
            follow = "keep lazy replan and watch frequency"
            interp = "artifact pull recovered after targeted refresh"
        elif outcome in REPLAN_FAILED_OUTCOMES:
            follow = "inspect receipts/manifests for failure context"
            interp = "targeted refresh did not resolve package access"
        elif outcome == "path_stale_blocked_before_pull":
            follow = "check policy vs refreshed package location"
            interp = "refresh succeeded but package became blocked before pull"
        elif outcome == "legacy_or_unknown_path_stale":
            follow = "collect newer artifacts before behavior changes"
            interp = "older or incomplete evidence cannot classify the exact outcome"
        else:
            follow = "correlate with snapshot age and package updates"
            interp = "refresh succeeded but package state drifted from inventory"
        outcome_rows.append(
            {
                "outcome": outcome,
                "count": count,
                "percent_of_path_stale": round(count / len(event_rows), 6) if event_rows else 0.0,
                "interpretation": interp,
                "suggested_follow_up": follow,
            }
        )

    age_group_all: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    age_group_events: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in record_rows:
        age_group_all[_snapshot_age_bucket(row.get("snapshot_age_seconds"))].append(row)
    for row in event_rows:
        age_group_events[_snapshot_age_bucket(row.get("inventory_snapshot_age_seconds"))].append(row)
    snapshot_age_rows = []
    for bucket in SNAPSHOT_AGE_BUCKETS:
        all_rows = age_group_all.get(bucket, [])
        stale_rows = age_group_events.get(bucket, [])
        success_count = sum(int(row.get("replan_success") or 0) for row in stale_rows)
        snapshot_age_rows.append(
            {
                "snapshot_age_bucket": bucket,
                "package_receipts_scanned": len(all_rows),
                "path_stale_events": len(stale_rows),
                "path_stale_rate": round(len(stale_rows) / len(all_rows), 6) if all_rows else None,
                "replan_success_rate": round(success_count / len(stale_rows), 6) if stale_rows else None,
                "notes": None,
            }
        )

    shape_all: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    shape_events: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in record_rows:
        shape_all[_norm_text(row.get("package_shape")) or "unknown"].append(row)
    for row in event_rows:
        shape_events[_norm_text(row.get("package_shape")) or "unknown"].append(row)
    split_rows = []
    for shape in ("base_only", "base_plus_splits", "unknown"):
        all_rows = shape_all.get(shape, [])
        stale_rows = shape_events.get(shape, [])
        split_rows.append(
            {
                "package_shape": shape,
                "packages_scanned": len(all_rows),
                "path_stale_events": len(stale_rows),
                "path_stale_rate": round(len(stale_rows) / len(all_rows), 6) if all_rows else None,
                "replan_success_rate": round(
                    sum(int(row.get("replan_success") or 0) for row in stale_rows) / len(stale_rows),
                    6,
                )
                if stale_rows
                else None,
                "path_set_changed_count": sum(int(row.get("path_set_changed") or 0) for row in stale_rows),
                "notes": None,
            }
        )

    recommendation = _build_recommendation(
        records=record_rows,
        events=event_rows,
        package_rows=package_rows,
        age_rows=snapshot_age_rows,
    )

    summary = {
        "report_type": "harvest_path_stale_audit",
        "generated_at": datetime.now(UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "data_root": str(data_dir),
        "output_dir": str(audit_output_dir),
        "harvest_session_count": len(session_groups),
        "package_record_count": len(record_rows),
        "path_stale_event_count": len(event_rows),
        "packages_with_path_stale": len(package_rows),
        "repeated_path_stale_packages": sum(1 for row in package_rows if int(row.get("event_count") or 0) > 1),
        "replan_success_count": sum(int(row.get("replan_success") or 0) for row in event_rows),
        "replan_failed_count": sum(int(row.get("replan_failed") or 0) for row in event_rows),
        "package_recovered_after_replan_count": sum(int(row.get("package_recovered_after_replan") or 0) for row in event_rows),
        "path_set_changed_count": sum(int(row.get("path_set_changed") or 0) for row in event_rows),
        "version_code_changed_count": sum(int(row.get("version_code_changed") or 0) for row in event_rows),
        "version_name_changed_count": sum(int(row.get("version_name_changed") or 0) for row in event_rows),
        "split_apk_path_stale_count": sum(int(row.get("split_apk_package") or 0) for row in event_rows),
        "outcome_counts": dict(sorted(outcome_counter.items())),
        "warnings": warnings,
        "limitations": limitations,
        "no_db_writes": True,
        "artifact_first": True,
        "output_files": [
            "summary.json",
            "path_stale_events.csv",
            "path_stale_by_package.csv",
            "path_stale_by_session.csv",
            "replan_outcome_summary.csv",
            "snapshot_age_summary.csv",
            "split_apk_path_stale_summary.csv",
            "recommended_next_action.json",
        ],
    }

    _write_csv(audit_output_dir / "path_stale_events.csv", event_rows)
    _write_csv(audit_output_dir / "path_stale_by_package.csv", package_rows)
    _write_csv(audit_output_dir / "path_stale_by_session.csv", session_rows)
    _write_csv(audit_output_dir / "replan_outcome_summary.csv", outcome_rows)
    _write_csv(audit_output_dir / "snapshot_age_summary.csv", snapshot_age_rows)
    _write_csv(audit_output_dir / "split_apk_path_stale_summary.csv", split_rows)
    _write_json(audit_output_dir / "recommended_next_action.json", recommendation)
    _write_json(audit_output_dir / "summary.json", summary)

    if args.verbose:
        sys.stderr.write(
            f"[harvest-path-stale] output_dir={audit_output_dir}\n"
            f"[harvest-path-stale] sessions={len(session_groups)} package_records={len(record_rows)} path_stale_events={len(event_rows)}\n"
        )
    print(audit_output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
