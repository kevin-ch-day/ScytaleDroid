#!/usr/bin/env python3
"""Read-only PCAP observer audit across dynamic evidence packs.

This report focuses on observer-side capture reliability signals from
``artifacts/pcapdroid_capture/pcapdroid_capture_meta.json`` and related local
PCAP artifacts. It does not modify DB rows, evidence packs, or capture inputs.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/pcap_observer_audit/<timestamp>/.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print the summary JSON to stdout after writing outputs.",
    )
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    return _REPO_ROOT / "output" / "audit" / "pcap_observer_audit" / stamp


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0


def _observer_case(row: dict[str, Any]) -> str:
    detail = _norm_text(row.get("pcap_failure_detail"))
    status_error = _norm_text(row.get("status_check_error")).lower()
    expected_exists = row.get("expected_device_path_exists")
    delayed_expected_exists = row.get("delayed_expected_device_path_exists")
    expected_size = _safe_int(row.get("expected_device_path_size_bytes"))
    delayed_expected_size = _safe_int(row.get("delayed_expected_device_path_size_bytes"))
    latest_fallback_path = _norm_text(row.get("latest_fallback_path"))
    delayed_latest_fallback_path = _norm_text(row.get("delayed_latest_fallback_path"))

    if detail == "" and bool(row.get("valid_dataset_run")):
        return "valid_capture"
    if delayed_expected_exists is True and delayed_expected_size <= 0:
        return "late_empty_named_file"
    if expected_exists is True and expected_size <= 0:
        return "empty_named_file_at_stop"
    if detail == "PCAP_PULL_FAILED":
        return "pull_failed_after_device_capture"
    if detail == "PCAP_LOCAL_FILE_EMPTY":
        return "local_empty_after_pull"
    if detail == "PCAP_LOCAL_FILE_MISSING":
        return "local_missing_after_pull"
    if (
        expected_exists is False
        and not latest_fallback_path
        and delayed_expected_exists is not True
        and not delayed_latest_fallback_path
    ):
        return "device_missing_at_stop"
    if "status unavailable" in status_error:
        return "status_unavailable"
    if detail:
        return f"other_{detail.lower()}"
    return "observer_meta_no_issue"


def _observer_notes(row: dict[str, Any]) -> str:
    notes: list[str] = []
    status_error = _norm_text(row.get("status_check_error"))
    status_source = _norm_text(row.get("status_check_source"))
    if status_error:
        notes.append(f"status={status_error}")
    elif status_source == "unavailable":
        notes.append("status_probe_unavailable")
    if row.get("expected_device_path_exists") is False and row.get("delayed_expected_device_path_exists") is True:
        delayed_size = _safe_int(row.get("delayed_expected_device_path_size_bytes"))
        if delayed_size <= 0:
            notes.append("named_file_appeared_late_empty")
        else:
            notes.append("named_file_appeared_late_nonempty")
    elif row.get("expected_device_path_exists") is False and not _norm_text(row.get("latest_fallback_path")):
        notes.append("named_file_not_visible_at_stop")
    return ";".join(notes)


def _row_for_run(run_dir: Path) -> dict[str, Any] | None:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import dataset_pcap_failure_detail

    manifest = _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, dict):
        return None
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    meta = _read_json(capture_dir / "pcapdroid_capture_meta.json") or {}
    diagnostics = meta.get("failure_diagnostics") if isinstance(meta.get("failure_diagnostics"), dict) else {}
    status = meta.get("status_check") if isinstance(meta.get("status_check"), dict) else {}
    local_pcaps = sorted(path for path in capture_dir.glob("*.pcap*") if path.is_file())
    local_sizes = []
    for path in local_pcaps:
        try:
            local_sizes.append(int(path.stat().st_size))
        except OSError:
            continue
    pcap_size_bytes = _safe_int(dataset.get("pcap_size_bytes") or meta.get("pcap_size_bytes"))
    raw_detail = _norm_text(dataset.get("pcap_failure_detail"))
    if not raw_detail and (_norm_text(dataset.get("invalid_reason_code")).startswith("PCAP_") or pcap_size_bytes <= 0):
        raw_detail = _norm_text(dataset_pcap_failure_detail(run_dir, pcap_size_int=pcap_size_bytes))

    row = {
        "run_id": _norm_text(manifest.get("dynamic_run_id") or run_dir.name),
        "package": _norm_text(target.get("package_name")),
        "app_label": _norm_text(target.get("display_name")),
        "run_profile": _norm_text(operator.get("run_profile")),
        "ended_at": _norm_text(manifest.get("ended_at")),
        "valid_dataset_run": bool(dataset.get("valid_dataset_run") is True),
        "invalid_reason_code": _norm_text(dataset.get("invalid_reason_code")),
        "pcap_failure_detail": raw_detail,
        "pcap_size_bytes": pcap_size_bytes,
        "local_pcap_count": len(local_pcaps),
        "local_max_pcap_size_bytes": max(local_sizes) if local_sizes else 0,
        "pcap_valid": bool(meta.get("pcap_valid") is True),
        "status_check_ok": status.get("ok"),
        "status_check_error": _norm_text(status.get("error")),
        "status_check_source": _norm_text(status.get("source")),
        "expected_device_path": _norm_text(diagnostics.get("expected_device_path")),
        "expected_device_path_exists": diagnostics.get("expected_device_path_exists"),
        "expected_device_path_size_bytes": diagnostics.get("expected_device_path_size_bytes"),
        "latest_fallback_path": _norm_text(diagnostics.get("latest_fallback_path")),
        "latest_fallback_exists": diagnostics.get("latest_fallback_exists"),
        "latest_fallback_size_bytes": diagnostics.get("latest_fallback_size_bytes"),
        "delayed_expected_device_path_exists": diagnostics.get("delayed_expected_device_path_exists"),
        "delayed_expected_device_path_size_bytes": diagnostics.get("delayed_expected_device_path_size_bytes"),
        "delayed_latest_fallback_path": _norm_text(diagnostics.get("delayed_latest_fallback_path")),
        "delayed_latest_fallback_exists": diagnostics.get("delayed_latest_fallback_exists"),
        "delayed_latest_fallback_size_bytes": diagnostics.get("delayed_latest_fallback_size_bytes"),
    }
    row["observer_case"] = _observer_case(row)
    row["observer_notes"] = _observer_notes(row)
    return row


def _classify_run_dirs(root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    completed: list[Path] = []
    in_progress: list[Path] = []
    ghost: list[Path] = []
    if not root.exists():
        return completed, in_progress, ghost
    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        manifest_path = run_dir / "run_manifest.json"
        if manifest_path.exists():
            completed.append(run_dir)
            continue
        if (run_dir / "notes" / ".scytaledroid_in_progress").exists():
            in_progress.append(run_dir)
        else:
            ghost.append(run_dir)
    return completed, in_progress, ghost


def generate_report(*, output_dir: Path | None = None, dynamic_root: Path | None = None) -> dict[str, Any]:
    root = dynamic_root or _dynamic_root()
    out_dir = Path(output_dir) if output_dir is not None else _default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    completed_run_dirs, in_progress_run_dirs, ghost_run_dirs = _classify_run_dirs(root)
    for run_dir in completed_run_dirs:
        row = _row_for_run(run_dir)
        if row is not None:
            rows.append(row)

    invalid_rows = [row for row in rows if _norm_text(row.get("invalid_reason_code")).startswith("PCAP_")]
    case_counts = Counter(str(row.get("observer_case") or "") for row in invalid_rows)
    status_error_counts = Counter(
        _norm_text(row.get("status_check_error"))
        for row in rows
        if _norm_text(row.get("status_check_error"))
    )
    status_source_counts = Counter(
        _norm_text(row.get("status_check_source")) or "unspecified"
        for row in rows
    )
    pcap_failure_detail_counts = Counter(
        _norm_text(row.get("pcap_failure_detail"))
        for row in invalid_rows
        if _norm_text(row.get("pcap_failure_detail"))
    )

    rows_sorted = sorted(
        rows,
        key=lambda row: (
            str(row.get("valid_dataset_run") is not True),
            str(row.get("observer_case") or ""),
            str(row.get("ended_at") or ""),
            str(row.get("run_id") or ""),
        ),
    )
    _write_csv(out_dir / "pcap_observer_audit.csv", rows_sorted)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "dynamic_evidence_root": str(root.resolve()),
        "run_dir_counts": {
            "completed": len(completed_run_dirs),
            "in_progress": len(in_progress_run_dirs),
            "ghost": len(ghost_run_dirs),
            "all_dirs_seen": len(completed_run_dirs) + len(in_progress_run_dirs) + len(ghost_run_dirs),
        },
        "runs_scanned": len(rows),
        "runs_with_pcap_meta": sum(1 for row in rows if row.get("status_check_ok") is not None or row.get("status_check_error") or row.get("expected_device_path")),
        "invalid_pcap_runs": len(invalid_rows),
        "observer_case_counts": dict(sorted(case_counts.items())),
        "status_error_counts": dict(sorted(status_error_counts.items())),
        "status_source_counts": dict(sorted(status_source_counts.items())),
        "pcap_failure_detail_counts": dict(sorted(pcap_failure_detail_counts.items())),
        "output_files": {
            "pcap_observer_audit_csv": str((out_dir / "pcap_observer_audit.csv").resolve()),
            "summary_json": str((out_dir / "summary.json").resolve()),
        },
        "no_db_writes": True,
        "notes": {
            "in_progress_run_dirs_skipped": [path.name for path in in_progress_run_dirs],
            "ghost_run_dirs_skipped": [path.name for path in ghost_run_dirs],
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir)
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
