#!/usr/bin/env python3
"""Repair stale dynamic dataset validity and policy-derived manifest fields.

This intentionally does not relax validity or quota policy. It supports two
bounded repairs sourced from existing evidence and tracker truth:

1. Re-run the existing dataset artifact validator and update manifests whose
   current dataset state is invalid while the current artifacts now validate as
   usable.
2. Sync stale policy-derived manifest fields (for example ``countable``,
   ``baseline_not_idle``, ``exploratory_class``) from the current tracker row
   when queue/tracker truth already differs from the local evidence-pack
   manifest.

Apply mode refreshes derived tracker truth before candidate selection so stale
tracker state does not hide newly repairable runs.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    _REPO_ROOT = Path(__file__).resolve().parents[2]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))


REPAIRABLE_INVALID_REASONS = {"PCAP_MISSING", "PCAP_TOO_SMALL", "PCAP_PARSE_ERROR"}
SYNCABLE_TRACKER_FIELDS = (
    "valid_dataset_run",
    "invalid_reason_code",
    "sampling_duration_seconds",
    "actual_sampling_seconds",
    "actual_sampling_seconds_source",
    "min_pcap_bytes",
    "netstats_observed_bytes",
    "pcap_available",
    "pcap_size_bytes",
    "pcap_failure_detail",
    "pcap_failure_summary",
    "timeline_available",
    "timeline_complete",
    "window_count_original",
    "window_count_final",
    "window_count_source",
    "window_count",
    "min_window_count",
    "short_run",
    "no_traffic_observed",
    "countable",
    "counts_toward_quota",
    "extra_run",
    "low_signal",
    "low_signal_reasons",
    "baseline_not_idle",
    "baseline_not_idle_reasons",
    "exploratory_class",
    "paper_eligible",
    "paper_exclusion_primary_reason_code",
    "paper_exclusion_all_reason_codes",
    "technical_validity",
    "protocol_compliance",
    "cohort_eligibility",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root; defaults to data/evidence/dynamic.")
    parser.add_argument("--output-dir", default=None, help="Directory for repair plan outputs.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict to one or more dynamic run IDs.")
    parser.add_argument(
        "--refresh-tracker",
        action="store_true",
        help=(
            "Recompute derived dataset tracker truth before candidate selection. "
            "Dry-run only uses this when explicitly requested; --apply refreshes automatically."
        ),
    )
    parser.add_argument("--apply", action="store_true", help="Update candidate run_manifest.json files and refresh tracker state.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON after writing outputs.")
    return parser


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-%f")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_dataset_validity_repair" / stamp


def _default_evidence_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _manifest_from_raw(raw: Mapping[str, Any], run_dir: Path):
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest

    manifest = RunManifest(
        run_manifest_version=int(raw.get("run_manifest_version") or 1),
        dynamic_run_id=str(raw.get("dynamic_run_id") or run_dir.name),
        created_at=str(raw.get("created_at") or ""),
        batch_id=raw.get("batch_id"),
        started_at=raw.get("started_at"),
        ended_at=raw.get("ended_at"),
        status=str(raw.get("status") or "unknown"),
        dataset=dict(raw.get("dataset") or {}) if isinstance(raw.get("dataset"), dict) else {},
        target=dict(raw.get("target") or {}) if isinstance(raw.get("target"), dict) else {},
        environment=dict(raw.get("environment") or {}) if isinstance(raw.get("environment"), dict) else {},
        scenario=dict(raw.get("scenario") or {}) if isinstance(raw.get("scenario"), dict) else {},
        operator=dict(raw.get("operator") or {}) if isinstance(raw.get("operator"), dict) else {},
    )
    manifest.artifacts = [
        ArtifactRecord(
            relative_path=str(item.get("relative_path") or ""),
            type=str(item.get("type") or ""),
            produced_by=str(item.get("produced_by") or ""),
            sha256=str(item.get("sha256")) if isinstance(item.get("sha256"), str) and item.get("sha256") else None,
            size_bytes=item.get("size_bytes"),
            origin=item.get("origin"),
            device_path=item.get("device_path"),
            pull_status=item.get("pull_status"),
        )
        for item in (raw.get("artifacts") or [])
        if isinstance(item, Mapping)
    ]
    return manifest


def _candidate_row(run_dir: Path) -> dict[str, Any] | None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, evaluate_dataset_validity

    manifest_path = run_dir / "run_manifest.json"
    raw = _read_json(manifest_path)
    if not isinstance(raw, dict):
        return None
    dataset = raw.get("dataset") if isinstance(raw.get("dataset"), dict) else {}
    operator = raw.get("operator") if isinstance(raw.get("operator"), dict) else {}
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    current_valid = dataset.get("valid_dataset_run") is True
    current_reason = str(dataset.get("invalid_reason_code") or "").strip().upper()
    manifest = _manifest_from_raw(raw, run_dir)
    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())
    new_valid = validity.get("valid_dataset_run") is True
    if current_valid or not new_valid:
        return None
    if current_reason and current_reason not in REPAIRABLE_INVALID_REASONS:
        return None
    return {
        "repair_type": "validity_repair",
        "run_id": run_dir.name,
        "package": str(target.get("package_name") or ""),
        "run_profile": str(dataset.get("run_profile") or operator.get("run_profile") or ""),
        "messaging_activity": str(operator.get("messaging_activity") or ""),
        "current_valid_dataset_run": int(current_valid),
        "current_invalid_reason_code": current_reason,
        "new_valid_dataset_run": int(new_valid),
        "new_invalid_reason_code": validity.get("invalid_reason_code"),
        "current_pcap_size_bytes": dataset.get("pcap_size_bytes"),
        "new_pcap_size_bytes": validity.get("pcap_size_bytes"),
        "new_min_pcap_bytes": validity.get("min_pcap_bytes"),
        "new_window_count": validity.get("window_count"),
        "new_min_window_count": validity.get("min_window_count"),
        "new_actual_sampling_seconds": validity.get("actual_sampling_seconds"),
        "new_sampling_duration_seconds": validity.get("sampling_duration_seconds"),
        "counts_toward_completion": int(operator.get("counts_toward_completion") is True),
        "_validity": validity,
    }


def _load_tracker_by_run() -> dict[str, Mapping[str, Any]]:
    from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_plan_read_path

    tracker_payload = _read_json(resolve_dataset_plan_read_path()) or {}
    by_run: dict[str, Mapping[str, Any]] = {}
    apps = tracker_payload.get("apps") if isinstance(tracker_payload.get("apps"), dict) else {}
    for entry in apps.values():
        if not isinstance(entry, Mapping):
            continue
        for item in entry.get("runs") or []:
            if isinstance(item, Mapping) and item.get("run_id"):
                by_run[str(item["run_id"])] = item
    return by_run


def _refresh_tracker_truth() -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, recompute_dataset_tracker

    recompute_dataset_tracker(config=DatasetTrackerConfig())


_MISSING = object()


def _normalized_value(value: Any) -> Any:
    if isinstance(value, list):
        return list(value)
    return value


def _normalized_policy_value(key: str, value: Any, *, dataset: Mapping[str, Any]) -> Any:
    if value is _MISSING:
        if key == "extra_run":
            return 0
        if key == "counts_toward_quota" and dataset.get("countable") is True:
            return True
    return _normalized_value(value)


def _policy_sync_candidate_row(run_dir: Path, tracker_row: Mapping[str, Any]) -> dict[str, Any] | None:
    raw = _read_json(run_dir / "run_manifest.json")
    if not isinstance(raw, dict):
        return None
    dataset = raw.get("dataset") if isinstance(raw.get("dataset"), dict) else {}
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    operator = raw.get("operator") if isinstance(raw.get("operator"), dict) else {}
    current_reason = str(dataset.get("invalid_reason_code") or "").strip().upper()
    if current_reason == "ABORTED_DISCARD":
        return None
    diffs: list[str] = []
    for key in SYNCABLE_TRACKER_FIELDS:
        if key not in tracker_row:
            continue
        manifest_value = _normalized_policy_value(
            key,
            dataset[key] if key in dataset else _MISSING,
            dataset=dataset,
        )
        tracker_value = _normalized_policy_value(
            key,
            tracker_row[key],
            dataset=dataset,
        )
        if manifest_value != tracker_value:
            diffs.append(key)
    if not diffs:
        return None
    return {
        "repair_type": "policy_sync",
        "run_id": run_dir.name,
        "package": str(target.get("package_name") or ""),
        "run_profile": str(dataset.get("run_profile") or operator.get("run_profile") or ""),
        "messaging_activity": str(operator.get("messaging_activity") or ""),
        "current_valid_dataset_run": int(dataset.get("valid_dataset_run") is True),
        "current_invalid_reason_code": str(dataset.get("invalid_reason_code") or ""),
        "new_valid_dataset_run": int(tracker_row.get("valid_dataset_run") is True),
        "new_invalid_reason_code": tracker_row.get("invalid_reason_code"),
        "current_pcap_size_bytes": dataset.get("pcap_size_bytes"),
        "new_pcap_size_bytes": tracker_row.get("pcap_size_bytes"),
        "new_min_pcap_bytes": tracker_row.get("min_pcap_bytes"),
        "new_window_count": tracker_row.get("window_count"),
        "new_min_window_count": tracker_row.get("min_window_count"),
        "new_actual_sampling_seconds": tracker_row.get("actual_sampling_seconds"),
        "new_sampling_duration_seconds": tracker_row.get("sampling_duration_seconds"),
        "counts_toward_completion": int(operator.get("counts_toward_completion") is True),
        "changed_fields": ",".join(sorted(diffs)),
        "_tracker_row": tracker_row,
    }


def _candidate_rows(evidence_root: Path, run_ids: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    tracker_by_run = _load_tracker_by_run()
    for run_dir in sorted([p for p in evidence_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if run_ids and run_dir.name not in run_ids:
            continue
        row = _candidate_row(run_dir)
        if row is not None:
            rows.append(row)
            continue
        tracker_row = tracker_by_run.get(run_dir.name)
        if tracker_row:
            policy_row = _policy_sync_candidate_row(run_dir, tracker_row)
            if policy_row is not None:
                rows.append(policy_row)
    return rows


def _sync_manifest_from_tracker(run_dir: Path, tracker_row: Mapping[str, Any]) -> bool:
    raw = _read_json(run_dir / "run_manifest.json")
    if not isinstance(raw, dict):
        return False
    dataset = raw.setdefault("dataset", {})
    if not isinstance(dataset, dict):
        dataset = {}
        raw["dataset"] = dataset
    before = json.dumps(dataset, sort_keys=True, default=str)
    for key in SYNCABLE_TRACKER_FIELDS:
        if key in tracker_row:
            dataset[key] = tracker_row.get(key)
    after = json.dumps(dataset, sort_keys=True, default=str)
    if before == after:
        return False
    _write_json(run_dir / "run_manifest.json", raw)
    return True


def _reindex_run_ids(evidence_root: Path, run_ids: Sequence[str]) -> int:
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import index_dynamic_evidence_pack_to_db

    reindexed_db_rows = 0
    for run_id in run_ids:
        normalized = str(run_id or "").strip()
        if not normalized:
            continue
        run_dir = evidence_root / normalized
        if not (run_dir / "run_manifest.json").exists():
            continue
        result = index_dynamic_evidence_pack_to_db(run_dir)
        if result.get("ok") is True:
            reindexed_db_rows += 1
    return reindexed_db_rows


def _apply_repairs(
    evidence_root: Path,
    output_dir: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    explicit_run_ids: Sequence[str] = (),
) -> tuple[int, int, int]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, recompute_dataset_tracker
    from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_plan_read_path
    from scripts.dynamic import refresh_analysis_summaries as refresh_summaries

    backups_dir = output_dir / "manifest_backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    updated_manifests = 0
    for row in rows:
        run_dir = evidence_root / str(row["run_id"])
        manifest_path = run_dir / "run_manifest.json"
        raw = _read_json(manifest_path)
        if not isinstance(raw, dict):
            continue
        _write_json(backups_dir / f"{run_dir.name}.run_manifest.before.json", raw)
        dataset = raw.setdefault("dataset", {})
        if not isinstance(dataset, dict):
            dataset = {}
            raw["dataset"] = dataset
        old_valid = dataset.get("valid_dataset_run")
        old_countable = dataset.get("countable")
        operator = raw.get("operator") if isinstance(raw.get("operator"), dict) else {}
        if row.get("repair_type") == "validity_repair":
            for key, value in (row.get("_validity") or {}).items():
                dataset[key] = value
            if old_valid is False and old_countable is False and operator.get("counts_toward_completion") is True:
                dataset.pop("countable", None)
        _write_json(manifest_path, raw)
        updated_manifests += 1

    if updated_manifests:
        recompute_dataset_tracker(config=DatasetTrackerConfig())

    tracker_payload = _read_json(resolve_dataset_plan_read_path()) or {}
    tracker_by_run: dict[str, Mapping[str, Any]] = {}
    for entry in (tracker_payload.get("apps") or {}).values() if isinstance(tracker_payload.get("apps"), dict) else []:
        if not isinstance(entry, Mapping):
            continue
        for item in entry.get("runs") or []:
            if isinstance(item, Mapping) and item.get("run_id"):
                tracker_by_run[str(item["run_id"])] = item

    synced_manifests = 0
    for row in rows:
        tracker_row = tracker_by_run.get(str(row["run_id"]))
        if tracker_row and _sync_manifest_from_tracker(evidence_root / str(row["run_id"]), tracker_row):
            synced_manifests += 1
    if rows:
        refresh_summaries.refresh_summaries(
            root=evidence_root,
            apply=True,
            refresh_pcap_report=True,
            refresh_pcap_features=True,
            refresh_overlap=True,
            run_ids={str(row["run_id"]) for row in rows if str(row.get("run_id") or "").strip()},
        )
    reindex_run_ids = [str(row.get("run_id") or "").strip() for row in rows if str(row.get("run_id") or "").strip()]
    if explicit_run_ids:
        seen = set(reindex_run_ids)
        for run_id in explicit_run_ids:
            normalized = str(run_id or "").strip()
            if normalized and normalized not in seen:
                reindex_run_ids.append(normalized)
                seen.add(normalized)
    reindexed_db_rows = _reindex_run_ids(evidence_root, reindex_run_ids)
    return updated_manifests, synced_manifests, reindexed_db_rows


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    evidence_root = Path(args.evidence_root) if args.evidence_root else _default_evidence_root()
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_ids = {str(value).strip() for value in (args.run_id or []) if str(value).strip()}
    tracker_refreshed_before_candidate_selection = bool(args.apply or args.refresh_tracker)
    if tracker_refreshed_before_candidate_selection:
        _refresh_tracker_truth()
    rows = _candidate_rows(evidence_root, run_ids)
    public_rows = [{key: value for key, value in row.items() if not key.startswith("_")} for row in rows]

    applied_rows = 0
    synced_rows = 0
    reindexed_db_rows = 0
    if args.apply and rows:
        applied_rows, synced_rows, reindexed_db_rows = _apply_repairs(
            evidence_root,
            output_dir,
            rows,
            explicit_run_ids=sorted(run_ids),
        )
    elif args.apply and run_ids:
        reindexed_db_rows = _reindex_run_ids(evidence_root, sorted(run_ids))

    fields = (
        "repair_type",
        "run_id",
        "package",
        "run_profile",
        "messaging_activity",
        "current_valid_dataset_run",
        "current_invalid_reason_code",
        "new_valid_dataset_run",
        "new_invalid_reason_code",
        "current_pcap_size_bytes",
        "new_pcap_size_bytes",
        "new_min_pcap_bytes",
        "new_window_count",
        "new_min_window_count",
        "new_actual_sampling_seconds",
        "new_sampling_duration_seconds",
        "counts_toward_completion",
        "changed_fields",
    )
    plan_csv = output_dir / "dynamic_dataset_validity_repair_plan.csv"
    _write_csv(plan_csv, public_rows, fields)
    summary = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "evidence_root": str(evidence_root.resolve()),
        "apply": bool(args.apply),
        "tracker_refreshed_before_candidate_selection": tracker_refreshed_before_candidate_selection,
        "candidate_rows": len(public_rows),
        "applied_rows": int(applied_rows),
        "synced_manifest_rows": int(synced_rows),
        "reindexed_db_rows": int(reindexed_db_rows),
        "note": (
            "Repairs stale invalid manifests, syncs stale policy-derived dataset fields from "
            "tracker truth into local evidence-pack manifests, refreshes the repaired runs' "
            "derived analysis artifacts, and reindexes repaired runs into DB truth."
        ),
        "output_files": {
            "repair_plan_csv": str(plan_csv.resolve()),
            "summary_json": str((output_dir / "summary.json").resolve()),
        },
    }
    _write_json(output_dir / "summary.json", summary)
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
