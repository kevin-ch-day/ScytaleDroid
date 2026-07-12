#!/usr/bin/env python3
"""Explicitly accept a technically valid dynamic run that was accidentally discarded.

This is intentionally narrower than the generic dataset-validity repair. An
``ABORTED_DISCARD`` verdict normally means the operator chose not to keep the
run, so this script only changes evidence/DB state when an operator explicitly
reruns it with ``--apply`` and the retained pack still passes technical
dataset-validity checks.
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


ACTION_FIELDS = (
    "run_id",
    "package_name",
    "run_profile",
    "current_status",
    "new_status",
    "current_valid_dataset_run",
    "new_valid_dataset_run",
    "current_countable",
    "new_countable",
    "current_invalid_reason_code",
    "new_invalid_reason_code",
    "pcap_size_bytes",
    "window_count",
    "actual_sampling_seconds",
    "status",
    "reason",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Dynamic run ID to explicitly accept.")
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root; defaults to data/evidence/dynamic.")
    parser.add_argument("--output-dir", default=None, help="Receipt directory; defaults to output/audit/dynamic_aborted_discard_acceptance/<timestamp>.")
    parser.add_argument("--reason", default="operator confirmed accidental discard; retained evidence is technically valid", help="Operator-facing repair reason recorded in receipts and manifest metadata.")
    parser.add_argument("--apply", action="store_true", help="Rewrite manifest/summary/tracker/derived DB index. Default is dry-run.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_aborted_discard_acceptance" / stamp


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _tracker_row_for_run(run_id: str, package_name: str) -> dict[str, Any] | None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    app_entry = apps.get(package_name) if isinstance(apps, dict) else None
    runs = app_entry.get("runs") if isinstance(app_entry, dict) else None
    if not isinstance(runs, list):
        return None
    for row in runs:
        if isinstance(row, dict) and str(row.get("run_id") or "") == run_id:
            return row
    return None


def _manifest_from_payload(payload: dict[str, Any]):
    from scripts.dynamic.refresh_analysis_summaries import _manifest_from_payload as build_manifest

    return build_manifest(payload)


def _technical_validity(run_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, evaluate_dataset_validity

    manifest = _manifest_from_payload(payload)
    return evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())


def _candidate(run_dir: Path) -> dict[str, Any]:
    payload = _read_json(run_dir / "run_manifest.json")
    if not isinstance(payload, dict):
        return {"status": "blocked", "reason": "missing_or_invalid_manifest", "run_id": run_dir.name}

    dataset = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
    operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    run_id = str(payload.get("dynamic_run_id") or run_dir.name)
    package_name = str(target.get("package_name") or "")
    current_reason = str(dataset.get("invalid_reason_code") or "").strip().upper()
    operator_discard = str(operator.get("interrupted_reason") or "").strip().upper() == "ABORTED_DISCARD"
    validity = _technical_validity(run_dir, payload)
    current_valid = dataset.get("valid_dataset_run") is True

    row = {
        "run_id": run_id,
        "package_name": package_name,
        "run_profile": str(operator.get("run_profile") or ""),
        "current_status": str(payload.get("status") or ""),
        "new_status": "success",
        "current_valid_dataset_run": dataset.get("valid_dataset_run"),
        "new_valid_dataset_run": True,
        "current_countable": dataset.get("countable"),
        "new_countable": True,
        "current_invalid_reason_code": current_reason,
        "new_invalid_reason_code": None,
        "pcap_size_bytes": validity.get("pcap_size_bytes", dataset.get("pcap_size_bytes")),
        "window_count": validity.get("window_count", dataset.get("window_count")),
        "actual_sampling_seconds": validity.get("actual_sampling_seconds", dataset.get("actual_sampling_seconds")),
        "_payload": payload,
        "_validity": validity,
    }

    if current_reason != "ABORTED_DISCARD":
        if current_valid and operator_discard and operator.get("counts_toward_completion") is not True:
            return {**row, "status": "blocked", "reason": "run_was_not_quota_intended"}
        if (
            current_valid
            and operator_discard
            and operator.get("counts_toward_completion") is True
            and validity.get("valid_dataset_run") is True
        ):
            if dataset.get("low_signal") is True and not _low_signal_repairable_after_recheck(
                run_dir,
                package_name=package_name,
                run_profile=str(operator.get("run_profile") or ""),
            ):
                return {**row, "status": "blocked", "reason": "low_signal_runs_require_normal_policy_review"}
            return {**row, "status": "candidate", "reason": "valid_run_with_stale_aborted_discard_marker"}
        return {**row, "status": "blocked", "reason": "current_invalid_reason_is_not_aborted_discard"}
    if validity.get("valid_dataset_run") is not True:
        return {
            **row,
            "new_valid_dataset_run": False,
            "new_invalid_reason_code": validity.get("invalid_reason_code"),
            "status": "blocked",
            "reason": "technical_validity_recheck_failed",
        }
    if operator.get("counts_toward_completion") is not True:
        return {**row, "status": "blocked", "reason": "run_was_not_quota_intended"}
    if dataset.get("low_signal") is True and not _low_signal_repairable_after_recheck(
        run_dir,
        package_name=package_name,
        run_profile=str(operator.get("run_profile") or ""),
    ):
        return {**row, "status": "blocked", "reason": "low_signal_runs_require_normal_policy_review"}
    return {**row, "status": "candidate", "reason": "technically_valid_aborted_discard"}


def _low_signal_repairable_after_recheck(
    run_dir: Path,
    *,
    package_name: str,
    run_profile: str,
) -> bool:
    from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run

    decision = compute_low_signal_for_run(
        run_dir,
        package_name=package_name,
        run_profile=run_profile,
    )
    return isinstance(decision, dict) and decision.get("low_signal") is False


def _connected_baseline_protocol_patch(payload: Mapping[str, Any]) -> dict[str, object]:
    operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    run_profile = str(operator.get("run_profile") or "").strip().lower()
    messaging_activity = str(operator.get("messaging_activity") or "").strip().lower()
    if run_profile != "baseline_connected" or messaging_activity not in {"", "connected_idle"}:
        return {}
    if operator.get("baseline_protocol_id") and operator.get("baseline_protocol_version"):
        return {}
    try:
        from scytaledroid.DynamicAnalysis.scenarios.manual import _build_baseline_protocol
        from types import SimpleNamespace

        target_duration = int(
            operator.get("target_duration_s")
            or (operator.get("run_context") or {}).get("duration_seconds")
            or 240
        )
        return _build_baseline_protocol(
            run_ctx=SimpleNamespace(
                package_name=str(target.get("package_name") or ""),
                messaging_activity=messaging_activity or "connected_idle",
            ),
            target_duration_s=target_duration,
        )
    except Exception:
        return {
            "baseline_protocol_id": "baseline_connected_v2",
            "baseline_protocol_version": 2,
        }


def _sync_manifest_from_tracker(run_dir: Path, tracker_row: Mapping[str, Any]) -> bool:
    payload = _read_json(run_dir / "run_manifest.json")
    if not isinstance(payload, dict):
        return False
    dataset = payload.setdefault("dataset", {})
    if not isinstance(dataset, dict):
        dataset = {}
        payload["dataset"] = dataset
    before = json.dumps(dataset, sort_keys=True, default=str)
    for key in SYNCABLE_TRACKER_FIELDS:
        if key in tracker_row:
            dataset[key] = tracker_row.get(key)
    after = json.dumps(dataset, sort_keys=True, default=str)
    if before == after:
        return False
    _write_json(run_dir / "run_manifest.json", payload)
    return True


def _apply_candidate(run_dir: Path, row: Mapping[str, Any], *, output_dir: Path, reason: str) -> dict[str, Any]:
    from scripts.dynamic import refresh_analysis_summaries
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, recompute_dataset_tracker
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import index_dynamic_evidence_pack_to_db

    payload = dict(row.get("_payload") or {})
    if not payload:
        return {**{k: row.get(k) for k in ACTION_FIELDS}, "status": "blocked", "reason": "missing_payload"}

    run_id = str(row.get("run_id") or run_dir.name)
    manifest_path = run_dir / "run_manifest.json"
    backup_path = output_dir / "manifest_backups" / f"{run_id}.run_manifest.before.json"
    _write_json(backup_path, payload)

    now = datetime.now(tz=UTC).isoformat()
    dataset = payload.setdefault("dataset", {})
    if not isinstance(dataset, dict):
        dataset = {}
        payload["dataset"] = dataset
    for key, value in dict(row.get("_validity") or {}).items():
        dataset[key] = value
    dataset["valid_dataset_run"] = True
    dataset["countable"] = True
    dataset["counts_toward_quota"] = True
    dataset["invalid_reason_code"] = None
    dataset["paper_eligible"] = True
    dataset["paper_exclusion_primary_reason_code"] = None
    dataset["paper_exclusion_all_reason_codes"] = []
    dataset["technical_validity"] = "VALID"
    dataset["protocol_compliance"] = dataset.get("protocol_compliance") or "COMPLIANT"
    dataset["cohort_eligibility"] = "COUNTABLE"

    operator = payload.setdefault("operator", {})
    if not isinstance(operator, dict):
        operator = {}
        payload["operator"] = operator
    operator["accepted_after_discard_repair"] = True
    operator["accepted_after_discard_at_utc"] = now
    operator["accepted_after_discard_reason"] = reason
    operator["accepted_after_discard_original"] = {
        "interrupted": operator.get("interrupted"),
        "interrupted_reason": operator.get("interrupted_reason"),
        "script_exit_code": operator.get("script_exit_code"),
        "status": row.get("current_status"),
    }
    operator["interrupted"] = False
    operator["interrupted_reason"] = None
    operator["script_exit_code"] = 0
    operator.update(_connected_baseline_protocol_patch(payload))
    operator["technical_validity"] = "VALID"
    operator["protocol_compliance"] = dataset["protocol_compliance"]
    operator["cohort_eligibility"] = "COUNTABLE"

    payload["status"] = "success"
    notes = payload.setdefault("notes", [])
    if isinstance(notes, list):
        notes.append(f"{now}: accepted after accidental ABORTED_DISCARD repair - {reason}")

    _write_json(manifest_path, payload)

    recompute_dataset_tracker(config=DatasetTrackerConfig())
    tracker_row = _tracker_row_for_run(run_id, str(row.get("package_name") or ""))
    tracker_synced = False
    if tracker_row:
        tracker_synced = _sync_manifest_from_tracker(run_dir, tracker_row)

    refresh_analysis_summaries.refresh_summaries(
        root=run_dir.parent,
        apply=True,
        refresh_pcap_report=False,
        refresh_pcap_features=False,
        refresh_overlap=False,
        run_ids={run_id},
    )
    index_result = index_dynamic_evidence_pack_to_db(run_dir)
    after_payload = _read_json(manifest_path) or {}
    after_dataset = after_payload.get("dataset") if isinstance(after_payload.get("dataset"), dict) else {}
    return {
        **{k: row.get(k) for k in ACTION_FIELDS},
        "status": "applied",
        "reason": "accepted_after_technical_recheck",
        "new_status": after_payload.get("status"),
        "new_valid_dataset_run": after_dataset.get("valid_dataset_run"),
        "new_countable": after_dataset.get("countable"),
        "new_invalid_reason_code": after_dataset.get("invalid_reason_code"),
        "tracker_synced": tracker_synced,
        "db_reindexed": index_result.get("ok") is True,
        "db_reindex_result": index_result,
        "manifest_backup": str(backup_path),
    }


def run(
    *,
    run_id: str,
    evidence_root: Path,
    output_dir: Path,
    apply: bool,
    reason: str,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = evidence_root / run_id
    candidate = _candidate(run_dir)
    action_rows: list[dict[str, Any]] = []
    blocked_rows: list[dict[str, Any]] = []
    if candidate.get("status") != "candidate":
        blocked_rows.append({k: candidate.get(k) for k in ACTION_FIELDS})
    elif apply:
        action_rows.append(_apply_candidate(run_dir, candidate, output_dir=output_dir, reason=reason))
    else:
        action_rows.append({k: candidate.get(k) for k in ACTION_FIELDS})

    _write_csv(output_dir / "actions.csv", action_rows, ACTION_FIELDS)
    _write_csv(output_dir / "blocked.csv", blocked_rows, ACTION_FIELDS)
    summary = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "apply": bool(apply),
        "run_id": run_id,
        "evidence_root": str(evidence_root.resolve()),
        "output_dir": str(output_dir.resolve()),
        "candidate_rows": int(candidate.get("status") == "candidate"),
        "applied_rows": sum(1 for row in action_rows if row.get("status") == "applied"),
        "blocked_rows": len(blocked_rows),
        "reason": reason,
        "output_files": {
            "actions_csv": str((output_dir / "actions.csv").resolve()),
            "blocked_csv": str((output_dir / "blocked.csv").resolve()),
            "summary_json": str((output_dir / "summary.json").resolve()),
        },
    }
    _write_json(output_dir / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    evidence_root = Path(args.evidence_root) if args.evidence_root else _default_evidence_root()
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    summary = run(
        run_id=str(args.run_id).strip(),
        evidence_root=evidence_root,
        output_dir=output_dir,
        apply=bool(args.apply),
        reason=str(args.reason or "").strip(),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"candidate_rows={summary['candidate_rows']} applied_rows={summary['applied_rows']} "
            f"blocked_rows={summary['blocked_rows']} output_dir={summary['output_dir']}"
        )
    return 0 if summary["blocked_rows"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
