#!/usr/bin/env python3
"""Refresh derived dynamic run analysis artifacts from existing evidence packs.

This is a safe derived-artifact maintenance tool. It does not mutate dataset
validity/countability flags. In apply mode it synchronizes ``run_manifest.json``
output records for refreshed derived artifacts so hashes and sizes remain valid.

Default behavior regenerates:
- analysis/summary.json
- analysis/summary.md

Optional apply-time flags can also regenerate:
- analysis/pcap_report.json
- analysis/pcap_features.json
- analysis/static_dynamic_overlap.json

Default mode is dry-run. Use ``--apply`` to write refreshed artifacts.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Rewrite analysis/summary.json and analysis/summary.md.")
    parser.add_argument("--pcap-report", action="store_true", help="Also regenerate analysis/pcap_report.json in apply mode.")
    parser.add_argument("--pcap-features", action="store_true", help="Also regenerate analysis/pcap_features.json in apply mode.")
    parser.add_argument("--overlap", action="store_true", help="Also regenerate analysis/static_dynamic_overlap.json in apply mode.")
    parser.add_argument(
        "--all-derived",
        action="store_true",
        help="Shortcut for --pcap-report --pcap-features --overlap plus refreshed summaries.",
    )
    parser.add_argument("--run-id", action="append", default=None, help="Restrict to one or more dynamic run IDs.")
    parser.add_argument("--package", action="append", default=None, help="Restrict to one or more package names.")
    parser.add_argument("--output-root", default=None, help="Override dynamic evidence root for testing or alternate workspaces.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _dynamic_root(output_root: str | None = None) -> Path:
    if output_root:
        return Path(output_root)
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _artifact_from_dict(payload: dict[str, Any]) -> "ArtifactRecord":
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord

    return ArtifactRecord(
        relative_path=str(payload.get("relative_path") or ""),
        type=str(payload.get("type") or ""),
        produced_by=str(payload.get("produced_by") or ""),
        sha256=payload.get("sha256"),
        size_bytes=payload.get("size_bytes"),
        origin=payload.get("origin"),
        device_path=payload.get("device_path"),
        pull_status=payload.get("pull_status"),
    )


def _manifest_from_payload(payload: dict[str, Any]) -> "RunManifest":
    from scytaledroid.DynamicAnalysis.core.manifest import ObserverRecord, RunManifest

    observers = []
    for row in payload.get("observers") or []:
        if not isinstance(row, dict):
            continue
        observers.append(
            ObserverRecord(
                observer_id=str(row.get("observer_id") or ""),
                status=str(row.get("status") or ""),
                error=(str(row.get("error")) if row.get("error") else None),
                artifacts=[
                    _artifact_from_dict(artifact)
                    for artifact in (row.get("artifacts") or [])
                    if isinstance(artifact, dict)
                ],
            )
        )

    return RunManifest(
        run_manifest_version=int(payload.get("run_manifest_version") or 1),
        dynamic_run_id=str(payload.get("dynamic_run_id") or ""),
        created_at=str(payload.get("created_at") or ""),
        batch_id=(str(payload.get("batch_id")) if payload.get("batch_id") else None),
        started_at=(str(payload.get("started_at")) if payload.get("started_at") else None),
        ended_at=(str(payload.get("ended_at")) if payload.get("ended_at") else None),
        sealed_at=(str(payload.get("sealed_at")) if payload.get("sealed_at") else None),
        sealed_by=(str(payload.get("sealed_by")) if payload.get("sealed_by") else None),
        status=str(payload.get("status") or "pending"),
        dataset=dict(payload.get("dataset") or {}),
        qa=dict(payload.get("qa") or {}),
        target=dict(payload.get("target") or {}),
        environment=dict(payload.get("environment") or {}),
        scenario=dict(payload.get("scenario") or {}),
        observers=observers,
        artifacts=[
            _artifact_from_dict(artifact)
            for artifact in (payload.get("artifacts") or [])
            if isinstance(artifact, dict)
        ],
        outputs=[
            _artifact_from_dict(artifact)
            for artifact in (payload.get("outputs") or [])
            if isinstance(artifact, dict)
        ],
        operator=dict(payload.get("operator") or {}),
        notes=[str(item) for item in (payload.get("notes") or [])],
    )


def _completed_run_dirs(root: Path) -> tuple[list[Path], list[str], list[str]]:
    run_dirs: list[Path] = []
    in_progress: list[str] = []
    ghost: list[str] = []
    if not root.exists():
        return run_dirs, in_progress, ghost
    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if (run_dir / "run_manifest.json").exists():
            run_dirs.append(run_dir)
        elif (run_dir / "notes" / ".scytaledroid_in_progress").exists():
            in_progress.append(run_dir.name)
        else:
            ghost.append(run_dir.name)
    return run_dirs, in_progress, ghost


def _summary_payload(run_dir: Path, manifest: "RunManifest") -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
    from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter

    writer = EvidencePackWriter(run_dir)
    return DynamicRunSummarizer(writer)._build_summary(manifest)


def _rewrite_derived_artifacts(
    *,
    run_dir: Path,
    manifest: "RunManifest",
    refresh_pcap_report: bool,
    refresh_pcap_features: bool,
    refresh_overlap: bool,
) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
    from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
    from scytaledroid.DynamicAnalysis.pcap.correlate import write_static_dynamic_overlap
    from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
    from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

    writer = EvidencePackWriter(run_dir)
    changed = {
        "pcap_report": False,
        "pcap_features": False,
        "overlap": False,
        "summary": False,
    }
    records = []
    if refresh_pcap_report:
        record = write_pcap_report(manifest, run_dir)
        changed["pcap_report"] = record is not None
        if record is not None:
            records.append(record)
    if refresh_pcap_features:
        record = write_pcap_features(manifest, run_dir)
        changed["pcap_features"] = record is not None
        if record is not None:
            records.append(record)
    if refresh_overlap:
        record = write_static_dynamic_overlap(manifest, run_dir)
        changed["overlap"] = record is not None
        if record is not None:
            records.append(record)
    records.extend(DynamicRunSummarizer(writer).summarize(manifest))
    changed["summary"] = True
    changed["records"] = [asdict(record) for record in records]
    return changed


def _sync_manifest_output_records(run_dir: Path, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    manifest_path = run_dir / "run_manifest.json"
    payload = _read_json(manifest_path)
    if not isinstance(payload, dict):
        return 0
    outputs = payload.get("outputs")
    if not isinstance(outputs, list):
        outputs = []
        payload["outputs"] = outputs

    changed = 0
    by_path: dict[str, int] = {}
    for idx, row in enumerate(outputs):
        if isinstance(row, dict):
            rel = str(row.get("relative_path") or "").strip()
            if rel:
                by_path[rel] = idx

    for record in records:
        rel = str(record.get("relative_path") or "").strip()
        if not rel:
            continue
        normalized = {key: value for key, value in record.items() if value is not None}
        existing_idx = by_path.get(rel)
        if existing_idx is None:
            outputs.append(normalized)
            by_path[rel] = len(outputs) - 1
            changed += 1
            continue
        existing = outputs[existing_idx]
        if existing != normalized:
            outputs[existing_idx] = normalized
            changed += 1

    if changed:
        manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return changed


def refresh_summaries(
    *,
    root: Path,
    apply: bool,
    refresh_pcap_report: bool = False,
    refresh_pcap_features: bool = False,
    refresh_overlap: bool = False,
    run_ids: set[str] | None = None,
    packages: set[str] | None = None,
) -> dict[str, Any]:
    completed_run_dirs, in_progress, ghost = _completed_run_dirs(root)
    scanned = 0
    matched = 0
    updated = 0
    changed_destinations = 0
    changed_network_capture = 0
    pcap_report_refreshed = 0
    pcap_features_refreshed = 0
    overlap_refreshed = 0
    manifest_outputs_synced = 0
    manifest_writes = 0
    rows: list[dict[str, Any]] = []

    for run_dir in completed_run_dirs:
        scanned += 1
        payload = _read_json(run_dir / "run_manifest.json")
        if not isinstance(payload, dict):
            continue
        run_id = str(payload.get("dynamic_run_id") or run_dir.name)
        package = str(((payload.get("target") or {}).get("package_name")) if isinstance(payload.get("target"), dict) else "") or ""
        if run_ids and run_id not in run_ids:
            continue
        if packages and package not in packages:
            continue
        matched += 1
        manifest = _manifest_from_payload(payload)
        old_summary = _read_json(run_dir / "analysis" / "summary.json") or {}
        new_summary = _summary_payload(run_dir, manifest)

        old_dest_count = len(old_summary.get("destinations_observed") or [])
        new_dest_count = len(new_summary.get("destinations_observed") or [])
        old_capture = old_summary.get("capture") if isinstance(old_summary.get("capture"), dict) else {}
        new_capture = new_summary.get("capture") if isinstance(new_summary.get("capture"), dict) else {}

        row = {
            "run_id": run_id,
            "package": package,
            "old_destinations_count": old_dest_count,
            "new_destinations_count": new_dest_count,
            "old_network_capture_present": old_summary.get("flags", {}).get("network_capture_present") if isinstance(old_summary.get("flags"), dict) else None,
            "new_network_capture_present": new_summary.get("flags", {}).get("network_capture_present") if isinstance(new_summary.get("flags"), dict) else None,
            "old_pcap_valid": old_capture.get("pcap_valid") if isinstance(old_capture, dict) else None,
            "new_pcap_valid": new_capture.get("pcap_valid") if isinstance(new_capture, dict) else None,
        }
        rows.append(row)

        if new_dest_count != old_dest_count:
            changed_destinations += 1
        if row["old_network_capture_present"] != row["new_network_capture_present"]:
            changed_network_capture += 1

        if apply:
            changed = _rewrite_derived_artifacts(
                run_dir=run_dir,
                manifest=manifest,
                refresh_pcap_report=refresh_pcap_report,
                refresh_pcap_features=refresh_pcap_features,
                refresh_overlap=refresh_overlap,
            )
            updated += 1
            pcap_report_refreshed += int(changed["pcap_report"])
            pcap_features_refreshed += int(changed["pcap_features"])
            overlap_refreshed += int(changed["overlap"])
            synced = _sync_manifest_output_records(
                run_dir,
                [record for record in changed.get("records", []) if isinstance(record, dict)],
            )
            manifest_outputs_synced += synced
            manifest_writes += int(synced > 0)

    return {
        "dynamic_evidence_root": str(root.resolve()),
        "runs_scanned": scanned,
        "runs_matched": matched,
        "runs_updated": updated,
        "pcap_report_refreshed": pcap_report_refreshed,
        "pcap_features_refreshed": pcap_features_refreshed,
        "overlap_refreshed": overlap_refreshed,
        "manifest_outputs_synced": manifest_outputs_synced,
        "manifest_writes": manifest_writes,
        "runs_with_destination_changes": changed_destinations,
        "runs_with_network_capture_flag_changes": changed_network_capture,
        "in_progress_dirs_skipped": in_progress,
        "ghost_dirs_skipped": ghost,
        "rows": rows,
        "apply_mode": bool(apply),
        "refresh_pcap_report": bool(refresh_pcap_report),
        "refresh_pcap_features": bool(refresh_pcap_features),
        "refresh_overlap": bool(refresh_overlap),
        "dataset_flags_unchanged": True,
        "manifest_writes_limited_to_outputs": True,
        "no_manifest_writes": not bool(manifest_writes),
    }


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = _dynamic_root(args.output_root)
    refresh_pcap_report = bool(args.pcap_report or args.all_derived)
    refresh_pcap_features = bool(args.pcap_features or args.all_derived)
    refresh_overlap = bool(args.overlap or args.all_derived)
    summary = refresh_summaries(
        root=root,
        apply=bool(args.apply),
        refresh_pcap_report=refresh_pcap_report,
        refresh_pcap_features=refresh_pcap_features,
        refresh_overlap=refresh_overlap,
        run_ids={str(value) for value in (args.run_id or [])} or None,
        packages={str(value) for value in (args.package or [])} or None,
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"runs_scanned={summary['runs_scanned']} runs_matched={summary['runs_matched']} "
            f"runs_updated={summary['runs_updated']} destination_changes={summary['runs_with_destination_changes']} "
            f"pcap_report_refreshed={summary['pcap_report_refreshed']} "
            f"pcap_features_refreshed={summary['pcap_features_refreshed']} "
            f"overlap_refreshed={summary['overlap_refreshed']} "
            f"in_progress_skipped={len(summary['in_progress_dirs_skipped'])} ghost_skipped={len(summary['ghost_dirs_skipped'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
