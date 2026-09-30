#!/usr/bin/env python3
"""Export versioned component exposure counts from frozen publication CSVs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_rows(
    cohort: list[dict[str, str]],
    findings: list[dict[str, str]],
    reviewed_signature_rows: list[dict[str, str]] | None = None,
) -> list[dict[str, str | int]]:
    from scytaledroid.Publication.metric_v2 import component_exposure_from_findings_v2

    run_to_app: dict[str, dict[str, str]] = {}
    for app in cohort:
        run_id = str(app.get("contributing_static_run_id") or "").strip()
        if not run_id or run_id in run_to_app:
            raise ValueError(f"Missing or duplicate contributing_static_run_id: {run_id!r}")
        run_to_app[run_id] = app
    by_run: dict[str, list[dict[str, str]]] = defaultdict(list)
    for finding in findings:
        run_id = str(finding.get("run_id") or "").strip()
        if run_id not in run_to_app:
            raise ValueError(f"Finding outside the selected cohort: run_id={run_id!r}")
        by_run[run_id].append(finding)
    if any(run_id not in by_run for run_id in run_to_app):
        raise ValueError("At least one selected run has no finding rows")

    findings_by_id = {str(row.get("id") or ""): row for row in findings if row.get("id")}
    if len(findings_by_id) != sum(bool(row.get("id")) for row in findings):
        raise ValueError("Duplicate finding database IDs in frozen input")
    correction_ids: set[str] = set()
    for review in reviewed_signature_rows or []:
        finding_db_id = str(review.get("finding_db_id") or "").strip()
        row = findings_by_id.get(finding_db_id)
        if (
            not finding_db_id
            or finding_db_id in correction_ids
            or row is None
            or str(row.get("run_id")) != str(review.get("static_run_id"))
            or str(row.get("finding_id")) != str(review.get("finding_id"))
            or str(review.get("recorded_protection_level")) != "0x00000002"
            or str(review.get("adjudication_status")) != "CONFIRMED_GUARD_CLASSIFICATION_ERROR"
            or component_exposure_from_findings_v2([row])[
                "ipc_components_with_weak_permission_guard"
            ] != 1
        ):
            raise ValueError(f"Reviewed signature row does not match frozen finding: {finding_db_id!r}")
        correction_ids.add(finding_db_id)

    rows: list[dict[str, str | int]] = []
    for run_id, app in sorted(run_to_app.items(), key=lambda item: (item[1].get("package_name", ""), item[0])):
        exposure = component_exposure_from_findings_v2(by_run[run_id])
        corrected_rows = [
            finding for finding in by_run[run_id]
            if str(finding.get("id") or "") not in correction_ids
        ]
        corrected_exposure = component_exposure_from_findings_v2(corrected_rows)
        corrected_count = len(by_run[run_id]) - len(corrected_rows)
        total = sum(
            exposure[key]
            for key in (
                "exported_activities",
                "exported_activity_aliases",
                "exported_services",
                "exported_receivers",
                "exported_providers",
            )
        )
        rows.append(
            {
                "app_label": app.get("app_label", ""),
                "package_name": app.get("package_name", ""),
                "base_apk_sha256": app.get("selected_base_apk_sha256", ""),
                "contributing_static_run_id": run_id,
                "raw_finding_rows": len(by_run[run_id]),
                "exported_component_identities": total,
                **exposure,
                "reviewed_signature_false_weak_rows": corrected_count,
                "weak_guard_labels_after_known_corrections": corrected_exposure[
                    "ipc_components_with_weak_permission_guard"
                ],
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-manifest", type=Path, required=True)
    parser.add_argument("--finding-rows", type=Path, required=True)
    parser.add_argument("--reviewed-signature-rows", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    cohort_path = args.cohort_manifest.resolve(strict=True)
    findings_path = args.finding_rows.resolve(strict=True)
    review_path = args.reviewed_signature_rows.resolve(strict=True) if args.reviewed_signature_rows else None
    output_dir = args.output_dir.resolve()
    if output_dir.exists() or output_dir.is_relative_to(cohort_path.parent):
        parser.error("output directory must be new and outside the frozen cohort directory")

    rows = build_rows(
        _read_csv(cohort_path),
        _read_csv(findings_path),
        _read_csv(review_path) if review_path else None,
    )
    if not rows:
        parser.error("cohort manifest has no selected runs")
    output_dir.mkdir(parents=True)
    output_csv = output_dir / "component_exposure_v2.csv"
    with output_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    receipt = {
        "method_version": "component_exposure_v2",
        "cohort_manifest": str(cohort_path),
        "cohort_manifest_sha256": _sha256(cohort_path),
        "finding_rows": str(findings_path),
        "finding_rows_sha256": _sha256(findings_path),
        "selected_app_builds": len(rows),
        "raw_finding_rows": sum(int(row["raw_finding_rows"]) for row in rows),
        "exported_component_identities": sum(int(row["exported_component_identities"]) for row in rows),
        "components_without_manifest_permission": sum(int(row["ipc_components_without_permission_guard"]) for row in rows),
        "components_labeled_weak_by_detector": sum(int(row["ipc_components_with_weak_permission_guard"]) for row in rows),
        "reviewed_signature_false_weak_rows": sum(int(row["reviewed_signature_false_weak_rows"]) for row in rows),
        "weak_guard_labels_after_known_corrections": sum(int(row["weak_guard_labels_after_known_corrections"]) for row in rows),
        "reviewed_signature_rows": str(review_path) if review_path else None,
        "reviewed_signature_rows_sha256": _sha256(review_path) if review_path else None,
        "metric_definitions": {
            "components_without_manifest_permission": (
                "Unique component identities with no manifest permission or at least"
                " one unguarded provider read/write direction."
            ),
            "components_labeled_weak_by_detector": (
                "Unique identities carrying a historical weak-guard finding ID;"
                " this is not an adjudicated weak-guard count."
            ),
            "weak_guard_labels_after_known_corrections": (
                "Historical weak-guard identities remaining after removal of exact"
                " reviewed numeric-signature false-weak rows; still unadjudicated."
            ),
            "exported_component_identities": (
                "Distinct identities represented by selected detector findings;"
                " not a full independent manifest inventory."
            ),
        },
        "unknown_guard_not_in_weak_count": True,
        "vulnerability_count": None,
    }
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output_csv)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    raise SystemExit(main())
