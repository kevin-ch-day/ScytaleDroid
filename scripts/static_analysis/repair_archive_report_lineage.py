#!/usr/bin/env python3
"""Repair missing static archive lineage from unanimous sibling reports.

Dry-run is the default. ``--apply`` writes timestamped byte-for-byte backups
and a JSON receipt. The tool never changes findings or any other non-metadata
report content, and it never overwrites an existing lineage value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LINEAGE_FIELDS = (
    "execution_id",
    "base_apk_sha256",
    "artifact_set_hash",
    "artifact_manifest_sha256",
    "identity_valid",
)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _semantic_payload_sha256(report: dict[str, Any]) -> str:
    payload = {key: value for key, value in report.items() if key != "metadata"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(encoded)


def _load_reports(archive_dir: Path) -> list[tuple[Path, bytes, dict[str, Any]]]:
    reports: list[tuple[Path, bytes, dict[str, Any]]] = []
    for path in sorted(archive_dir.glob("*.json")):
        raw = path.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("metadata"), dict):
            raise ValueError(f"invalid report object/metadata: {path}")
        reports.append((path, raw, payload))
    return reports


def plan_repairs(archive_dir: Path, *, session: str) -> list[dict[str, Any]]:
    """Return bounded repairs supported by unanimous same-package siblings."""

    reports = _load_reports(archive_dir)
    by_package: dict[str, list[tuple[Path, bytes, dict[str, Any]]]] = defaultdict(list)
    for row in reports:
        metadata = row[2]["metadata"]
        package = str(metadata.get("package_name") or "").strip()
        if package:
            by_package[package].append(row)

    repairs: list[dict[str, Any]] = []
    for package, package_reports in sorted(by_package.items()):
        for path, raw, report in package_reports:
            metadata = report["metadata"]
            missing = [field for field in LINEAGE_FIELDS if metadata.get(field) in (None, "")]
            if not missing:
                continue
            if metadata.get("is_split_member") is not False:
                raise ValueError(f"refusing non-base lineage repair: {path}")
            if str(metadata.get("session_stamp") or "") != session:
                raise ValueError(f"session mismatch in target: {path}")
            if str(metadata.get("sha256") or "").lower() != path.stem.lower():
                raise ValueError(f"target SHA-256 does not match archive filename: {path}")

            additions: dict[str, Any] = {}
            for field in missing:
                values = {
                    sibling[2]["metadata"].get(field)
                    for sibling in package_reports
                    if sibling[0] != path
                    and sibling[2]["metadata"].get(field) not in (None, "")
                }
                if len(values) != 1:
                    raise ValueError(
                        f"no unanimous sibling value for {package} {field}: {sorted(map(str, values))}"
                    )
                additions[field] = values.pop()

            if additions.get("base_apk_sha256") != metadata.get("sha256"):
                raise ValueError(f"sibling base hash does not identify repair target: {path}")
            repairs.append(
                {
                    "path": path,
                    "raw": raw,
                    "report": report,
                    "package_name": package,
                    "additions": additions,
                }
            )
    return repairs


def plan_latest_mirror_repairs(
    archive_dir: Path,
    latest_dir: Path,
) -> list[dict[str, Any]]:
    """Fill missing mirror lineage only when analytical content matches archive."""

    repairs: list[dict[str, Any]] = []
    for archive_path, _raw, archive_report in _load_reports(archive_dir):
        latest_path = latest_dir / archive_path.name
        if not latest_path.is_file():
            continue
        latest_raw = latest_path.read_bytes()
        latest_report = json.loads(latest_raw)
        if not isinstance(latest_report, dict) or not isinstance(latest_report.get("metadata"), dict):
            raise ValueError(f"invalid latest mirror: {latest_path}")
        if _semantic_payload_sha256(archive_report) != _semantic_payload_sha256(latest_report):
            raise ValueError(f"latest mirror analytical payload differs from archive: {latest_path}")
        archive_metadata = archive_report["metadata"]
        latest_metadata = latest_report["metadata"]
        if latest_metadata.get("package_name") != archive_metadata.get("package_name"):
            raise ValueError(f"latest mirror package differs from archive: {latest_path}")
        additions: dict[str, Any] = {}
        for field in LINEAGE_FIELDS:
            archive_value = archive_metadata.get(field)
            latest_value = latest_metadata.get(field)
            if latest_value in (None, "") and archive_value not in (None, ""):
                additions[field] = archive_value
            elif latest_value not in (None, "") and latest_value != archive_value:
                raise ValueError(f"latest mirror conflicts on {field}: {latest_path}")
        if additions:
            repairs.append(
                {
                    "path": latest_path,
                    "raw": latest_raw,
                    "report": latest_report,
                    "package_name": archive_metadata.get("package_name"),
                    "additions": additions,
                }
            )
    return repairs


def apply_repairs(
    repairs: list[dict[str, Any]],
    *,
    backup_dir: Path,
) -> list[dict[str, Any]]:
    backup_dir.mkdir(parents=True, exist_ok=False)
    receipt_rows: list[dict[str, Any]] = []
    for repair in repairs:
        path: Path = repair["path"]
        raw: bytes = repair["raw"]
        report: dict[str, Any] = repair["report"]
        before_semantic = _semantic_payload_sha256(report)
        backup_path = backup_dir / path.name
        backup_path.write_bytes(raw)

        metadata = report["metadata"]
        for field, value in repair["additions"].items():
            if metadata.get(field) not in (None, ""):
                raise ValueError(f"refusing to overwrite {field}: {path}")
            metadata[field] = value
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            handle.write(encoded)
            temp_path = Path(handle.name)
        os.replace(temp_path, path)

        after = json.loads(path.read_text(encoding="utf-8"))
        after_semantic = _semantic_payload_sha256(after)
        if before_semantic != after_semantic:
            shutil.copy2(backup_path, path)
            raise RuntimeError(f"non-metadata payload changed; restored backup: {path}")
        receipt_rows.append(
            {
                "package_name": repair["package_name"],
                "path": str(path),
                "backup_path": str(backup_path),
                "added_fields": sorted(repair["additions"]),
                "before_file_sha256": _sha256_bytes(raw),
                "after_file_sha256": _sha256_bytes(path.read_bytes()),
                "non_metadata_payload_sha256_before": before_semantic,
                "non_metadata_payload_sha256_after": after_semantic,
            }
        )
    return receipt_rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true", help="Apply planned fills; default is read-only.")
    parser.add_argument(
        "--include-latest-mirrors",
        action="store_true",
        help="Also repair matching latest mirrors whose analytical payload equals the archive.",
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    session = str(args.session).strip()
    archive_dir = repo / "data" / "static_analysis" / "reports" / "archive" / session
    if not archive_dir.is_dir():
        parser.error(f"archive directory not found: {archive_dir}")
    repairs = plan_repairs(archive_dir, session=session)
    latest_repairs = (
        plan_latest_mirror_repairs(
            archive_dir,
            repo / "data" / "static_analysis" / "reports" / "latest",
        )
        if args.include_latest_mirrors
        else []
    )
    now = datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "operation": "static_archive_lineage_fill_from_unanimous_siblings",
        "session_stamp": session,
        "generated_at_utc": now.isoformat().replace("+00:00", "Z"),
        "mode": "apply" if args.apply else "dry_run",
        "planned_report_count": len(repairs),
        "planned_latest_mirror_count": len(latest_repairs),
        "reports": [
            {
                "package_name": row["package_name"],
                "path": str(row["path"]),
                "added_fields": sorted(row["additions"]),
            }
            for row in repairs
        ],
    }
    if args.apply and repairs:
        backup_dir = (
            repo
            / "data"
            / "static_analysis"
            / "reports"
            / "repair_backups"
            / session
            / stamp
        )
        receipt["reports"] = apply_repairs(repairs, backup_dir=backup_dir)
        receipt["backup_dir"] = str(backup_dir)
    if args.apply and latest_repairs:
        latest_backup_dir = (
            repo
            / "data"
            / "static_analysis"
            / "reports"
            / "repair_backups"
            / session
            / f"{stamp}-latest"
        )
        receipt["latest_mirrors"] = apply_repairs(
            latest_repairs,
            backup_dir=latest_backup_dir,
        )
        receipt["latest_backup_dir"] = str(latest_backup_dir)
    if args.apply and (repairs or latest_repairs):
        receipt_path = (
            repo
            / "output"
            / "audit"
            / "run_artifacts"
            / f"{session}_lineage_repair_{stamp}.json"
        )
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        receipt["receipt_path"] = str(receipt_path)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
