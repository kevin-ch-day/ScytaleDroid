#!/usr/bin/env python3
"""Read-only audit for migrating legacy device APK pulls into the APK library.

Scans legacy ``data/device_apks/<serial>/runs`` payloads and reports duplicate
APK bytes, package/version coverage, and proposed canonical library locations.
No files are modified.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.DeviceAnalysis.harvest import common  # noqa: E402
from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store  # noqa: E402


@dataclass(frozen=True)
class ApkAuditRow:
    legacy_path: str
    size_bytes: int
    sha256: str
    package_name: str
    version_code: str
    version_name: str
    split_label: str
    is_base: bool
    manifest_path: str
    canonical_blob_path: str
    proposed_library_dir: str
    can_migrate: bool
    blocked_reason: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=None, help="Legacy root; default data/device_apks.")
    parser.add_argument("--output-dir", default=None, help="Report directory; default output/audit/apk_library_migration/<stamp>.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return ROOT / "output" / "audit" / "apk_library_migration" / _stamp()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _nearest_manifest(path: Path, root: Path) -> Path | None:
    for parent in [path.parent, *path.parents]:
        if parent == root.parent:
            break
        candidate = parent / "harvest_package_manifest.json"
        if candidate.exists():
            return candidate
    return None


def _read_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _artifact_from_manifest(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    execution = manifest.get("execution") if isinstance(manifest.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return {}
    rel = common.normalise_local_path(path)
    for item in observed:
        if not isinstance(item, dict):
            continue
        local = str(item.get("local_artifact_path") or "").strip()
        file_name = str(item.get("file_name") or "").strip()
        if local == rel or file_name == path.name:
            return item
    return {}


def _planned_hash_from_manifest(manifest: dict[str, Any]) -> str:
    package = manifest.get("package") if isinstance(manifest.get("package"), dict) else {}
    planning = manifest.get("planning") if isinstance(manifest.get("planning"), dict) else {}
    expected = planning.get("expected_artifacts")
    rows = []
    if isinstance(expected, list):
        for item in expected:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "role": "base" if item.get("is_base") is True else "split",
                    "split_name": str(item.get("split_label") or item.get("file_name") or ""),
                    "file_name": str(item.get("file_name") or ""),
                }
            )
    rows.sort(key=lambda row: (row["role"], row["split_name"], row["file_name"]))
    payload = {
        "package_name": str(package.get("package_name") or ""),
        "version_code": str(package.get("version_code") or ""),
        "artifacts": rows,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def build_audit(*, source_root: Path) -> tuple[list[ApkAuditRow], dict[str, Any]]:
    root = source_root.expanduser().resolve()
    rows: list[ApkAuditRow] = []
    for apk_path in sorted(root.rglob("*.apk")) if root.exists() else []:
        if not apk_path.is_file():
            continue
        manifest_path = _nearest_manifest(apk_path, root)
        manifest = _read_json(manifest_path)
        package = manifest.get("package") if isinstance(manifest.get("package"), dict) else {}
        artifact = _artifact_from_manifest(apk_path, manifest)
        package_name = str(package.get("package_name") or "").strip()
        version_code = str(package.get("version_code") or "").strip()
        version_name = str(package.get("version_name") or "").strip()
        digest = _sha256(apk_path)
        canonical = artifact_store.canonical_apk_path(digest)
        split_hash = _planned_hash_from_manifest(manifest) if manifest else ""
        proposed_dir = (
            apk_library_service.split_set_dir(package_name, version_code or "unknown", split_hash)
            if package_name and split_hash
            else Path("")
        )
        blocked = ""
        if not manifest:
            blocked = "missing_harvest_package_manifest"
        elif not package_name:
            blocked = "missing_package_name"
        elif not version_code:
            blocked = "missing_version_code"
        elif not split_hash:
            blocked = "missing_split_set_identity"
        rows.append(
            ApkAuditRow(
                legacy_path=artifact_store.repo_relative_path(apk_path),
                size_bytes=apk_path.stat().st_size,
                sha256=digest,
                package_name=package_name,
                version_code=version_code,
                version_name=version_name,
                split_label=str(artifact.get("split_label") or ("base" if artifact.get("is_base") else apk_path.stem)),
                is_base=bool(artifact.get("is_base")),
                manifest_path=artifact_store.repo_relative_path(manifest_path) if manifest_path else "",
                canonical_blob_path=artifact_store.repo_relative_path(canonical),
                proposed_library_dir=artifact_store.repo_relative_path(proposed_dir) if str(proposed_dir) else "",
                can_migrate=not blocked,
                blocked_reason=blocked,
            )
        )

    by_sha: dict[str, list[ApkAuditRow]] = defaultdict(list)
    for row in rows:
        by_sha[row.sha256].append(row)
    duplicate_groups = {sha: group for sha, group in by_sha.items() if len(group) > 1}
    duplicate_bytes_wasted = sum(sum(r.size_bytes for r in group) - max(r.size_bytes for r in group) for group in duplicate_groups.values())
    package_versions = {(r.package_name, r.version_code) for r in rows if r.package_name and r.version_code}
    split_sets = {(r.package_name, r.version_code, r.proposed_library_dir) for r in rows if r.proposed_library_dir}
    blocked = Counter(r.blocked_reason for r in rows if r.blocked_reason)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_root": artifact_store.repo_relative_path(root),
        "total_apk_files": len(rows),
        "total_apk_bytes": sum(r.size_bytes for r in rows),
        "unique_sha256": len(by_sha),
        "duplicate_apk_files": sum(len(group) - 1 for group in duplicate_groups.values()),
        "duplicate_sha256_groups": len(duplicate_groups),
        "duplicate_bytes_wasted": duplicate_bytes_wasted,
        "packages_found": len({r.package_name for r in rows if r.package_name}),
        "package_versions_found": len(package_versions),
        "split_sets_found": len(split_sets),
        "apks_can_migrate_cleanly": sum(1 for r in rows if r.can_migrate),
        "apks_blocked_from_migration": sum(1 for r in rows if not r.can_migrate),
        "blocked_reasons": dict(blocked),
        "static_runs_legacy_path_refs": "not_mutated_audit_only",
    }
    return rows, summary


def _write_csv(path: Path, rows: list[ApkAuditRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(rows[0]).keys()) if rows else list(ApkAuditRow.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    source_root = Path(args.source_root).expanduser().resolve() if args.source_root else artifact_store.device_apks_root()
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else _default_output_dir()
    rows, summary = build_audit(source_root=source_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "apk_library_migration_candidates.csv"
    summary_path = output_dir / "summary.json"
    _write_csv(csv_path, rows)
    summary.update(
        {
            "output_dir": str(output_dir),
            "csv_report": str(csv_path),
            "summary_json": str(summary_path),
        }
    )
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("# APK library migration audit")
        print(f"output: {output_dir}")
        print(
            f"APKs: {summary['total_apk_files']} files, {summary['total_apk_bytes']} bytes; "
            f"duplicates={summary['duplicate_apk_files']} files / {summary['duplicate_bytes_wasted']} bytes wasted"
        )
        print(
            f"packages={summary['packages_found']} versions={summary['package_versions_found']} "
            f"split_sets={summary['split_sets_found']} clean={summary['apks_can_migrate_cleanly']} "
            f"blocked={summary['apks_blocked_from_migration']}"
        )
        print(csv_path)
        print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
