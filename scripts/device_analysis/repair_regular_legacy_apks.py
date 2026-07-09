#!/usr/bin/env python3
"""Canonicalize regular APK files left in legacy harvest run folders.

The default mode is read-only. With ``--apply`` the script copies missing APK
bytes into ``data/store/apk/sha256`` and registers package/version metadata in
``data/android_apks``. It does not delete or replace legacy APK files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=None)
    parser.add_argument("--serial", default="ZY22JK89DR")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--apply", action="store_true", help="Copy missing canonical blobs and index metadata.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def build_rows(
    *,
    data_root: Path,
    serial: str,
    artifact_store: Any,
    apk_library_service: Any,
    limit: int = 0,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = data_root / "device_apks" / serial / "runs"
    for apk_path in sorted(root.rglob("*.apk")) if root.exists() else []:
        if apk_path.is_symlink() or not apk_path.is_file():
            continue
        manifest_path = apk_path.parent / "harvest_package_manifest.json"
        payload = _read_json(manifest_path)
        sha = _sha256(apk_path)
        canonical = artifact_store.canonical_apk_path(sha)
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        observed = execution.get("observed_artifacts") if isinstance(execution.get("observed_artifacts"), list) else []
        plan = apk_library_service._plan_from_legacy_receipt(payload)
        artifact_plan = _matching_plan_artifact(plan, apk_path.name) if plan is not None else None
        planned_count = len(plan.artifacts) if plan is not None else 0
        available_names = {p.name for p in apk_path.parent.glob("*.apk") if p.exists()}
        complete_planned_artifacts_available = bool(
            plan is not None and all(artifact.file_name in available_names for artifact in plan.artifacts)
        )
        library_manifest = _find_library_manifest(sha, artifact_store=artifact_store)
        partial_manifest = _find_partial_manifest(sha, data_root=data_root)
        if canonical.exists() and library_manifest:
            action = "already_canonical_and_indexed"
            safe_to_canonicalize = True
        elif canonical.exists() and partial_manifest:
            action = "already_canonical_and_partial_indexed"
            safe_to_canonicalize = True
        elif canonical.exists():
            action = "index_existing_canonical_blob" if complete_planned_artifacts_available else "index_partial_legacy_artifact"
            safe_to_canonicalize = plan is not None and artifact_plan is not None
        else:
            action = "copy_to_canonical_and_index" if complete_planned_artifacts_available else "copy_to_canonical_and_index_partial"
            safe_to_canonicalize = plan is not None and artifact_plan is not None
        if not manifest_path.exists():
            action = "blocked_missing_manifest"
            safe_to_canonicalize = False
        elif plan is None:
            action = "blocked_missing_planning"
            safe_to_canonicalize = False
        elif artifact_plan is None:
            action = "blocked_no_matching_planned_artifact"
            safe_to_canonicalize = False
        rows.append(
            {
                "path": artifact_store.repo_relative_path(apk_path),
                "session_label": _session_from_path(apk_path),
                "package_name": str(package.get("package_name") or ""),
                "version_code": str(package.get("version_code") or ""),
                "version_name": str(package.get("version_name") or ""),
                "file_name": apk_path.name,
                "size_bytes": apk_path.stat().st_size,
                "sha256": sha,
                "canonical_path": artifact_store.repo_relative_path(canonical),
                "canonical_exists": canonical.exists(),
                "library_manifest_path": artifact_store.repo_relative_path(library_manifest) if library_manifest else "",
                "partial_manifest_path": artifact_store.repo_relative_path(partial_manifest) if partial_manifest else "",
                "manifest_path": artifact_store.repo_relative_path(manifest_path),
                "manifest_observed_artifact_count": len(observed),
                "plan_reconstructable": plan is not None,
                "planned_artifact_match": artifact_plan is not None,
                "planned_artifact_count": planned_count,
                "available_apk_count": len(available_names),
                "complete_planned_artifacts_available": complete_planned_artifacts_available,
                "safe_to_canonicalize": safe_to_canonicalize,
                "action": action,
                "applied": False,
                "reason": action,
            }
        )
        if limit > 0 and len(rows) >= limit:
            break
    return rows


def apply_rows(rows: list[dict[str, Any]], *, artifact_store: Any, apk_library_service: Any) -> None:
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactResult, PullResult

    for row in rows:
        if not row["safe_to_canonicalize"]:
            continue
        if row["action"] in {"already_canonical_and_indexed", "already_canonical_and_partial_indexed"}:
            continue
        apk_path = Path(str(row["path"]))
        sha = str(row["sha256"])
        canonical = artifact_store.canonical_apk_path(sha)
        if not canonical.exists():
            materialized = artifact_store.materialize_apk(apk_path, sha256_digest=sha, move=False)
            row["canonical_path"] = artifact_store.repo_relative_path(materialized)
        manifest = Path(str(row["manifest_path"]))
        payload = _read_json(manifest)
        plan = apk_library_service._plan_from_legacy_receipt(payload)
        artifact_plan = _matching_plan_artifact(plan, str(row["file_name"])) if plan is not None else None
        if plan is None or artifact_plan is None:
            row["reason"] = "blocked_plan_changed_during_apply"
            continue
        if not row["complete_planned_artifacts_available"]:
            partial = _write_partial_artifact_manifest(
                row=row,
                plan=plan,
                artifact_plan=artifact_plan,
                canonical=canonical,
                artifact_store=artifact_store,
                apk_library_service=apk_library_service,
            )
            row["partial_manifest_path"] = artifact_store.repo_relative_path(partial)
            row["applied"] = True
            row["reason"] = "partial_artifact_indexed"
            continue
        result = PullResult(plan=plan)
        result.ok.append(
            ArtifactResult(
                file_name=artifact_plan.file_name,
                apk_id=None,
                dest_path=canonical,
                source_path=artifact_plan.source_path,
                sha256=sha,
                file_size=int(row["size_bytes"]),
                artifact_label=artifact_plan.artifact,
                is_base=not artifact_plan.is_split_member,
                observed_source_path=artifact_plan.source_path,
                canonical_store_path=artifact_store.repo_relative_path(canonical),
            )
        )
        entry = apk_library_service.register_result(
            result,
            serial="",
            session_stamp=str(row["session_label"]),
            source="legacy_regular_apk_repair",
        )
        if entry is None:
            row["reason"] = "library_registration_failed"
            continue
        row["library_manifest_path"] = artifact_store.repo_relative_path(entry.manifest_path)
        row["applied"] = True
        row["reason"] = "applied"


def _matching_plan_artifact(plan: Any, file_name: str) -> Any | None:
    if plan is None:
        return None
    for artifact in plan.artifacts:
        if artifact.file_name == file_name:
            return artifact
    return None


def _find_library_manifest(sha: str, *, artifact_store: Any) -> Path | None:
    root = artifact_store.data_root() / "android_apks" / "packages"
    for manifest in root.glob("*/*/split_sets/*/package_manifest.json"):
        if _manifest_has_sha(manifest, sha):
            return manifest
    for manifest in root.glob("*/*/split_sets/*/content_variants/*/package_manifest.json"):
        if _manifest_has_sha(manifest, sha):
            return manifest
    return None


def _find_partial_manifest(sha: str, *, data_root: Path) -> Path | None:
    root = data_root / "android_apks" / "partial_artifacts"
    matches = list(root.glob(f"*/*/{sha}/artifact_manifest.json"))
    return matches[0] if matches else None


def _write_partial_artifact_manifest(
    *,
    row: dict[str, Any],
    plan: Any,
    artifact_plan: Any,
    canonical: Path,
    artifact_store: Any,
    apk_library_service: Any,
) -> Path:
    package = str(row["package_name"] or plan.inventory.package_name)
    version = str(row["version_code"] or plan.inventory.version_code or "unknown")
    sha = str(row["sha256"])
    out = (
        artifact_store.data_root()
        / "android_apks"
        / "partial_artifacts"
        / package
        / version
        / sha
        / "artifact_manifest.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "apk_library_partial_artifact_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "package_name": package,
        "version_code": version,
        "version_name": str(row.get("version_name") or ""),
        "session_label": str(row.get("session_label") or ""),
        "legacy_path": str(row.get("path") or ""),
        "manifest_path": str(row.get("manifest_path") or ""),
        "planned_split_set_hash": apk_library_service.planned_split_set_hash_for_plan(plan),
        "planned_artifact_count": int(row.get("planned_artifact_count") or 0),
        "available_apk_count": int(row.get("available_apk_count") or 0),
        "complete_planned_artifacts_available": False,
        "artifact": {
            "file_name": artifact_plan.file_name,
            "role": "split" if artifact_plan.is_split_member else "base",
            "split_name": artifact_plan.artifact,
            "device_path": artifact_plan.source_path,
            "sha256": sha,
            "size_bytes": int(row.get("size_bytes") or 0),
            "canonical_path": artifact_store.repo_relative_path(canonical),
        },
        "source": "legacy_regular_apk_repair",
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def _manifest_has_sha(path: Path, sha: str) -> bool:
    payload = _read_json(path)
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
    return any(isinstance(item, dict) and str(item.get("sha256") or "").lower() == sha for item in artifacts)


def _session_from_path(path: Path) -> str:
    parts = path.parts
    if "runs" not in parts:
        return ""
    idx = parts.index("runs")
    return parts[idx + 1] if len(parts) > idx + 1 else ""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store

    data_root = args.data_root or artifact_store.data_root()
    output_dir = args.output_dir or (ROOT / "output" / "audit" / "regular_legacy_apk_repair" / _stamp())
    rows = build_rows(
        data_root=data_root,
        serial=args.serial,
        artifact_store=artifact_store,
        apk_library_service=apk_library_service,
        limit=max(args.limit, 0),
    )
    if args.apply:
        apply_rows(rows, artifact_store=artifact_store, apk_library_service=apk_library_service)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "regular_legacy_apks.csv"
    summary_path = output_dir / "summary.json"
    _write_csv(csv_path, rows)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "mode": "apply" if args.apply else "dry_run",
        "regular_apk_count": len(rows),
        "safe_to_canonicalize": sum(1 for row in rows if row["safe_to_canonicalize"]),
        "canonical_missing_count": sum(1 for row in rows if not row["canonical_exists"]),
        "already_canonical_and_indexed_count": sum(1 for row in rows if row["action"] == "already_canonical_and_indexed"),
        "already_partial_indexed_count": sum(1 for row in rows if row["action"] == "already_canonical_and_partial_indexed"),
        "partial_artifact_indexed_count": sum(1 for row in rows if row["reason"] == "partial_artifact_indexed"),
        "applied_count": sum(1 for row in rows if row["applied"]),
        "blocked_count": sum(1 for row in rows if not row["safe_to_canonicalize"]),
        "bytes_total": sum(int(row["size_bytes"]) for row in rows),
        "bytes_canonical_missing": sum(int(row["size_bytes"]) for row in rows if not row["canonical_exists"]),
        "reasons": dict(sorted({row["reason"]: sum(1 for r in rows if r["reason"] == row["reason"]) for row in rows}.items())),
        "csv_report": csv_path.as_posix(),
        "summary_json": summary_path.as_posix(),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"regular APKs: {summary['regular_apk_count']} safe: {summary['safe_to_canonicalize']} applied: {summary['applied_count']}")
        print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
