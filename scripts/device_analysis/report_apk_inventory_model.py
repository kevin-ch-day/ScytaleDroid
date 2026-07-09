#!/usr/bin/env python3
"""Read-only APK package/version/split-set inventory report.

This report treats ``data/android_apks`` as the package/version library,
``data/store/apk/sha256`` as the logical canonical byte surface, and legacy
``data/device_apks/<serial>/runs`` folders as observation history.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping


DEFAULT_COLD_ROOT = Path("/mnt/MERCURY_DATA_V2/scytaledroid_artifacts/apk_store/cold")


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    cold_root: Path = DEFAULT_COLD_ROOT,
    stamp: str | None = None,
    write_outputs: bool = True,
) -> dict[str, Any]:
    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "apk_inventory_model" / stamp

    canonical = _index_canonical_store(data_root=data_root, cold_root=cold_root)
    library = _load_apk_library(data_root=data_root, canonical=canonical)
    partial_artifacts = _load_partial_artifacts(data_root=data_root, canonical=canonical)
    library["library_shas"].update({row["sha256"] for row in partial_artifacts if row["sha256"]})
    from scytaledroid.DeviceAnalysis.services import apk_library_service

    receipts = _load_harvest_receipts(data_root=data_root, apk_library_service=apk_library_service)
    cold_audit = _load_latest_cold_audit(repo_root / "output" / "audit" / "apk_cold_promotion")

    library_content_hashes = {row["content_split_set_hash"] for row in library["split_sets"] if row["content_split_set_hash"]}
    library_by_planned_hash = {
        (row["package_name"], row["version_code"], row["planned_split_set_hash"]): row
        for row in library["split_sets"]
        if row["planned_split_set_hash"]
    }
    seed_rows: list[dict[str, Any]] = []
    content_variant_rows: list[dict[str, Any]] = []
    blocked_rows: list[dict[str, Any]] = []
    receipt_observations = Counter()
    for receipt in receipts:
        package = receipt["package_name"]
        version_code = receipt["version_code"]
        key = (package, version_code)
        receipt_observations[key] += 1
        if receipt["seedable"]:
            if receipt["content_split_set_hash"] not in library_content_hashes:
                planned_key = (package, version_code, receipt["planned_split_set_hash"])
                planned_hit = library_by_planned_hash.get(planned_key) if receipt["planned_split_set_hash"] else None
                if planned_hit and planned_hit["content_split_set_hash"] != receipt["content_split_set_hash"]:
                    content_variant_rows.append(
                        {
                            **receipt,
                            "reason": "planned_split_set_hash_collision",
                            "existing_manifest_path": planned_hit["manifest_path"],
                            "existing_content_split_set_hash": planned_hit["content_split_set_hash"],
                        }
                    )
                else:
                    seed_rows.append(receipt)
        else:
            blocked_rows.append(receipt)

    package_versions: list[dict[str, Any]] = []
    by_package_versions: dict[str, set[str]] = defaultdict(set)
    for row in library["package_versions"]:
        key = (row["package_name"], row["version_code"])
        split_rows = [
            split
            for split in library["split_sets"]
            if split["package_name"] == row["package_name"] and split["version_code"] == row["version_code"]
        ]
        status_counts = Counter(split["byte_status"] for split in split_rows)
        shas = {sha for split in split_rows for sha in split["sha256s"].split(";") if sha}
        audit_classes = Counter(cold_audit["classes_by_sha"].get(sha, "") for sha in shas)
        by_package_versions[row["package_name"]].add(row["version_code"])
        package_versions.append(
            {
                **row,
                "split_set_count": len(split_rows),
                "artifact_count": sum(int(split["artifact_count"] or 0) for split in split_rows),
                "byte_status": _version_byte_status(status_counts),
                "hot_artifacts": sum(int(split["hot_artifacts"] or 0) for split in split_rows),
                "cold_artifacts": sum(int(split["cold_artifacts"] or 0) for split in split_rows),
                "missing_artifacts": sum(int(split["missing_artifacts"] or 0) for split in split_rows),
                "harvest_observation_count": receipt_observations[key],
                "current_research_protected_artifacts": audit_classes.get("KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA", 0),
                "paper_protected_artifacts": audit_classes.get("KEEP_HOT_SELECTED_PAPER_TARGET", 0),
                "current_installed_protected_artifacts": audit_classes.get("KEEP_HOT_CURRENT_INSTALLED_BUILD", 0),
                "cold_candidate_artifacts": audit_classes.get("PROMOTE_COLD_PRIOR_VERSION_CANDIDATE", 0),
            }
        )

    legacy_dependencies = _summarize_legacy_dependencies(data_root=data_root, library_shas=library["library_shas"], canonical=canonical)

    summary = {
        "schema_version": "apk_inventory_model_report_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "total_packages": len(by_package_versions),
        "total_package_version_entries": len(package_versions),
        "total_split_sets": len(library["split_sets"]),
        "total_library_artifacts": len(library["library_shas"]),
        "total_partial_artifacts": len(partial_artifacts),
        "canonical_apk_blobs": canonical["total"],
        "hot_local_blobs": canonical["hot"],
        "cold_mercury_blobs": canonical["cold"],
        "missing_or_broken_canonical_blobs": canonical["missing"],
        "byte_available_split_sets": sum(1 for row in library["split_sets"] if row["byte_available"] == "yes"),
        "hot_local_split_sets": sum(1 for row in library["split_sets"] if row["byte_status"] == "hot_local"),
        "cold_mercury_split_sets": sum(1 for row in library["split_sets"] if row["byte_status"] == "cold_mercury"),
        "mixed_hot_cold_split_sets": sum(1 for row in library["split_sets"] if row["byte_status"] == "mixed_hot_cold"),
        "metadata_only_split_sets": sum(1 for row in library["split_sets"] if row["byte_status"] == "metadata_only"),
        "missing_byte_split_sets": sum(1 for row in library["split_sets"] if row["byte_status"] == "missing"),
        "packages_with_multiple_versions": sum(1 for versions in by_package_versions.values() if len(versions) > 1),
        "versions_missing_from_android_apks_but_seedable_from_receipts": len(seed_rows),
        "receipt_rows_blocked_by_planned_split_set_collision": len(content_variant_rows),
        "receipt_rows_blocked_from_seed": len(blocked_rows),
        "legacy_run_session_count": len(legacy_dependencies),
        "legacy_sessions_storage_safe_to_archive_later": sum(1 for row in legacy_dependencies if row["safe_to_archive_later"] == "yes"),
        "db_lineage": "not_connected_filesystem_report",
    }

    outputs = {
        "summary_json": output_root / "summary.json",
        "package_versions_csv": output_root / "package_versions.csv",
        "split_sets_csv": output_root / "split_sets.csv",
        "partial_artifacts_csv": output_root / "partial_artifacts.csv",
        "legacy_run_dependencies_csv": output_root / "legacy_run_dependencies.csv",
        "seed_candidates_csv": output_root / "seed_candidates.csv",
        "content_variant_collisions_csv": output_root / "content_variant_collisions.csv",
        "blocked_csv": output_root / "blocked.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_csv(outputs["package_versions_csv"], package_versions)
        _write_csv(outputs["split_sets_csv"], _strip_internal(library["split_sets"]))
        _write_csv(outputs["partial_artifacts_csv"], partial_artifacts)
        _write_csv(outputs["legacy_run_dependencies_csv"], legacy_dependencies)
        _write_csv(outputs["seed_candidates_csv"], seed_rows)
        _write_csv(outputs["content_variant_collisions_csv"], content_variant_rows)
        _write_csv(outputs["blocked_csv"], blocked_rows)

    return {
        "summary": summary,
        "outputs": {key: path.as_posix() for key, path in outputs.items()},
        "package_versions": package_versions,
        "split_sets": library["split_sets"],
        "partial_artifacts": partial_artifacts,
        "seed_candidates": seed_rows,
        "content_variant_collisions": content_variant_rows,
        "blocked": blocked_rows,
        "legacy_run_dependencies": legacy_dependencies,
    }


def _index_canonical_store(*, data_root: Path, cold_root: Path) -> dict[str, Any]:
    sha_root = data_root / "store" / "apk" / "sha256"
    by_sha: dict[str, dict[str, Any]] = {}
    counts = Counter()
    for path in sha_root.glob("*/*.apk"):
        sha = path.stem.lower()
        if len(sha) != 64:
            continue
        status = "missing"
        resolved = ""
        size = 0
        if path.is_symlink():
            try:
                target = path.resolve(strict=True)
                resolved = target.as_posix()
                if target.is_file():
                    size = target.stat().st_size
                    status = "cold" if _inside(target, cold_root) else "symlink"
                else:
                    status = "missing"
            except FileNotFoundError:
                status = "missing"
        elif path.is_file():
            status = "hot"
            resolved = path.resolve(strict=False).as_posix()
            size = path.stat().st_size
        counts[status] += 1
        by_sha[sha] = {"path": path.as_posix(), "status": status, "resolved_path": resolved, "size_bytes": size}
    return {
        "by_sha": by_sha,
        "total": len(by_sha),
        "hot": counts["hot"],
        "cold": counts["cold"],
        "missing": counts["missing"],
        "symlink_other": counts["symlink"],
    }


def _load_apk_library(*, data_root: Path, canonical: Mapping[str, Any]) -> dict[str, Any]:
    root = data_root / "android_apks" / "packages"
    package_versions: list[dict[str, Any]] = []
    split_sets: list[dict[str, Any]] = []
    library_shas: set[str] = set()
    for version_manifest in sorted(root.glob("*/*/package_manifest.json")):
        version_payload = _read_json(version_manifest)
        if not version_payload:
            continue
        package = str(version_payload.get("package_name") or version_manifest.parent.parent.name)
        version_code = str(version_payload.get("version_code") or version_manifest.parent.name)
        package_versions.append(
            {
                "package_name": package,
                "version_code": version_code,
                "version_name": str(version_payload.get("version_name") or ""),
                "first_seen": str(version_payload.get("first_seen_at") or ""),
                "last_seen": str(version_payload.get("last_seen_at") or ""),
            }
        )
        for split_manifest in _iter_split_set_manifests(version_manifest.parent / "split_sets"):
            row, shas = _split_set_row(
                split_manifest,
                package=package,
                version_code=version_code,
                canonical=canonical,
            )
            if row:
                split_sets.append(row)
                library_shas.update(shas)
    return {"package_versions": package_versions, "split_sets": split_sets, "library_shas": library_shas}


def _load_partial_artifacts(*, data_root: Path, canonical: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = data_root / "android_apks" / "partial_artifacts"
    for manifest in sorted(root.glob("*/*/*/artifact_manifest.json")):
        payload = _read_json(manifest)
        artifact = payload.get("artifact") if isinstance(payload.get("artifact"), dict) else {}
        sha = str(artifact.get("sha256") or "").strip().lower()
        if len(sha) != 64:
            continue
        status = canonical["by_sha"].get(sha, {}).get("status", "missing")
        rows.append(
            {
                "package_name": str(payload.get("package_name") or ""),
                "version_code": str(payload.get("version_code") or ""),
                "version_name": str(payload.get("version_name") or ""),
                "session_label": str(payload.get("session_label") or ""),
                "file_name": str(artifact.get("file_name") or ""),
                "role": str(artifact.get("role") or ""),
                "split_name": str(artifact.get("split_name") or ""),
                "sha256": sha,
                "size_bytes": int(artifact.get("size_bytes") or 0),
                "byte_status": str(status),
                "manifest_path": manifest.as_posix(),
                "canonical_path": str(artifact.get("canonical_path") or ""),
                "legacy_path": str(payload.get("legacy_path") or ""),
                "planned_split_set_hash": str(payload.get("planned_split_set_hash") or ""),
            }
        )
    return rows


def _iter_split_set_manifests(split_sets_root: Path) -> list[Path]:
    manifests = list(split_sets_root.glob("*/package_manifest.json"))
    manifests.extend(split_sets_root.glob("*/content_variants/*/package_manifest.json"))
    return sorted(manifests)


def _split_set_row(
    split_manifest: Path,
    *,
    package: str,
    version_code: str,
    canonical: Mapping[str, Any],
) -> tuple[dict[str, Any], set[str]]:
    payload = _read_json(split_manifest)
    if not payload:
        return {}, set()
    artifacts = [item for item in payload.get("artifacts") or [] if isinstance(item, dict)]
    statuses: list[str] = []
    shas: list[str] = []
    sizes = 0
    for artifact in artifacts:
        sha = str(artifact.get("sha256") or "").strip().lower()
        if len(sha) != 64:
            statuses.append("missing")
            continue
        shas.append(sha)
        status = canonical["by_sha"].get(sha, {}).get("status", "missing")
        statuses.append(str(status))
        sizes += int(artifact.get("size_bytes") or 0)
    status_counts = Counter(statuses)
    entry_kind = str(payload.get("entry_kind") or "planned_split_set")
    return (
        {
            "package_name": str(payload.get("package_name") or package),
            "version_code": str(payload.get("version_code") or version_code),
            "version_name": str(payload.get("version_name") or ""),
            "planned_split_set_hash": str(payload.get("planned_split_set_hash") or split_manifest.parent.name),
            "content_split_set_hash": str(payload.get("split_set_hash") or _content_split_set_hash(artifacts)),
            "entry_kind": entry_kind,
            "artifact_count": len(artifacts),
            "byte_available": "yes" if artifacts and status_counts["missing"] == 0 else "no",
            "byte_status": _split_set_byte_status(status_counts, bool(artifacts)),
            "hot_artifacts": status_counts["hot"],
            "cold_artifacts": status_counts["cold"],
            "missing_artifacts": status_counts["missing"],
            "size_bytes": sizes,
            "devices_seen": ";".join(payload.get("source_device_serials") or []),
            "first_seen": str(payload.get("first_seen_at") or ""),
            "last_seen": str(payload.get("last_seen_at") or ""),
            "source": str(payload.get("source") or ""),
            "manifest_path": split_manifest.as_posix(),
            "sha256s": ";".join(sorted(shas)),
        },
        set(shas),
    )


def _load_harvest_receipts(*, data_root: Path, apk_library_service: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for receipt in sorted((data_root / "receipts" / "harvest").glob("*/*.json")):
        payload = _read_json(receipt)
        if not payload:
            continue
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        observed = [item for item in execution.get("observed_artifacts") or [] if isinstance(item, dict)]
        shas = [str(item.get("sha256") or "").strip().lower() for item in observed]
        shas = [sha for sha in shas if len(sha) == 64]
        planned_hash, content_hash = _split_set_hashes_from_receipt(payload, observed, apk_library_service)
        missing_reason = ""
        if not observed:
            missing_reason = "missing_observed_artifacts"
        elif len(shas) != len(observed):
            missing_reason = "missing_sha256"
        elif any(not str(item.get("canonical_store_path") or "").strip() for item in observed):
            missing_reason = "missing_canonical_store_path"
        rows.append(
            {
                "receipt_path": receipt.as_posix(),
                "session_label": receipt.parent.name,
                "device_serial": str(package.get("device_serial") or ""),
                "package_name": str(package.get("package_name") or ""),
                "version_code": str(package.get("version_code") or ""),
                "version_name": str(package.get("version_name") or ""),
                "observed_artifact_count": len(observed),
                "sha256s": ";".join(sorted(shas)),
                "planned_split_set_hash": planned_hash,
                "content_split_set_hash": content_hash if shas else "",
                "seedable": not bool(missing_reason),
                "reason": missing_reason or "seedable",
            }
        )
    return rows


def _summarize_legacy_dependencies(*, data_root: Path, library_shas: set[str], canonical: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for session_dir in sorted((data_root / "device_apks").glob("*/runs/*")):
        if not session_dir.is_dir():
            continue
        files = [p for p in session_dir.rglob("*") if p.is_file() or p.is_symlink()]
        apk_paths = [p for p in files if p.name.endswith(".apk")]
        manifests = list(session_dir.rglob("harvest_package_manifest.json"))
        packages: set[str] = set()
        versions: set[str] = set()
        observed_shas: set[str] = set()
        for manifest in manifests:
            payload = _read_json(manifest)
            package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
            execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
            package_name = str(package.get("package_name") or "")
            version_code = str(package.get("version_code") or "")
            if package_name:
                packages.add(package_name)
            if package_name or version_code:
                versions.add(f"{package_name}@{version_code}")
            for item in execution.get("observed_artifacts") or []:
                if isinstance(item, dict):
                    sha = str(item.get("sha256") or "").strip().lower()
                    if len(sha) == 64:
                        observed_shas.add(sha)
        regular_apks = [p for p in apk_paths if not p.is_symlink() and p.is_file()]
        symlink_apks = [p for p in apk_paths if p.is_symlink()]
        broken_apk_symlinks = [p for p in symlink_apks if not p.exists()]
        all_indexed = "yes" if observed_shas and observed_shas <= library_shas else ("n/a" if not observed_shas else "no")
        all_available = "yes" if observed_shas and all(canonical["by_sha"].get(sha, {}).get("status") in {"hot", "cold", "symlink"} for sha in observed_shas) else ("n/a" if not observed_shas else "no")
        storage_safe = not regular_apks and not broken_apk_symlinks and all_indexed in {"yes", "n/a"} and all_available in {"yes", "n/a"}
        rows.append(
            {
                "serial": session_dir.parents[1].name,
                "session_label": session_dir.name,
                "session_path": session_dir.as_posix(),
                "total_files": len(files),
                "apk_symlinks": len(symlink_apks),
                "regular_apks": len(regular_apks),
                "broken_apk_symlinks": len(broken_apk_symlinks),
                "sidecars_manifests": sum(1 for p in files if p.suffix.lower() in {".json", ".csv"}),
                "packages_represented": len(packages),
                "versions_represented": len(versions),
                "observed_sha_count": len(observed_shas),
                "all_apk_artifacts_indexed_in_apk_library": all_indexed,
                "all_apk_bytes_available_hot_or_cold": all_available,
                "static_dynamic_references_requiring_session_path": "unknown_filesystem_only",
                "safe_to_archive_later": "yes" if storage_safe else "no",
                "reason": "storage_safe_review_static_dynamic_refs" if storage_safe else "regular_or_unindexed_or_missing_artifacts_present",
            }
        )
    return rows


def _load_latest_cold_audit(root: Path) -> dict[str, Any]:
    classes_by_sha: dict[str, str] = {}
    for path in _latest_files(root, ("candidates.csv", "blocked.csv")):
        with path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                sha = str(row.get("sha256") or "").strip().lower()
                if len(sha) == 64:
                    classes_by_sha[sha] = str(row.get("promotion_class") or "")
    return {"classes_by_sha": classes_by_sha}


def _latest_files(root: Path, names: Iterable[str]) -> list[Path]:
    dirs = sorted((p for p in root.glob("*") if p.is_dir()), key=lambda p: p.name)
    if not dirs:
        return []
    latest = dirs[-1]
    return [latest / name for name in names if (latest / name).exists()]


def _split_set_byte_status(status_counts: Counter[str], has_artifacts: bool) -> str:
    if not has_artifacts:
        return "metadata_only"
    if status_counts["missing"]:
        return "missing"
    if status_counts["cold"] and not status_counts["hot"] and not status_counts["symlink"]:
        return "cold_mercury"
    if status_counts["hot"] and not status_counts["cold"] and not status_counts["symlink"]:
        return "hot_local"
    return "mixed_hot_cold"


def _version_byte_status(status_counts: Counter[str]) -> str:
    if not status_counts:
        return "metadata_only"
    if status_counts["missing"]:
        return "missing"
    if status_counts["cold_mercury"] and len(status_counts) == 1:
        return "cold_mercury"
    if status_counts["hot_local"] and len(status_counts) == 1:
        return "hot_local"
    return "mixed_hot_cold"


def _content_split_set_hash(artifacts: list[Mapping[str, Any]]) -> str:
    rows = [
        {
            "role": "base" if str(item.get("role") or "").lower() == "base" else "split",
            "split_name": str(item.get("split_name") or ""),
            "sha256": str(item.get("sha256") or "").lower(),
        }
        for item in artifacts
        if str(item.get("sha256") or "")
    ]
    rows.sort(key=lambda row: (row["role"], row["split_name"], row["sha256"]))
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() if rows else ""


def _split_set_hashes_from_receipt(
    payload: dict[str, Any],
    observed: list[Mapping[str, Any]],
    apk_library_service: Any,
) -> tuple[str, str]:
    plan = apk_library_service._plan_from_legacy_receipt(payload)
    if plan is None:
        return "", _content_split_set_hash_from_receipt(observed)
    planned_hash = apk_library_service.planned_split_set_hash_for_plan(plan)
    rows = []
    for artifact in plan.artifacts:
        hit = apk_library_service._matching_observed_artifact(artifact, observed)
        if hit is None:
            return planned_hash, ""
        sha = str(hit.get("sha256") or "").lower()
        if len(sha) != 64:
            return planned_hash, ""
        rows.append(
            {
                "role": "split" if artifact.is_split_member else "base",
                "split_name": apk_library_service._split_name(
                    artifact.artifact,
                    artifact.file_name,
                    artifact.is_split_member,
                ),
                "sha256": sha,
            }
        )
    return planned_hash, apk_library_service._content_split_set_hash(rows)


def _content_split_set_hash_from_receipt(observed: list[Mapping[str, Any]]) -> str:
    rows = []
    for item in observed:
        role = "base" if item.get("is_base") is True else "split"
        rows.append({"role": role, "split_name": str(item.get("split_label") or ""), "sha256": str(item.get("sha256") or "").lower()})
    rows.sort(key=lambda row: (row["role"], row["split_name"], row["sha256"]))
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() if rows else ""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _strip_internal(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in row.items() if key != "sha256s"} for row in rows]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--cold-root", type=Path, default=DEFAULT_COLD_ROOT)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = build_report(
        data_root=args.data_root,
        output_root=args.output_root,
        cold_root=args.cold_root,
        stamp=args.stamp,
    )
    if args.json:
        print(json.dumps({"summary": report["summary"], "outputs": report["outputs"]}, indent=2, sort_keys=True))
    else:
        print("APK inventory model report")
        print(f"  Status outputs : {report['outputs']['summary_json']}")
        print(f"  Packages       : {report['summary']['total_packages']}")
        print(f"  Package/version: {report['summary']['total_package_version_entries']}")
        print(f"  Split sets     : {report['summary']['total_split_sets']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
