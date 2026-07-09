#!/usr/bin/env python3
"""Read-only APK storage transition debt report.

This report rolls up the APK library, hot/cold canonical store, legacy
run-folder retirement, and known package/version/split-set collision signals
into a prioritized work list. It does not move APK bytes, delete folders, or
write database rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--cold-root", type=Path, default=None)
    parser.add_argument("--serial", default="ZY22JK89DR")
    parser.add_argument("--stamp", default=None)
    hash_group = parser.add_mutually_exclusive_group()
    hash_group.add_argument(
        "--verify-sha256",
        action="store_true",
        help="Hash canonical APK blobs and verify filenames. Slower on large stores.",
    )
    hash_group.add_argument(
        "--skip-sha256",
        action="store_true",
        help="Deprecated compatibility flag; SHA-256 byte hashing is skipped by default.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    cold_root: Path | None = None,
    serial: str = "ZY22JK89DR",
    stamp: str | None = None,
    verify_sha256: bool = False,
    write_outputs: bool = True,
) -> dict[str, Any]:
    from scripts.device_analysis import check_external_apk_store_mount as mount_check
    from scripts.device_analysis import report_apk_inventory_model as inventory_model
    from scripts.device_analysis import report_legacy_harvest_run_retirement as retirement_report

    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "apk_transition_debt" / stamp
    cold = cold_root or inventory_model.DEFAULT_COLD_ROOT

    inventory = inventory_model.build_report(
        data_root=data_root,
        cold_root=cold,
        stamp=f"{stamp}-inventory",
        write_outputs=False,
    )
    retirement = retirement_report.build_report(
        data_root=data_root,
        cold_root=cold,
        stamp=f"{stamp}-retirement",
        write_outputs=False,
    )
    store = mount_check.build_report(
        data_root=data_root,
        serial=serial,
        verify_sha256=verify_sha256,
    )

    collision_groups = _content_variant_groups(
        inventory["content_variant_collisions"],
        split_sets=inventory["split_sets"],
        data_root=data_root,
    )
    represented_shas = _library_shas(inventory["split_sets"])
    represented_shas.update(_partial_artifact_shas(inventory.get("partial_artifacts", [])))
    unindexed_blobs = _unindexed_canonical_blobs(data_root=data_root, library_shas=represented_shas)
    regular_legacy_apks = _regular_legacy_apks(data_root=data_root, serial=serial)
    issues = _prioritized_issues(
        inventory_summary=inventory["summary"],
        retirement_summary=retirement["summary"],
        store_report=store,
        collision_groups=collision_groups,
        unindexed_blobs=unindexed_blobs,
        regular_legacy_apks=regular_legacy_apks,
    )
    summary = {
        "schema_version": "apk_transition_debt_report_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "serial": serial,
        "status": "ACTION_REQUIRED" if issues else "OK",
        "top_issue": issues[0]["issue_id"] if issues else "",
        "issue_count": len(issues),
        "critical_issue_count": sum(1 for row in issues if row["severity"] == "critical"),
        "high_issue_count": sum(1 for row in issues if row["severity"] == "high"),
        "medium_issue_count": sum(1 for row in issues if row["severity"] == "medium"),
        "canonical_apk_blobs": store["canonical_store"]["canonical_apk_blob_count"],
        "library_artifact_rows": inventory["summary"]["total_library_artifacts"],
        "partial_artifact_rows": inventory["summary"].get("total_partial_artifacts", 0),
        "unindexed_canonical_blob_count": len(unindexed_blobs),
        "content_variant_planned_groups": len(collision_groups),
        "content_variant_receipt_rows": inventory["summary"]["receipt_rows_blocked_by_planned_split_set_collision"],
        "content_variant_extra_variants": sum(max(int(row["content_variant_count"]) - 1, 0) for row in collision_groups),
        "split_set_dirs_with_history_variants": sum(1 for row in collision_groups if int(row["history_content_variant_count"]) > 1),
        "regular_legacy_apk_count": len(regular_legacy_apks),
        "regular_legacy_apk_bytes": sum(int(row["size_bytes"]) for row in regular_legacy_apks),
        "regular_legacy_apk_canonical_missing_count": sum(1 for row in regular_legacy_apks if not row["canonical_exists"]),
        "regular_legacy_apk_canonical_missing_bytes": sum(
            int(row["size_bytes"]) for row in regular_legacy_apks if not row["canonical_exists"]
        ),
        "regular_legacy_apk_represented_count": sum(
            1 for row in regular_legacy_apks if row.get("apk_library_representation") in {"full", "partial"}
        ),
        "regular_legacy_apk_unrepresented_count": sum(
            1 for row in regular_legacy_apks if row.get("apk_library_representation") == "none"
        ),
        "legacy_session_count": retirement["summary"]["session_count"],
        "legacy_archive_candidate_count": retirement["summary"]["archive_candidate_count"],
        "legacy_sessions_with_regular_apks": retirement["summary"]["sessions_with_regular_apks"],
        "legacy_sessions_with_unindexed_observed_artifacts": retirement["summary"]["sessions_with_unindexed_observed_artifacts"],
        "store_checker_status": store["status"],
        "store_checker_findings": store["findings"],
        "notes": [
            "Read-only report. No APK files moved, no DB rows changed, no legacy run folders archived.",
            "Known content-variant planned groups are unsafe for blind APK-library harvest skips.",
        ],
    }

    outputs = {
        "summary_json": output_root / "summary.json",
        "issues_csv": output_root / "issues.csv",
        "content_variant_groups_csv": output_root / "content_variant_groups.csv",
        "unindexed_canonical_blobs_csv": output_root / "unindexed_canonical_blobs.csv",
        "regular_legacy_apks_csv": output_root / "regular_legacy_apks.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_csv(outputs["issues_csv"], issues)
        _write_csv(outputs["content_variant_groups_csv"], collision_groups)
        _write_csv(outputs["unindexed_canonical_blobs_csv"], unindexed_blobs)
        _write_csv(outputs["regular_legacy_apks_csv"], regular_legacy_apks)

    return {
        "summary": summary,
        "outputs": {key: path.as_posix() for key, path in outputs.items()},
        "issues": issues,
        "content_variant_groups": collision_groups,
        "unindexed_canonical_blobs": unindexed_blobs,
        "regular_legacy_apks": regular_legacy_apks,
    }


def _content_variant_groups(
    rows: list[Mapping[str, Any]],
    *,
    split_sets: list[Mapping[str, Any]],
    data_root: Path,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for split in split_sets:
        key = (
            str(split.get("package_name") or ""),
            str(split.get("version_code") or ""),
            str(split.get("planned_split_set_hash") or ""),
        )
        content_hash = str(split.get("content_split_set_hash") or "")
        if not all(key) or not content_hash:
            continue
        item = grouped.setdefault(
            key,
            {
                "package_name": key[0],
                "version_code": key[1],
                "planned_split_set_hash": key[2],
                "collision_receipt_rows": 0,
                "collision_sessions": set(),
                "collision_content_hashes": set(),
                "library_content_hashes": set(),
                "existing_content_split_set_hash": "",
                "existing_manifest_path": "",
            },
        )
        item["library_content_hashes"].add(content_hash)
        if split.get("entry_kind") != "content_variant" and not item["existing_content_split_set_hash"]:
            item["existing_content_split_set_hash"] = content_hash
            item["existing_manifest_path"] = str(split.get("manifest_path") or "")
    for row in rows:
        key = (
            str(row.get("package_name") or ""),
            str(row.get("version_code") or ""),
            str(row.get("planned_split_set_hash") or ""),
        )
        item = grouped.setdefault(
            key,
            {
                "package_name": key[0],
                "version_code": key[1],
                "planned_split_set_hash": key[2],
                "collision_receipt_rows": 0,
                "collision_sessions": set(),
                "collision_content_hashes": set(),
                "library_content_hashes": set(),
                "existing_content_split_set_hash": str(row.get("existing_content_split_set_hash") or ""),
                "existing_manifest_path": str(row.get("existing_manifest_path") or ""),
            },
        )
        item["collision_receipt_rows"] += 1
        if row.get("session_label"):
            item["collision_sessions"].add(str(row.get("session_label")))
        if row.get("content_split_set_hash"):
            item["collision_content_hashes"].add(str(row.get("content_split_set_hash")))

    output: list[dict[str, Any]] = []
    for key, item in grouped.items():
        package, version, planned_hash = key
        history_hashes, history_rows = _history_hashes(data_root, package, version, planned_hash)
        all_hashes = set(item["collision_content_hashes"])
        all_hashes.update(item["library_content_hashes"])
        if item["existing_content_split_set_hash"]:
            all_hashes.add(item["existing_content_split_set_hash"])
        all_hashes.update(history_hashes)
        if len(all_hashes) <= 1:
            continue
        output.append(
            {
                "package_name": package,
                "version_code": version,
                "planned_split_set_hash": planned_hash,
                "content_variant_count": len(all_hashes),
                "extra_content_variants": max(len(all_hashes) - 1, 0),
                "collision_receipt_rows": item["collision_receipt_rows"],
                "collision_session_count": len(item["collision_sessions"]),
                "history_row_count": history_rows,
                "history_content_variant_count": len(history_hashes),
                "existing_content_split_set_hash": item["existing_content_split_set_hash"],
                "collision_content_hashes": ";".join(sorted(item["collision_content_hashes"])),
                "library_content_hashes": ";".join(sorted(item["library_content_hashes"])),
                "all_known_content_hashes": ";".join(sorted(all_hashes)),
                "existing_manifest_path": item["existing_manifest_path"],
                "risk": "harvest_library_hit_can_mask_changed_bytes",
                "recommended_action": (
                    "keep harvest content-variant pull guard enabled; add device-side content verification before allowing skips"
                ),
            }
        )
    return sorted(output, key=lambda row: (-int(row["content_variant_count"]), row["package_name"]))


def _history_hashes(data_root: Path, package_name: str, version_code: str, planned_hash: str) -> tuple[set[str], int]:
    history = (
        data_root
        / "android_apks"
        / "packages"
        / package_name
        / version_code
        / "split_sets"
        / planned_hash
        / "harvest_history.csv"
    )
    if not history.exists():
        return set(), 0
    hashes: set[str] = set()
    rows = 0
    with history.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            rows += 1
            value = str(row.get("split_set_hash") or "").strip()
            if value:
                hashes.add(value)
    return hashes, rows


def _library_shas(split_sets: Iterable[Mapping[str, Any]]) -> set[str]:
    shas: set[str] = set()
    for row in split_sets:
        for sha in str(row.get("sha256s") or "").split(";"):
            if len(sha) == 64:
                shas.add(sha)
    return shas


def _partial_artifact_shas(partial_artifacts: Iterable[Mapping[str, Any]]) -> set[str]:
    return {
        str(row.get("sha256") or "").lower()
        for row in partial_artifacts
        if len(str(row.get("sha256") or "")) == 64
    }


def _unindexed_canonical_blobs(*, data_root: Path, library_shas: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((data_root / "store" / "apk" / "sha256").glob("*/*.apk")):
        sha = path.stem.lower()
        if len(sha) != 64 or sha in library_shas:
            continue
        try:
            resolved = path.resolve(strict=True)
            exists = True
            size = resolved.stat().st_size if resolved.is_file() else 0
        except OSError:
            resolved = path.resolve(strict=False)
            exists = False
            size = 0
        rows.append(
            {
                "sha256": sha,
                "canonical_path": path.as_posix(),
                "resolved_path": resolved.as_posix(),
                "is_symlink": path.is_symlink(),
                "target_exists": exists,
                "size_bytes": size,
                "reason": "canonical_blob_not_represented_in_data_android_apks",
            }
        )
    return rows


def _regular_legacy_apks(*, data_root: Path, serial: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = data_root / "device_apks" / serial / "runs"
    for path in sorted(root.rglob("*.apk")) if root.exists() else []:
        if path.is_symlink() or not path.is_file():
            continue
        sha = _sha256(path)
        canonical = data_root / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"
        package, version = _package_version_from_legacy_path(path)
        representation, representation_path = _apk_library_representation(data_root=data_root, sha=sha)
        rows.append(
            {
                "path": path.as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha,
                "canonical_path": canonical.as_posix(),
                "canonical_exists": canonical.exists(),
                "apk_library_representation": representation,
                "apk_library_representation_path": representation_path,
                "session_label": _session_from_legacy_path(path),
                "package_name": package,
                "version_label": version,
                "safe_to_keep_for_now": "yes",
                "reason": (
                    "legacy_regular_apk_represented_but_unthinned"
                    if representation in {"full", "partial"} and canonical.exists()
                    else "legacy_regular_apk_left_unthinned_or_blocked_by_sidecar_metadata"
                ),
            }
        )
    return rows


def _apk_library_representation(*, data_root: Path, sha: str) -> tuple[str, str]:
    partial = data_root / "android_apks" / "partial_artifacts"
    partial_matches = list(partial.glob(f"*/*/{sha}/artifact_manifest.json"))
    if partial_matches:
        return "partial", partial_matches[0].as_posix()
    packages = data_root / "android_apks" / "packages"
    for manifest in packages.glob("*/*/split_sets/*/package_manifest.json"):
        if _manifest_has_sha(manifest, sha):
            return "full", manifest.as_posix()
    for manifest in packages.glob("*/*/split_sets/*/content_variants/*/package_manifest.json"):
        if _manifest_has_sha(manifest, sha):
            return "full", manifest.as_posix()
    return "none", ""


def _manifest_has_sha(path: Path, sha: str) -> bool:
    payload = _read_json(path)
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
    return any(isinstance(item, dict) and str(item.get("sha256") or "").lower() == sha for item in artifacts)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _session_from_legacy_path(path: Path) -> str:
    parts = path.parts
    if "runs" not in parts:
        return ""
    idx = parts.index("runs")
    return parts[idx + 1] if len(parts) > idx + 1 else ""


def _package_version_from_legacy_path(path: Path) -> tuple[str, str]:
    parts = path.parts
    if "runs" not in parts:
        return "", ""
    idx = parts.index("runs")
    package = parts[idx + 2] if len(parts) > idx + 2 else ""
    version = parts[idx + 3] if len(parts) > idx + 3 else ""
    return package, version


def _prioritized_issues(
    *,
    inventory_summary: Mapping[str, Any],
    retirement_summary: Mapping[str, Any],
    store_report: Mapping[str, Any],
    collision_groups: list[Mapping[str, Any]],
    unindexed_blobs: list[Mapping[str, Any]],
    regular_legacy_apks: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if collision_groups:
        unresolved_variant_rows = int(inventory_summary.get("receipt_rows_blocked_by_planned_split_set_collision") or 0)
        unresolved_variant_blobs = len(unindexed_blobs)
        if unresolved_variant_rows or unresolved_variant_blobs:
            severity = "critical"
            issue_id = "APK_LIBRARY_CONTENT_VARIANT_MODEL_GAP"
            impact = "The current library coverage is incomplete for content variants and harvest library-hit skip can mask changed APK bytes."
            next_action = "Index missing content variants and keep library-hit skip disabled for variant planned split-sets."
        else:
            severity = "medium"
            issue_id = "APK_LIBRARY_CONTENT_VARIANTS_REQUIRE_PULL_VERIFICATION"
            impact = (
                "Content variants are indexed and harvest forces fresh pulls for these planned split-sets, "
                "but installed bytes still cannot be known from planned split-set identity alone."
            )
            next_action = "Keep harvest content-variant pull guard enabled until device-side content verification exists."
        issues.append(
            _issue(
                priority=1,
                severity=severity,
                issue_id=issue_id,
                count=len(collision_groups),
                bytes_at_risk=sum(int(row.get("size_bytes") or 0) for row in unindexed_blobs),
                evidence=(
                    f"{len(collision_groups)} package/version/planned split-set group(s) have multiple content hashes; "
                    f"{inventory_summary.get('receipt_rows_blocked_by_planned_split_set_collision')} receipt rows are blocked."
                ),
                impact=impact,
                next_action=next_action,
            )
        )
    if unindexed_blobs:
        issues.append(
            _issue(
                priority=2,
                severity="high",
                issue_id="CANONICAL_BLOBS_NOT_IN_APK_LIBRARY",
                count=len(unindexed_blobs),
                bytes_at_risk=sum(int(row.get("size_bytes") or 0) for row in unindexed_blobs),
                evidence=f"{len(unindexed_blobs)} canonical APK blob(s) are not represented in data/android_apks.",
                impact="Version comparison and legacy retirement cannot rely solely on the APK library.",
                next_action="Represent the missing content variants without overwriting existing split-set manifests.",
            )
        )
    if int(retirement_summary.get("sessions_with_unindexed_observed_artifacts") or 0):
        issues.append(
            _issue(
                priority=3,
                severity="high",
                issue_id="LEGACY_RETIREMENT_BLOCKED_BY_READ_MODEL",
                count=int(retirement_summary.get("sessions_with_unindexed_observed_artifacts") or 0),
                bytes_at_risk=0,
                evidence=(
                    f"{retirement_summary.get('sessions_with_unindexed_observed_artifacts')} of "
                    f"{retirement_summary.get('session_count')} legacy sessions still have observed artifacts not fully indexed."
                ),
                impact="Legacy run-folder retirement is not ready beyond the tiny candidate set.",
                next_action="Resolve APK library content-variant coverage before expanding archive candidates.",
            )
        )
    if regular_legacy_apks:
        missing_regular_count = sum(1 for row in regular_legacy_apks if not row.get("canonical_exists"))
        missing_regular_bytes = sum(int(row.get("size_bytes") or 0) for row in regular_legacy_apks if not row.get("canonical_exists"))
        unrepresented_count = sum(1 for row in regular_legacy_apks if row.get("apk_library_representation") == "none")
        severity = "medium" if missing_regular_count or unrepresented_count else "low"
        if missing_regular_count or unrepresented_count:
            impact = "These sessions cannot be treated as fully thinned until canonical and APK-library representation is complete."
            next_action = "Repair canonical copies and APK-library or partial-artifact metadata before any thinning."
        else:
            impact = "These APK bytes are canonicalized and represented, but the legacy files remain as unthinned provenance copies."
            next_action = "Keep them until an explicit legacy thinning or archive apply pass is approved."
        issues.append(
            _issue(
                priority=4,
                severity=severity,
                issue_id="REGULAR_APKS_REMAIN_IN_LEGACY_RUN_FOLDERS",
                count=len(regular_legacy_apks),
                bytes_at_risk=missing_regular_bytes,
                evidence=(
                    f"{len(regular_legacy_apks)} regular APK file(s) remain under legacy device_apks; "
                    f"{missing_regular_count} lack canonical copies; {unrepresented_count} lack APK-library representation."
                ),
                impact=impact,
                next_action=next_action,
            )
        )
    canonical = store_report.get("canonical_store", {})
    if canonical.get("broken_canonical_symlink_count") or canonical.get("unavailable_cold_blob_count"):
        issues.append(
            _issue(
                priority=5,
                severity="critical",
                issue_id="CANONICAL_STORE_INTEGRITY_BLOCKER",
                count=int(canonical.get("broken_canonical_symlink_count") or 0)
                + int(canonical.get("unavailable_cold_blob_count") or 0),
                bytes_at_risk=int(canonical.get("unavailable_cold_bytes") or 0),
                evidence=str(store_report.get("findings") or []),
                impact="Old static/harvest paths may fail to open APK bytes.",
                next_action="Repair canonical symlinks or mount Mercury before any analysis work.",
            )
        )
    if store_report.get("status") == "WARN":
        issues.append(
            _issue(
                priority=6,
                severity="low",
                issue_id="STORE_CHECKER_WARNINGS",
                count=len(store_report.get("findings") or []),
                bytes_at_risk=0,
                evidence=str(store_report.get("findings") or []),
                impact="The checker skipped or warned on some validation dimension.",
                next_action="Run with SHA verification when time permits.",
            )
        )
    return sorted(issues, key=lambda row: int(row["priority"]))


def _issue(
    *,
    priority: int,
    severity: str,
    issue_id: str,
    count: int,
    bytes_at_risk: int,
    evidence: str,
    impact: str,
    next_action: str,
) -> dict[str, Any]:
    return {
        "priority": priority,
        "severity": severity,
        "issue_id": issue_id,
        "count": count,
        "bytes_at_risk": bytes_at_risk,
        "evidence": evidence,
        "impact": impact,
        "next_action": next_action,
    }


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = build_report(
        data_root=args.data_root,
        output_root=args.output_root,
        cold_root=args.cold_root,
        serial=args.serial,
        stamp=args.stamp,
        verify_sha256=args.verify_sha256,
    )
    if args.json:
        print(json.dumps({"summary": report["summary"], "outputs": report["outputs"]}, indent=2, sort_keys=True))
    else:
        print("APK transition debt report")
        print(f"  Status : {report['summary']['status']}")
        print(f"  Output : {report['outputs']['summary_json']}")
        for issue in report["issues"][:5]:
            print(f"  P{issue['priority']} {issue['severity']}: {issue['issue_id']} ({issue['count']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
