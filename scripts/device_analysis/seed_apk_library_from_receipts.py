#!/usr/bin/env python3
"""Seed the APK library from existing harvest receipts.

The script reads receipt metadata and canonical store paths. It does not hash or
copy APK bytes, and it does not delete legacy harvest payloads.
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

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts-root", default=None, help="Receipt root; default data/receipts/harvest.")
    parser.add_argument("--session", action="append", default=[], help="Only seed one receipt session; repeatable.")
    parser.add_argument("--package", dest="packages", action="append", default=[], help="Only seed one package; repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N matching receipts.")
    parser.add_argument("--output-dir", default=None, help="Report directory; default output/audit/apk_library_seed/<stamp>.")
    parser.add_argument("--apply", action="store_true", help="Write APK library manifests. Default is dry-run.")
    parser.add_argument(
        "--include-existing",
        action="store_true",
        help="Also re-register receipts whose package/version content split-set is already indexed.",
    )
    parser.add_argument(
        "--include-content-variants",
        action="store_true",
        help="Register content variants under split_sets/<planned_hash>/content_variants/<content_hash>.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return ROOT / "output" / "audit" / "apk_library_seed" / _stamp()


def _read_package_name(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    package = payload.get("package") if isinstance(payload, dict) and isinstance(payload.get("package"), dict) else {}
    return str(package.get("package_name") or "").strip()


def _iter_receipts(root: Path, *, sessions: set[str], packages: set[str], limit: int) -> list[Path]:
    if not root.exists():
        return []
    receipts: list[Path] = []
    for path in sorted(root.rglob("*.json")):
        if sessions and path.parent.name not in sessions:
            continue
        package_name = path.stem
        if packages and package_name not in packages:
            package_name = _read_package_name(path)
            if package_name not in packages:
                continue
        receipts.append(path)
        if limit > 0 and len(receipts) >= limit:
            break
    return receipts


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "receipt_path",
        "session",
        "package_name",
        "version_code",
        "planned_split_set_hash",
        "content_split_set_hash",
        "seedable",
        "reason",
        "already_indexed",
        "planned_hash_collision",
        "content_variant_enabled",
        "existing_manifest_path",
        "existing_content_split_set_hash",
        "applied",
        "library_manifest_path",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store

    root = Path(args.receipts_root).expanduser().resolve() if args.receipts_root else artifact_store.harvest_receipts_root()
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else _default_output_dir()
    sessions = {str(item).strip() for item in args.session if str(item).strip()}
    packages = {str(item).strip() for item in args.packages if str(item).strip()}
    receipts = _iter_receipts(root, sessions=sessions, packages=packages, limit=max(args.limit, 0))
    indexed, indexed_by_planned_hash = _indexed_split_sets(artifact_store.data_root() / "android_apks", artifact_store)

    rows: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    applied = 0
    already_indexed = 0
    planned_hash_collisions = 0
    for receipt in receipts:
        payload = _read_json(receipt)
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        package_name = str(package.get("package_name") or "").strip() or receipt.stem
        version_code = str(package.get("version_code") or "").strip()
        planned_hash, content_hash = _split_set_hashes_from_receipt(payload, apk_library_service)
        indexed_key = (package_name, version_code, content_hash)
        planned_key = (package_name, version_code, planned_hash)
        is_indexed = bool(content_hash and indexed_key in indexed)
        planned_hit = indexed_by_planned_hash.get(planned_key) if planned_hash else None
        planned_collision = bool(
            planned_hit
            and content_hash
            and str(planned_hit.get("content_split_set_hash") or "") != content_hash
        )
        seedable, reason = apk_library_service.legacy_receipt_seedable(receipt)
        entry = None
        if seedable and is_indexed and not args.include_existing:
            reason = "already_indexed"
            already_indexed += 1
        elif seedable and planned_collision and not args.include_content_variants:
            reason = "planned_split_set_hash_collision"
            planned_hash_collisions += 1
        elif seedable and planned_collision:
            reason = "content_variant_seedable"
            if args.apply:
                entry = apk_library_service.register_legacy_receipt(receipt)
                if entry is None:
                    reason = "registration_failed"
                else:
                    applied += 1
                    if content_hash:
                        indexed.add(indexed_key)
        elif args.apply and seedable:
            entry = apk_library_service.register_legacy_receipt(receipt)
            if entry is None:
                reason = "registration_failed"
            else:
                applied += 1
                if content_hash:
                    indexed.add(indexed_key)
                if planned_hash:
                    indexed_by_planned_hash[planned_key] = {
                        "content_split_set_hash": entry.split_set_hash,
                        "manifest_path": artifact_store.repo_relative_path(entry.manifest_path),
                    }
        reasons[reason] += 1
        rows.append(
            {
                "receipt_path": artifact_store.repo_relative_path(receipt),
                "session": receipt.parent.name,
                "package_name": package_name,
                "version_code": version_code,
                "planned_split_set_hash": planned_hash,
                "content_split_set_hash": content_hash,
                "seedable": seedable,
                "reason": reason,
                "already_indexed": is_indexed,
                "planned_hash_collision": planned_collision,
                "content_variant_enabled": bool(args.include_content_variants),
                "existing_manifest_path": planned_hit.get("manifest_path", "") if planned_hit else "",
                "existing_content_split_set_hash": planned_hit.get("content_split_set_hash", "") if planned_hit else "",
                "applied": bool(entry),
                "library_manifest_path": artifact_store.repo_relative_path(entry.manifest_path) if entry else "",
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "apk_library_seed_receipts.csv"
    summary_path = output_dir / "summary.json"
    _write_csv(csv_path, rows)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "mode": "apply" if args.apply else "dry_run",
        "receipts_root": artifact_store.repo_relative_path(root),
        "sessions": sorted(sessions),
        "packages": sorted(packages),
        "receipts_seen": len(receipts),
        "seedable_receipts": sum(1 for row in rows if row["seedable"]),
        "already_indexed_receipts": already_indexed,
        "planned_split_set_hash_collisions": planned_hash_collisions,
        "include_existing": bool(args.include_existing),
        "include_content_variants": bool(args.include_content_variants),
        "applied_receipts": applied,
        "reasons": dict(sorted(reasons.items())),
        "output_dir": str(output_dir),
        "csv_report": str(csv_path),
        "summary_json": str(summary_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("# APK library receipt seed")
        print(f"mode: {summary['mode']}")
        print(f"output: {output_dir}")
        print(
            f"receipts={summary['receipts_seen']} seedable={summary['seedable_receipts']} "
            f"already_indexed={summary['already_indexed_receipts']} "
            f"planned_collisions={summary['planned_split_set_hash_collisions']} "
            f"applied={summary['applied_receipts']}"
        )
        print(f"reasons={summary['reasons']}")
        print(csv_path)
        print(summary_path)
    return 0


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _indexed_split_sets(
    library_root: Path,
    artifact_store: Any,
) -> tuple[set[tuple[str, str, str]], dict[tuple[str, str, str], dict[str, str]]]:
    indexed: set[tuple[str, str, str]] = set()
    indexed_by_planned_hash: dict[tuple[str, str, str], dict[str, str]] = {}
    primary_manifests = sorted((library_root / "packages").glob("*/*/split_sets/*/package_manifest.json"))
    variant_manifests = sorted((library_root / "packages").glob("*/*/split_sets/*/content_variants/*/package_manifest.json"))
    for manifest in primary_manifests:
        payload = _read_json(manifest)
        if not payload:
            continue
        package_name = str(payload.get("package_name") or "").strip()
        version_code = str(payload.get("version_code") or "").strip()
        planned_hash = str(payload.get("planned_split_set_hash") or "").strip()
        content_hash = str(payload.get("split_set_hash") or "").strip()
        if package_name and version_code and content_hash:
            indexed.add((package_name, version_code, content_hash))
        if package_name and version_code and planned_hash:
            indexed_by_planned_hash[(package_name, version_code, planned_hash)] = {
                "content_split_set_hash": content_hash,
                "manifest_path": artifact_store.repo_relative_path(manifest),
            }
    for manifest in variant_manifests:
        payload = _read_json(manifest)
        if not payload:
            continue
        package_name = str(payload.get("package_name") or "").strip()
        version_code = str(payload.get("version_code") or "").strip()
        content_hash = str(payload.get("split_set_hash") or "").strip()
        if package_name and version_code and content_hash:
            indexed.add((package_name, version_code, content_hash))
    return indexed, indexed_by_planned_hash


def _split_set_hashes_from_receipt(payload: dict[str, Any], apk_library_service: Any) -> tuple[str, str]:
    plan = apk_library_service._plan_from_legacy_receipt(payload)
    if plan is None:
        return "", ""
    planned_hash = apk_library_service.planned_split_set_hash_for_plan(plan)
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return planned_hash, ""
    rows = []
    for artifact in plan.artifacts:
        hit = apk_library_service._matching_observed_artifact(artifact, observed)
        if hit is None:
            return planned_hash, ""
        sha = str(hit.get("sha256") or "").strip().lower()
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
    if not rows:
        return planned_hash, ""
    return planned_hash, apk_library_service._content_split_set_hash(rows)


if __name__ == "__main__":
    raise SystemExit(main())
