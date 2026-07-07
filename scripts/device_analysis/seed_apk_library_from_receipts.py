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
        "seedable",
        "reason",
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

    rows: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    applied = 0
    for receipt in receipts:
        package_name = _read_package_name(receipt) or receipt.stem
        seedable, reason = apk_library_service.legacy_receipt_seedable(receipt)
        entry = None
        if args.apply and seedable:
            entry = apk_library_service.register_legacy_receipt(receipt)
            if entry is None:
                reason = "registration_failed"
            else:
                applied += 1
        reasons[reason] += 1
        rows.append(
            {
                "receipt_path": artifact_store.repo_relative_path(receipt),
                "session": receipt.parent.name,
                "package_name": package_name,
                "seedable": seedable,
                "reason": reason,
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
            f"applied={summary['applied_receipts']}"
        )
        print(f"reasons={summary['reasons']}")
        print(csv_path)
        print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
