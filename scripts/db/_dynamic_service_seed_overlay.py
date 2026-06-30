"""Read-only helpers to overlay repo seed rows onto DB-backed service audits."""

from __future__ import annotations

import argparse
from typing import Any, Mapping


def merge_missing_seed_services(
    db_rows: list[dict[str, Any]],
    seed_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(row) for row in db_rows if isinstance(row, Mapping)]
    seen = {str(row.get("service_key") or "") for row in merged}
    for row in seed_rows:
        service_key = str(row.get("service_key") or "")
        if service_key and service_key not in seen:
            merged.append(dict(row))
            seen.add(service_key)
    merged.sort(
        key=lambda row: (
            str(row.get("owner_class") or ""),
            str(row.get("service_category") or ""),
            str(row.get("service_key") or ""),
        )
    )
    return merged


def merge_missing_seed_service_maps(
    db_rows: list[dict[str, Any]],
    seed_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(row) for row in db_rows if isinstance(row, Mapping)]
    seen = {
        (
            str(row.get("service_key") or ""),
            str(row.get("package_name_scope") or ""),
            str(row.get("domain_pattern") or ""),
            str(row.get("match_type") or ""),
        )
        for row in merged
    }
    for row in seed_rows:
        key = (
            str(row.get("service_key") or ""),
            str(row.get("package_name_scope") or ""),
            str(row.get("domain_pattern") or ""),
            str(row.get("match_type") or ""),
        )
        if key[0] and key[2] and key[3] and key not in seen:
            merged.append(dict(row))
            seen.add(key)
    merged.sort(
        key=lambda row: (
            str(row.get("service_key") or ""),
            str(row.get("package_name_scope") or ""),
            str(row.get("match_type") or ""),
            str(row.get("domain_pattern") or ""),
        )
    )
    return merged


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--help-only",
        action="store_true",
        help="no-op flag reserved for help-contract validation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
