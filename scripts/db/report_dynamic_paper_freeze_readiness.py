#!/usr/bin/env python3
"""Read-only paper-freeze readiness report for dynamic build-backed evidence."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--package",
        action="append",
        default=None,
        help="Optional package filter; may be passed more than once.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print summary JSON to stdout after writing report files.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Alias for --json; kept for consistency with adjacent report scripts.",
    )
    parser.add_argument(
        "--skip-live-drift",
        action="store_true",
        help="Do not query the selected device for live installed-build drift.",
    )
    return parser


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "paper" / f"dynamic_paper_freeze_{stamp}"


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _load_app_labels(packages: list[str]) -> dict[str, str]:
    normalized = [_norm_text(package).lower() for package in packages if _norm_text(package)]
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception:
        return {}
    placeholders = ", ".join(["%s"] * len(normalized))
    try:
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   NULLIF(display_name, '') AS display_name
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(normalized),
            fetch="all",
            dictionary=True,
            query_name="dynamic.paper_freeze.labels",
        ) or []
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        pkg = _norm_text(row.get("package_name")).lower()
        label = _norm_text(row.get("display_name"))
        if pkg and label:
            out[pkg] = label
    return out


def _load_live_drift_map(packages: list[str]) -> tuple[dict[str, dict[str, str]], str, str]:
    try:
        from scytaledroid.DeviceAnalysis import device_manager
        from scytaledroid.DynamicAnalysis.menus.queue_data_sources import (
            resolve_live_build_drift_map,
        )
    except Exception:
        return {}, "", ""
    try:
        device_serial = _norm_text(device_manager.get_active_serial())
        device_label = _norm_text(device_manager.describe_active_device())
    except Exception:
        return {}, "", ""
    if not device_serial:
        return {}, "", device_label
    try:
        drift_map = resolve_live_build_drift_map(packages, device_serial=device_serial)
    except Exception:
        return {}, device_serial, device_label
    return drift_map, device_serial, device_label


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
        build_paper_evidence_tier_report,
        build_paper_freeze_decision_board,
        build_paper_freeze_manifest,
    )

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_paper_freeze_manifest(package_filter=args.package)
    decision_board = build_paper_freeze_decision_board(package_filter=args.package)
    app_rows = list(manifest.get("apps") or [])
    packages = [_norm_text(row.get("package_name")) for row in app_rows]
    live_drift_map: dict[str, dict[str, str]] | None = None
    device_serial = ""
    device_label = ""
    if not args.skip_live_drift:
        live_drift_map, device_serial, device_label = _load_live_drift_map(packages)
    tier_report = build_paper_evidence_tier_report(
        package_filter=args.package,
        live_drift_map=live_drift_map,
    )
    label_map = _load_app_labels([_norm_text(row.get("package_name")) for row in app_rows])

    csv_rows: list[dict[str, Any]] = []
    for row in app_rows:
        flat = {key: value for key, value in row.items() if key != "build_candidates"}
        pkg = _norm_text(flat.get("package_name")).lower()
        flat["app"] = label_map.get(pkg, _norm_text(flat.get("app")) or pkg)
        csv_rows.append(flat)

    plan_rows = list(manifest.get("paper_minimal_run_plan") or [])
    for row in plan_rows:
        pkg = _norm_text(row.get("package_name")).lower()
        row["app"] = label_map.get(pkg, _norm_text(row.get("app")) or pkg)

    board_rows = list(decision_board.get("rows") or [])
    for row in board_rows:
        pkg = _norm_text(row.get("package_name")).lower()
        row["app"] = label_map.get(pkg, _norm_text(row.get("app")) or pkg)

    tier_rows = list(tier_report.get("rows") or [])
    for row in tier_rows:
        pkg = _norm_text(row.get("package_name")).lower()
        row["app"] = label_map.get(pkg, _norm_text(row.get("app")) or pkg)

    json_path = output_dir / "paper_freeze_manifest.json"
    csv_path = output_dir / "paper_freeze_manifest.csv"
    plan_path = output_dir / "paper_minimal_run_plan.csv"
    board_json_path = output_dir / "paper_freeze_decision_board.json"
    board_csv_path = output_dir / "paper_freeze_decision_board.csv"
    tier_json_path = output_dir / "paper_evidence_tiers.json"
    tier_csv_path = output_dir / "paper_evidence_tiers.csv"
    summary_path = output_dir / "summary.json"

    json_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    board_json_path.write_text(json.dumps(decision_board, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tier_json_path.write_text(json.dumps(tier_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(csv_path, csv_rows)
    _write_csv(plan_path, plan_rows)
    _write_csv(board_csv_path, board_rows)
    _write_csv(tier_csv_path, tier_rows)

    summary = {
        **dict(manifest.get("summary") or {}),
        "cohort_label": manifest.get("cohort_label"),
        "live_drift_checked": bool(device_serial) and not bool(args.skip_live_drift),
        "live_device_serial": device_serial,
        "live_device_label": device_label,
        "live_drifted_package_count": len(live_drift_map or {}),
        "evidence_tier_summary": tier_report.get("summary"),
        "paper_freeze_manifest_json": str(json_path.resolve()),
        "paper_freeze_manifest_csv": str(csv_path.resolve()),
        "paper_minimal_run_plan_csv": str(plan_path.resolve()),
        "paper_freeze_decision_board_json": str(board_json_path.resolve()),
        "paper_freeze_decision_board_csv": str(board_csv_path.resolve()),
        "paper_evidence_tiers_json": str(tier_json_path.resolve()),
        "paper_evidence_tiers_csv": str(tier_csv_path.resolve()),
        "summary_json": str(summary_path.resolve()),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json or args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"summary.json: {summary_path}")
        print(f"paper_freeze_manifest.json: {json_path}")
        print(f"paper_freeze_manifest.csv: {csv_path}")
        print(f"paper_minimal_run_plan.csv: {plan_path}")
        print(f"paper_freeze_decision_board.json: {board_json_path}")
        print(f"paper_freeze_decision_board.csv: {board_csv_path}")
        print(f"paper_evidence_tiers.json: {tier_json_path}")
        print(f"paper_evidence_tiers.csv: {tier_csv_path}")
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
