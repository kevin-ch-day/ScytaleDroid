#!/usr/bin/env python3
"""Profile v3 APK freshness gate (publication-grade, fail-closed).

Checks that for every package in the v3 catalog:
- the package exists in the latest device inventory snapshot
- the most recent harvested base APK on disk matches the inventory version_code

This prevents mixed-version cohorts and makes "commercial app versions" defensible.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
import csv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.profile_v3_metrics import load_profile_v3_catalog  # noqa: E402


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _latest_inventory_snapshot(serial: str) -> Path:
    pattern = str(REPO_ROOT / "data" / "state" / serial / "inventory" / "inventory_*.json")
    paths = sorted([p for p in glob.glob(pattern) if not p.endswith(".meta.json")])
    if not paths:
        raise SystemExit(f"PROFILE_V3_NO_INVENTORY_SNAPSHOT: {pattern}")
    return Path(paths[-1])


def _load_inventory_versions(snapshot_path: Path) -> dict[str, str]:
    payload = _rjson(snapshot_path)
    pkgs = payload.get("packages")
    if not isinstance(pkgs, list):
        raise SystemExit(f"PROFILE_V3_BAD_INVENTORY_SNAPSHOT: missing packages list in {snapshot_path}")
    out: dict[str, str] = {}
    for row in pkgs:
        if not isinstance(row, dict):
            continue
        name = str(row.get("package_name") or "").strip()
        if not name:
            continue
        vc = row.get("version_code")
        if vc is None:
            continue
        out[name] = str(vc).strip()
    return out


_BASE_APK_RE = re.compile(r"_(\d+)__base\.apk$")


def _latest_harvested_version(device_apks_root: Path, package: str) -> tuple[str | None, str | None, str | None]:
    # Search newest day dir containing package.
    for day_dir in sorted([p for p in device_apks_root.iterdir() if p.is_dir()], reverse=True):
        pkg_dir = day_dir / package
        if not pkg_dir.is_dir():
            continue
        base_apks = sorted([p for p in pkg_dir.glob("*__base.apk")], key=lambda p: p.stat().st_mtime, reverse=True)
        if not base_apks:
            continue
        m = _BASE_APK_RE.search(base_apks[0].name)
        ver = m.group(1) if m else None
        return day_dir.name, ver, str(base_apks[0])
    return None, None, None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Profile v3 APK freshness check (fail-closed)")
    p.add_argument(
        "--serial",
        default="",
        help="Device serial (e.g., ZY22JK89DR). If omitted, uses data/state/active_device.json active_serial.",
    )
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to v3 app catalog.",
    )
    p.add_argument(
        "--device-apks-root",
        default=str(REPO_ROOT / "data" / "device_apks"),
        help="Root of harvested APK storage.",
    )
    p.add_argument(
        "--out-csv",
        default=str(REPO_ROOT / "output" / "audit" / "profile_v3" / "profile_v3_apk_freshness_report.csv"),
        help="Write a cohort-only freshness report CSV (paper-facing).",
    )
    args = p.parse_args(argv)

    serial = str(args.serial or "").strip()
    if not serial:
        try:
            active = _rjson(REPO_ROOT / "data" / "state" / "active_device.json")
            serial = str(active.get("active_serial") or active.get("last_serial") or "").strip()
        except Exception:
            serial = ""
    if not serial:
        raise SystemExit("PROFILE_V3_NO_ACTIVE_DEVICE: provide --serial or set data/state/active_device.json")

    catalog = load_profile_v3_catalog(Path(args.catalog))
    snapshot_path = _latest_inventory_snapshot(serial)
    inv = _load_inventory_versions(snapshot_path)

    device_apks_root = Path(args.device_apks_root) / serial
    if not device_apks_root.exists():
        raise SystemExit(f"PROFILE_V3_NO_DEVICE_APKS_ROOT: {device_apks_root}")

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    report_rows: list[dict[str, str]] = []
    failures: list[str] = []
    for pkg in sorted(catalog.keys()):
        meta = catalog.get(pkg) or {}
        app = str(meta.get("app") or "").strip()
        category = str(meta.get("app_category") or "").strip()
        dev_ver = inv.get(pkg)
        day, harv_ver, base_apk_path = _latest_harvested_version(device_apks_root, pkg)

        status = "PASS"
        if not dev_ver:
            status = "MISSING_ON_DEVICE"
        elif not harv_ver:
            status = "NEVER_HARVESTED"
        elif str(harv_ver) != str(dev_ver):
            status = "STALE_HARVEST"

        report_rows.append(
            {
                "package": pkg,
                "app": app,
                "app_category": category,
                "inventory_snapshot": snapshot_path.name,
                "version_code_device": str(dev_ver or ""),
                "version_code_disk": str(harv_ver or ""),
                "harvest_day": str(day or ""),
                "harvest_base_apk": str(base_apk_path or ""),
                "status": status,
            }
        )

        if status != "PASS":
            if status == "MISSING_ON_DEVICE":
                failures.append(f"{status}\t{pkg}")
            elif status == "NEVER_HARVESTED":
                failures.append(f"{status}\t{pkg}\tdevice={dev_ver}")
            elif status == "STALE_HARVEST":
                failures.append(f"{status}\t{pkg}\tdevice={dev_ver}\tharvest={harv_ver}\tday={day}")
            else:
                failures.append(f"{status}\t{pkg}")

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "package",
                "app",
                "app_category",
                "inventory_snapshot",
                "version_code_device",
                "version_code_disk",
                "harvest_day",
                "harvest_base_apk",
                "status",
            ],
        )
        w.writeheader()
        for row in report_rows:
            w.writerow(row)

    if failures:
        print(f"[FAIL] profile v3 APK freshness check failed (snapshot={snapshot_path.name})")
        print(f"  report_csv={out_csv}")
        for line in failures:
            print("  " + line)
        return 2

    print(f"[PASS] profile v3 APK freshness OK (snapshot={snapshot_path.name})")
    print(f"  report_csv={out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
