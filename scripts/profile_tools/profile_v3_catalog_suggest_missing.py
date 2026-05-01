#!/usr/bin/env python3
"""Suggest missing Profile v3 catalog entries from a device inventory snapshot.

This tool is intentionally conservative:
- It never edits the catalog.
- It never guesses package IDs.

It reads:
- profiles/profile_v3_app_catalog.json (current catalog)
- data/state/<serial>/inventory/latest.json (device inventory snapshot)

Then prints candidate packages (from the device snapshot) whose app labels look
like common missing cohort apps (e.g., "Drive", "Sheets") and are not already
present in the v3 catalog.

Use case:
When Pull APKs precheck says "catalog=19 expected=21", run this after installing
the missing apps on the device to quickly discover the exact package strings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _active_serial() -> str | None:
    p = REPO_ROOT / "data" / "state" / "active_device.json"
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    # device_manager persists active devices under active_serial/last_serial.
    serial = str(obj.get("active_serial") or obj.get("last_serial") or obj.get("serial") or "").strip()
    return serial or None


def _load_catalog(path: Path) -> dict[str, dict[str, object]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise SystemExit(f"PROFILE_V3_BAD_CATALOG: expected object at {path}")
    catalog: dict[str, dict[str, object]] = {}
    for pkg, meta in obj.items():
        if not isinstance(pkg, str):
            continue
        if isinstance(meta, dict):
            catalog[pkg.strip().lower()] = meta
        else:
            catalog[pkg.strip().lower()] = {}
    return catalog


def _load_inventory(path: Path) -> list[dict[str, object]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or not isinstance(obj.get("packages"), list):
        raise SystemExit(f"PROFILE_V3_BAD_INVENTORY_SNAPSHOT: missing packages list in {path}")
    rows = []
    for row in obj["packages"]:
        if isinstance(row, dict):
            rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Suggest missing Profile v3 catalog entries from device inventory.")
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to Profile v3 app catalog JSON.",
    )
    p.add_argument(
        "--serial",
        default="",
        help="Device serial to locate inventory snapshot (defaults to active_device.json).",
    )
    p.add_argument(
        "--inventory",
        default="",
        help="Explicit inventory snapshot path (defaults to data/state/<serial>/inventory/latest.json).",
    )
    p.add_argument(
        "--contains",
        default="drive,sheets",
        help="Comma-separated label substrings to search for (case-insensitive).",
    )
    args = p.parse_args(argv)

    catalog_path = Path(args.catalog)
    catalog = _load_catalog(catalog_path)

    serial = str(args.serial).strip() or (_active_serial() or "")
    if args.inventory:
        inv_path = Path(args.inventory)
    else:
        if not serial:
            raise SystemExit("PROFILE_V3_NO_ACTIVE_DEVICE: provide --serial or set data/state/active_device.json")
        inv_path = REPO_ROOT / "data" / "state" / serial / "inventory" / "latest.json"
    if not inv_path.exists():
        raise SystemExit(f"PROFILE_V3_NO_INVENTORY_SNAPSHOT: {inv_path}")

    rows = _load_inventory(inv_path)
    tokens = [t.strip().lower() for t in str(args.contains).split(",") if t.strip()]
    if not tokens:
        raise SystemExit("Provide at least one --contains token.")

    candidates: list[tuple[str, str, int | None]] = []
    for row in rows:
        pkg = str(row.get("package_name") or "").strip().lower()
        if not pkg or pkg in catalog:
            continue
        label = str(row.get("app_label") or "").strip()
        label_l = label.lower()
        if not label:
            continue
        if any(tok in label_l for tok in tokens):
            vc = row.get("version_code")
            version_code = int(vc) if isinstance(vc, int) else None
            candidates.append((pkg, label, version_code))

    print()
    print("Profile v3 catalog missing-entry helper")
    print("-------------------------------------")
    print(f"catalog_path : {catalog_path}")
    print(f"catalog_size : {len(catalog)}")
    print(f"inventory    : {inv_path}")
    if serial:
        print(f"device_serial: {serial}")
    print(f"search_tokens: {tokens}")
    print()

    if not candidates:
        print("No candidates found in the inventory snapshot.")
        print("If you expected Drive/Sheets/etc:")
        print("- Confirm the apps are installed on the device.")
        print("- Run a full inventory sync so data/state/<serial>/inventory/latest.json includes them.")
        print("- Then re-run this helper (or pass an explicit --inventory snapshot path).")
        return 1

    print("Candidate packages (not in catalog):")
    for pkg, label, vc in sorted(candidates, key=lambda t: (t[1].lower(), t[0])):
        vc_text = f" version_code={vc}" if vc is not None else ""
        print(f"- {pkg}  label={label}{vc_text}")

    print()
    print("Next step: add the correct package IDs to profiles/profile_v3_app_catalog.json (no guessing).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
