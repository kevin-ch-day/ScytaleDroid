#!/usr/bin/env python3
"""Read-only external APK store mount and integrity check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Config import app_config  # noqa: E402
from scytaledroid.DeviceAnalysis.services import artifact_store  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", default=None, help="Data root; default configured DATA_DIR.")
    parser.add_argument("--serial", default="ZY22JK89DR", help="Device serial for legacy APK symlink audit.")
    parser.add_argument(
        "--mount-root",
        action="append",
        default=[],
        help="External mount root to accept; repeatable. Defaults to Mercury V2/USB roots.",
    )
    parser.add_argument("--skip-sha256", action="store_true", help="Skip byte hashing of canonical APK blobs.")
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    return parser


def build_report(
    *,
    data_root: Path | None = None,
    serial: str = "ZY22JK89DR",
    mount_roots: Sequence[Path] | None = None,
    verify_sha256: bool = True,
    is_mount: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Build a read-only APK store report."""

    root = (data_root or Path(app_config.DATA_DIR)).expanduser()
    apk_path = root / "store" / "apk"
    android_path = root / "android_apks"
    roots = tuple(mount_roots or artifact_store.EXTERNAL_APK_STORE_MOUNT_ROOTS)

    apk_status = artifact_store.external_apk_store_mount_status(
        apk_root=apk_path,
        mount_roots=roots,
        is_mount=is_mount,
    )
    android_status = _path_status(android_path, mount_roots=roots, is_mount=is_mount)
    canonical = _canonical_counts(
        apk_path / "sha256",
        verify_sha256=verify_sha256,
        mount_roots=roots,
        is_mount=is_mount,
    )
    broken_legacy = _broken_legacy_apk_symlinks(root / "device_apks" / serial / "runs")

    findings: list[str] = []
    status = "OK"
    if apk_status["is_symlink"] and apk_status["external_mount_root"] and not apk_status["external_mount_mounted"]:
        status = "BLOCKED"
        findings.append("External APK store is configured but not mounted.")
    if apk_status["is_symlink"] and not apk_status["target_exists"]:
        status = "BLOCKED"
        findings.append("data/store/apk symlink target does not exist.")
    if canonical["unreadable_canonical_blob_count"] or canonical["zero_size_canonical_blob_count"]:
        status = "BLOCKED"
        findings.append("Canonical APK store contains unreadable or zero-size blobs.")
    if canonical["broken_canonical_symlink_count"]:
        status = "BLOCKED"
        findings.append("Canonical APK store contains broken APK symlinks.")
    if canonical["canonical_symlink_outside_allowed_roots_count"]:
        status = "BLOCKED"
        findings.append("Canonical APK store contains symlinks outside allowed Mercury roots.")
    if canonical["unavailable_cold_blob_count"]:
        status = "BLOCKED"
        findings.append("Cold APK blobs are referenced but Mercury is not mounted or targets are unavailable.")
    if canonical["sha_filename_mismatch_count"]:
        status = "BLOCKED"
        findings.append("Canonical APK store contains SHA-256 filename mismatches.")
    if broken_legacy:
        status = "WARN" if status == "OK" else status
        findings.append("Legacy device_apks contains broken APK symlinks.")
    if canonical["sha_filename_mismatch_count"] is None:
        status = "WARN" if status == "OK" else status
        findings.append("Canonical SHA-256 byte verification was skipped.")

    return {
        "status": status,
        "findings": findings,
        "data_root": root.as_posix(),
        "data_store_apk": {
            "path": apk_status["path"],
            "exists": apk_status["exists"],
            "is_symlink": apk_status["is_symlink"],
            "resolved_target": apk_status["resolved_target"],
            "target_exists": apk_status["target_exists"],
            "under_external_mount": bool(apk_status["external_mount_root"]),
            "external_mount_root": apk_status["external_mount_root"],
            "external_mount_mounted": apk_status["external_mount_mounted"],
        },
        "canonical_store": canonical,
        "data_android_apks": android_status,
        "legacy_device_apks": {
            "serial": serial,
            "runs_root": (root / "device_apks" / serial / "runs").as_posix(),
            "broken_apk_symlink_count": broken_legacy,
        },
    }


def _path_status(
    path: Path,
    *,
    mount_roots: Sequence[Path],
    is_mount: Callable[[str], bool] | None,
) -> dict[str, Any]:
    mount_check = is_mount or os.path.ismount
    exists = path.exists()
    symlink = path.is_symlink()
    target = _symlink_target(path) if symlink else path.expanduser().resolve(strict=False)
    external = _external_mount_root_for(target, mount_roots)
    return {
        "path": path.as_posix(),
        "exists": exists,
        "is_symlink": symlink,
        "resolved_target": target.as_posix(),
        "target_exists": target.exists(),
        "under_external_mount": bool(external),
        "external_mount_root": external.as_posix() if external else None,
        "external_mount_mounted": bool(external and mount_check(str(external))),
    }


def _canonical_counts(
    root: Path,
    *,
    verify_sha256: bool,
    mount_roots: Sequence[Path] | None = None,
    is_mount: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    count = 0
    hot_regular = 0
    cold_symlink = 0
    symlink_outside = 0
    broken_symlink = 0
    missing_target = 0
    unavailable_cold = 0
    hot_bytes = 0
    cold_bytes = 0
    unavailable_cold_bytes = 0
    zero = 0
    unreadable = 0
    bad_pattern = 0
    mismatch: int | None = 0 if verify_sha256 else None
    roots = tuple(mount_roots or artifact_store.EXTERNAL_APK_STORE_MOUNT_ROOTS)
    mount_check = is_mount or os.path.ismount
    for path in sorted(root.rglob("*.apk")) if root.exists() else []:
        count += 1
        stem = path.stem.lower()
        try:
            rel = path.relative_to(root)
            prefix = rel.parts[0] if len(rel.parts) >= 2 else ""
        except ValueError:
            prefix = ""
        if len(stem) != 64 or prefix != stem[:2]:
            bad_pattern += 1
        if path.is_symlink():
            target = _symlink_target(path)
            external = _external_mount_root_for(target, roots)
            target_exists = target.exists()
            if external:
                cold_symlink += 1
                if not mount_check(str(external)):
                    unavailable_cold += 1
                    unavailable_cold_bytes += target.stat().st_size if target_exists else 0
                elif target_exists:
                    cold_bytes += target.stat().st_size
                else:
                    unavailable_cold += 1
                    unavailable_cold_bytes += 0
            else:
                symlink_outside += 1
            if not target_exists:
                missing_target += 1
            if not path.exists():
                broken_symlink += 1
            if not target_exists or (external and not mount_check(str(external))):
                continue
            if not os.access(path, os.R_OK):
                unreadable += 1
                continue
            if path.stat().st_size == 0:
                zero += 1
            if verify_sha256 and len(stem) == 64:
                digest = _sha256(path)
                if digest != stem:
                    mismatch = int(mismatch or 0) + 1
            continue
        if not path.is_file():
            continue
        hot_regular += 1
        if not os.access(path, os.R_OK):
            unreadable += 1
            continue
        size = path.stat().st_size
        hot_bytes += size
        if size == 0:
            zero += 1
        if verify_sha256 and len(stem) == 64:
            digest = _sha256(path)
            if digest != stem:
                mismatch = int(mismatch or 0) + 1
    return {
        "path": root.as_posix(),
        "canonical_apk_blob_count": count,
        "local_hot_regular_blob_count": hot_regular,
        "cold_symlink_blob_count": cold_symlink,
        "broken_canonical_symlink_count": broken_symlink,
        "canonical_symlink_outside_allowed_roots_count": symlink_outside,
        "canonical_symlink_missing_target_count": missing_target,
        "unavailable_cold_blob_count": unavailable_cold,
        "local_hot_bytes": hot_bytes,
        "cold_referenced_bytes": cold_bytes,
        "unavailable_cold_bytes": unavailable_cold_bytes,
        "zero_size_canonical_blob_count": zero,
        "unreadable_canonical_blob_count": unreadable,
        "bad_canonical_path_pattern_count": bad_pattern,
        "sha_filename_mismatch_count": mismatch,
        "sha256_verified": verify_sha256,
    }


def _broken_legacy_apk_symlinks(root: Path) -> int:
    if not root.exists():
        return 0
    total = 0
    for path in root.rglob("*.apk"):
        if path.is_symlink() and not path.exists():
            total += 1
    return total


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _external_mount_root_for(path: Path, roots: Sequence[Path]) -> Path | None:
    resolved = path.expanduser().resolve(strict=False)
    for root in sorted(roots, key=lambda p: len(p.parts), reverse=True):
        candidate = Path(root).expanduser().resolve(strict=False)
        try:
            resolved.relative_to(candidate)
        except ValueError:
            continue
        return candidate
    return None


def _symlink_target(path: Path) -> Path:
    raw = path.readlink()
    if raw.is_absolute():
        return raw.expanduser().resolve(strict=False)
    return (path.parent / raw).expanduser().resolve(strict=False)


def _print_human(report: dict[str, Any]) -> None:
    print(f"Status: {report['status']}")
    for finding in report["findings"]:
        print(f"- {finding}")
    print(f"data_root: {report['data_root']}")
    for section in ("data_store_apk", "data_android_apks"):
        payload = report[section]
        print(f"\n{section}:")
        for key, value in payload.items():
            print(f"  {key}: {value}")
    print("\ncanonical_store:")
    for key, value in report["canonical_store"].items():
        print(f"  {key}: {value}")
    print("\nlegacy_device_apks:")
    for key, value in report["legacy_device_apks"].items():
        print(f"  {key}: {value}")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    mount_roots = [Path(p) for p in args.mount_root] or list(artifact_store.EXTERNAL_APK_STORE_MOUNT_ROOTS)
    report = build_report(
        data_root=Path(args.data_root) if args.data_root else None,
        serial=args.serial,
        mount_roots=mount_roots,
        verify_sha256=not args.skip_sha256,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_human(report)
    return 2 if report["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
