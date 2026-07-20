#!/usr/bin/env python3
"""Convert legacy harvest session APK payloads into canonical-store symlinks.

Dry-run by default. In apply mode, each eligible regular APK under
``data/device_apks/<serial>/runs/<session>/...`` is replaced with a relative
symlink to its existing canonical SHA-store blob. Sidecars, package manifests,
receipts, and DB rows are not modified.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _external_apk_store_mount_roots() -> tuple[Path, ...]:
    """Load the shared mount configuration after direct-script path bootstrap."""

    from scytaledroid.DeviceAnalysis.services.artifact_store import EXTERNAL_APK_STORE_MOUNT_ROOTS

    return EXTERNAL_APK_STORE_MOUNT_ROOTS


EXTERNAL_APK_STORE_MOUNT_ROOTS = _external_apk_store_mount_roots()


@dataclass(frozen=True)
class ThinCandidate:
    apk_path: str
    session_label: str
    sha256: str
    canonical_path: str
    size_bytes: int
    allocated_bytes: int
    physical_reclaimable_bytes: int
    status: str
    reason: str
    applied: bool = False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=None, help="Data root; default configured DATA_DIR.")
    parser.add_argument("--session", action="append", default=[], help="Only process one session label; repeatable.")
    parser.add_argument("--latest-session", action="store_true", help="Process only the newest harvest session directory.")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N eligible candidates.")
    parser.add_argument("--verify", action="store_true", help="Hash session and canonical APK bytes before eligibility.")
    parser.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow apply without hashing when sidecar, manifest, and canonical blob checks pass.",
    )
    parser.add_argument("--apply", action="store_true", help="Replace eligible regular APKs with symlinks.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Report directory; default output/audit/storage.")
    parser.add_argument("--stamp", default=None, help="Output filename stamp; default current UTC timestamp.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _logical_absolute(path: Path) -> Path:
    """Return an absolute path without resolving symlinks."""

    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _inside_logical(path: Path, root: Path) -> bool:
    try:
        _logical_absolute(path).relative_to(_logical_absolute(root))
        return True
    except ValueError:
        return False


def _symlink_target(path: Path) -> Path:
    raw = path.readlink()
    if raw.is_absolute():
        return raw.expanduser().resolve(strict=False)
    return (path.parent / raw).expanduser().resolve(strict=False)


def _external_mount_root_for(path: Path) -> Path | None:
    resolved = path.expanduser().resolve(strict=False)
    for root in sorted(EXTERNAL_APK_STORE_MOUNT_ROOTS, key=lambda item: len(item.parts), reverse=True):
        candidate = root.expanduser().resolve(strict=False)
        try:
            resolved.relative_to(candidate)
        except ValueError:
            continue
        return candidate
    return None


def _canonical_availability_reason(path: Path) -> str | None:
    if not path.is_symlink():
        return None if path.exists() else "canonical_missing"

    target = _symlink_target(path)
    external_root = _external_mount_root_for(target)
    if external_root is not None and not os.path.ismount(str(external_root)):
        return "cold_apk_store_unmounted"
    if not target.exists():
        return "canonical_missing"
    return None


def _session_label(path: Path) -> str:
    parts = path.parts
    if "runs" not in parts:
        return ""
    index = parts.index("runs")
    return parts[index + 1] if index + 1 < len(parts) else ""


def _latest_session(device_root: Path) -> str | None:
    sessions = [
        path
        for path in device_root.glob("*/runs/*")
        if path.is_dir()
    ]
    if not sessions:
        return None
    return max(sessions, key=lambda path: (path.stat().st_mtime, path.as_posix())).name


def _same_inode(path_a: Path, path_b: Path) -> bool:
    try:
        a = path_a.stat()
        b = path_b.stat()
    except OSError:
        return False
    return int(a.st_dev) == int(b.st_dev) and int(a.st_ino) == int(b.st_ino)


def _allocated_bytes(path: Path) -> int:
    try:
        return int(getattr(path.stat(), "st_blocks", 0)) * 512
    except OSError:
        return 0


def _candidate_for_apk(
    apk_path: Path,
    *,
    data_root: Path,
    repo_root: Path,
    canonical_root: Path,
    verify: bool,
) -> ThinCandidate:
    session = _session_label(apk_path)
    size = apk_path.stat().st_size if apk_path.exists() and not apk_path.is_symlink() else 0
    allocated = _allocated_bytes(apk_path) if apk_path.exists() and not apk_path.is_symlink() else 0
    sidecar_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    manifest_path = apk_path.parent / "harvest_package_manifest.json"

    if apk_path.is_symlink():
        return ThinCandidate(apk_path.as_posix(), session, "", "", size, allocated, 0, "skip", "already_symlink")
    if not apk_path.is_file():
        return ThinCandidate(apk_path.as_posix(), session, "", "", size, allocated, 0, "blocked", "not_regular_file")
    if not sidecar_path.exists():
        return ThinCandidate(apk_path.as_posix(), session, "", "", size, allocated, 0, "blocked", "missing_sidecar")
    if not manifest_path.exists():
        return ThinCandidate(apk_path.as_posix(), session, "", "", size, allocated, 0, "blocked", "missing_manifest")

    sidecar = _read_json(sidecar_path)
    sha = str(sidecar.get("sha256") or "").strip().lower()
    if len(sha) != 64:
        return ThinCandidate(apk_path.as_posix(), session, sha, "", size, allocated, 0, "blocked", "missing_sha256")
    declared = str(sidecar.get("canonical_store_path") or "").strip()
    if not declared:
        return ThinCandidate(apk_path.as_posix(), session, sha, "", size, allocated, 0, "blocked", "missing_canonical_store_path")
    canonical_path = Path(declared)
    if not canonical_path.is_absolute():
        canonical_path = _logical_absolute(repo_root / canonical_path)
    if not _inside_logical(canonical_path, canonical_root):
        return ThinCandidate(apk_path.as_posix(), session, sha, canonical_path.as_posix(), size, allocated, 0, "blocked", "canonical_outside_store")
    expected_path = canonical_root / sha[:2] / f"{sha}.apk"
    if _logical_absolute(canonical_path) != _logical_absolute(expected_path):
        return ThinCandidate(apk_path.as_posix(), session, sha, canonical_path.as_posix(), size, allocated, 0, "blocked", "canonical_path_sha_mismatch")
    unavailable_reason = _canonical_availability_reason(canonical_path)
    if unavailable_reason is not None:
        return ThinCandidate(apk_path.as_posix(), session, sha, canonical_path.as_posix(), size, allocated, 0, "blocked", unavailable_reason)
    if verify:
        if _hash_file(apk_path) != sha:
            return ThinCandidate(apk_path.as_posix(), session, sha, canonical_path.as_posix(), size, allocated, 0, "blocked", "session_hash_mismatch")
        if _hash_file(canonical_path) != sha:
            return ThinCandidate(apk_path.as_posix(), session, sha, canonical_path.as_posix(), size, allocated, 0, "blocked", "canonical_hash_mismatch")
        reason = "eligible_verified"
    else:
        reason = "eligible_unverified"
    physical = 0 if _same_inode(apk_path, canonical_path) else allocated
    return ThinCandidate(
        apk_path=apk_path.as_posix(),
        session_label=session,
        sha256=sha,
        canonical_path=canonical_path.as_posix(),
        size_bytes=size,
        allocated_bytes=allocated,
        physical_reclaimable_bytes=physical,
        status="eligible",
        reason=reason,
    )


def _iter_apks(device_root: Path, *, sessions: set[str]) -> list[Path]:
    paths = []
    for apk_path in sorted(device_root.rglob("*.apk")):
        if "runs" not in apk_path.parts:
            continue
        if apk_path.is_dir():
            continue
        if sessions and _session_label(apk_path) not in sessions:
            continue
        paths.append(apk_path)
    return paths


def _apply_candidate(candidate: ThinCandidate) -> ThinCandidate:
    apk_path = Path(candidate.apk_path)
    canonical_path = Path(candidate.canonical_path)
    backup = apk_path.with_name(f"{apk_path.name}.thin-backup-{os.getpid()}")
    target = os.path.relpath(canonical_path, start=apk_path.parent)
    apk_path.rename(backup)
    try:
        apk_path.symlink_to(target)
        if not apk_path.exists() or not apk_path.is_symlink():
            raise RuntimeError("created symlink is not readable")
        if apk_path.resolve(strict=True) != canonical_path.resolve(strict=True):
            raise RuntimeError("created symlink target mismatch")
        backup.unlink()
    except Exception:
        try:
            if apk_path.is_symlink() or apk_path.exists():
                apk_path.unlink()
            backup.rename(apk_path)
        finally:
            pass
        raise
    return ThinCandidate(**{**asdict(candidate), "applied": True})


def _write_csv(path: Path, rows: list[ThinCandidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(ThinCandidate.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.latest_session and args.session:
        sys.stderr.write("--latest-session and --session are mutually exclusive.\n")
        return 2
    if args.apply and not args.verify and not args.allow_unverified:
        sys.stderr.write("--apply requires --verify, or explicit --allow-unverified.\n")
        return 2

    from scytaledroid.DeviceAnalysis.services import artifact_store

    data_root = (args.data_root or artifact_store.data_root()).expanduser().resolve()
    repo_root = data_root.parent.resolve()
    device_root = data_root / "device_apks"
    canonical_root = data_root / "store" / "apk" / "sha256"
    sessions = {str(item).strip() for item in args.session if str(item).strip()}
    if args.latest_session:
        latest = _latest_session(device_root)
        sessions = {latest} if latest else set()

    candidates: list[ThinCandidate] = []
    eligible_seen = 0
    for apk_path in _iter_apks(device_root, sessions=sessions):
        candidate = _candidate_for_apk(
            apk_path,
            data_root=data_root,
            repo_root=repo_root,
            canonical_root=canonical_root,
            verify=bool(args.verify),
        )
        if candidate.status == "eligible":
            eligible_seen += 1
            if args.limit > 0 and eligible_seen > args.limit:
                break
        candidates.append(candidate)

    rows: list[ThinCandidate] = []
    errors: list[str] = []
    for candidate in candidates:
        if args.apply and candidate.status == "eligible":
            try:
                rows.append(_apply_candidate(candidate))
            except Exception as exc:
                rows.append(ThinCandidate(**{**asdict(candidate), "status": "error", "reason": repr(exc)}))
                errors.append(f"{candidate.apk_path}: {exc!r}")
        else:
            rows.append(candidate)

    counts = Counter(row.reason for row in rows)
    stamp = args.stamp or _stamp()
    output_dir = (args.output_dir or (Path("output") / "audit" / "storage")).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / f"thin_session_apply_candidates_{stamp}.csv"
    summary_path = output_dir / f"thin_session_apply_{stamp}.json"
    _write_csv(csv_path, rows)
    summary = {
        "schema_version": "thin_session_apply_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "mode": "apply" if args.apply else "dry_run",
        "data_root": data_root.as_posix(),
        "sessions": sorted(sessions),
        "verify": bool(args.verify),
        "allow_unverified": bool(args.allow_unverified),
        "rows_seen": len(rows),
        "eligible_files": sum(1 for row in rows if row.status == "eligible"),
        "applied_files": sum(1 for row in rows if row.applied),
        "blocked_or_skipped_files": sum(1 for row in rows if row.status != "eligible"),
        "logical_reclaimable_bytes": sum(row.size_bytes for row in rows if row.status == "eligible"),
        "physical_reclaimable_bytes_estimate": sum(row.physical_reclaimable_bytes for row in rows if row.status == "eligible"),
        "applied_logical_bytes": sum(row.size_bytes for row in rows if row.applied),
        "applied_physical_bytes_estimate": sum(row.physical_reclaimable_bytes for row in rows if row.applied),
        "reason_counts": dict(sorted(counts.items())),
        "errors": errors,
        "csv_report": str(csv_path),
        "summary_json": str(summary_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("# Thin harvest session APKs")
        print(f"mode: {summary['mode']}")
        print(f"sessions: {summary['sessions'] or ['<all>']}")
        print(f"rows={summary['rows_seen']} eligible={summary['eligible_files']} applied={summary['applied_files']}")
        print(f"physical_reclaimable_bytes_estimate={summary['physical_reclaimable_bytes_estimate']}")
        print(csv_path)
        print(summary_path)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
