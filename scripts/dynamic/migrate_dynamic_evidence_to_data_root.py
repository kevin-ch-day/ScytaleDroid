#!/usr/bin/env python3
"""Migrate dynamic evidence packs from output/ to data/.

Dry-run is the default. The safe apply flow copies a pack to the canonical
data-root first and verifies counts/bytes before changing the legacy source.
Use --replace-with-symlink to reclaim output/ bytes while keeping legacy direct
paths usable.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config  # noqa: E402
from scytaledroid.DynamicAnalysis.utils.path_utils import (  # noqa: E402
    dynamic_evidence_root,
    legacy_dynamic_evidence_root,
)


@dataclass(frozen=True)
class PackStats:
    files: int
    bytes: int


@dataclass(frozen=True)
class FileFingerprint:
    size: int
    sha256: str


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _pack_stats(path: Path) -> PackStats:
    files = 0
    size = 0
    for item in path.rglob("*"):
        if item.is_symlink():
            continue
        if item.is_file():
            files += 1
            try:
                size += item.stat().st_size
            except OSError:
                pass
    return PackStats(files=files, bytes=size)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_fingerprints(path: Path) -> dict[str, FileFingerprint]:
    out: dict[str, FileFingerprint] = {}
    for item in sorted(path.rglob("*")):
        if item.is_symlink() or not item.is_file():
            continue
        rel = item.relative_to(path).as_posix()
        st = item.stat()
        out[rel] = FileFingerprint(size=int(st.st_size), sha256=_sha256_file(item))
    return out


def _verify_pack(source: Path, dest: Path) -> tuple[bool, str, PackStats, PackStats]:
    src_stats = _pack_stats(source)
    dest_stats = _pack_stats(dest)
    if src_stats != dest_stats:
        return False, f"copy verification mismatch source={src_stats} dest={dest_stats}", src_stats, dest_stats
    src_fp = _file_fingerprints(source)
    dest_fp = _file_fingerprints(dest)
    if src_fp != dest_fp:
        src_keys = set(src_fp)
        dest_keys = set(dest_fp)
        missing = sorted(src_keys - dest_keys)[:3]
        extra = sorted(dest_keys - src_keys)[:3]
        mismatched = sorted(k for k in src_keys.intersection(dest_keys) if src_fp[k] != dest_fp[k])[:3]
        return (
            False,
            "copy hash verification mismatch "
            f"missing={missing} extra={extra} mismatched={mismatched}",
            src_stats,
            dest_stats,
        )
    return True, "hash verified", src_stats, dest_stats


def _is_within(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError:
        return False
    return resolved == root_resolved or root_resolved in resolved.parents


def _iter_legacy_run_dirs(source_root: Path) -> list[Path]:
    if not source_root.exists():
        return []
    return sorted([p for p in source_root.iterdir() if p.is_dir()], key=lambda p: p.name)


def _copy_pack(source: Path, dest: Path) -> tuple[str, str]:
    if dest.exists():
        if source.is_symlink() and source.resolve() == dest.resolve():
            return "already_present", "destination exists and source already points to it"
        ok, reason, _src_stats, _dest_stats = _verify_pack(source, dest)
        if ok:
            return "already_present", f"destination exists; {reason}"
        return "blocked_existing_mismatch", reason
    tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}")
    if tmp.exists():
        shutil.rmtree(tmp)
    shutil.copytree(source, tmp, symlinks=True)
    ok, reason, _src_stats, _tmp_stats = _verify_pack(source, tmp)
    if not ok:
        shutil.rmtree(tmp, ignore_errors=True)
        return "blocked", reason
    tmp.rename(dest)
    return "copied", f"copied and {reason}"


def _replace_source_with_symlink(source: Path, dest: Path) -> tuple[bool, str]:
    if source.is_symlink():
        return True, "source already symlink"
    backup = source.with_name(f".{source.name}.migrate-backup-{os.getpid()}")
    if backup.exists():
        return False, f"backup path already exists: {backup}"
    try:
        source.rename(backup)
        source.symlink_to(dest.resolve(), target_is_directory=True)
        if not source.is_symlink() or source.resolve() != dest.resolve():
            source.unlink(missing_ok=True)
            backup.rename(source)
            return False, "symlink verification failed; source restored"
        shutil.rmtree(backup)
        return True, "source replaced with compatibility symlink"
    except Exception as exc:  # noqa: BLE001
        try:
            if source.is_symlink():
                source.unlink()
            if backup.exists() and not source.exists():
                backup.rename(source)
        except Exception:
            pass
        return False, f"{type(exc).__name__}: {exc}"


def _write_outputs(receipt_dir: Path, rows: list[dict[str, object]], *, args: argparse.Namespace) -> None:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "apply": bool(args.apply),
        "replace_with_symlink": bool(args.replace_with_symlink),
        "source_root": str(args.source_root),
        "dest_root": str(args.dest_root),
        "rows": len(rows),
        "planned": sum(1 for r in rows if r["status"] == "planned"),
        "copied": sum(1 for r in rows if r["status"] == "copied"),
        "already_present": sum(1 for r in rows if r["status"] == "already_present"),
        "symlinked": sum(1 for r in rows if r.get("source_replaced_with_symlink") is True),
        "blocked": sum(1 for r in rows if str(r["status"]).startswith("blocked")),
        "bytes_selected": sum(int(r.get("source_bytes") or 0) for r in rows),
    }
    (receipt_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (receipt_dir / "actions.csv").open("w", newline="", encoding="utf-8") as fh:
        keys = [
            "run_id",
            "source_path",
            "dest_path",
            "source_files",
            "source_bytes",
            "dest_files",
            "dest_bytes",
            "status",
            "reason",
            "source_replaced_with_symlink",
        ]
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=legacy_dynamic_evidence_root())
    parser.add_argument("--dest-root", type=Path, default=dynamic_evidence_root())
    parser.add_argument("--receipt-dir", type=Path, default=Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_evidence_migration")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--run-id", action="append", default=[])
    parser.add_argument("--apply", action="store_true", help="Perform copy/verification. Default is dry-run.")
    parser.add_argument(
        "--replace-with-symlink",
        action="store_true",
        help="After verified copy, replace the legacy source directory with a compatibility symlink.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    source_root = args.source_root
    dest_root = args.dest_root
    if not _is_within(source_root, REPO_ROOT) or not _is_within(dest_root, REPO_ROOT):
        parser.error("source-root and dest-root must resolve inside the ScytaleDroid repo")
    if args.replace_with_symlink and not args.apply:
        parser.error("--replace-with-symlink requires --apply")

    run_filter = {str(x).strip() for x in args.run_id if str(x).strip()}
    run_dirs = _iter_legacy_run_dirs(source_root)
    if run_filter:
        run_dirs = [p for p in run_dirs if p.name in run_filter]
    if args.limit is not None:
        run_dirs = run_dirs[: max(0, int(args.limit))]

    rows: list[dict[str, object]] = []
    for source in run_dirs:
        dest = dest_root / source.name
        src_stats = _pack_stats(source)
        status = "planned"
        reason = "dry-run"
        dest_stats = PackStats(0, 0)
        source_replaced = False
        if args.apply:
            status, reason = _copy_pack(source, dest)
            if dest.exists():
                dest_stats = _pack_stats(dest)
            if status in {"copied", "already_present"} and args.replace_with_symlink:
                ok, symlink_reason = _replace_source_with_symlink(source, dest)
                source_replaced = ok
                if not ok:
                    status = "blocked_symlink"
                reason = f"{reason}; {symlink_reason}"
        elif dest.exists():
            dest_stats = _pack_stats(dest)
            status = "already_present"
            reason = "destination already exists"
        rows.append(
            {
                "run_id": source.name,
                "source_path": str(source),
                "dest_path": str(dest),
                "source_files": src_stats.files,
                "source_bytes": src_stats.bytes,
                "dest_files": dest_stats.files,
                "dest_bytes": dest_stats.bytes,
                "status": status,
                "reason": reason,
                "source_replaced_with_symlink": source_replaced,
            }
        )

    receipt_dir = args.receipt_dir / _utc_stamp()
    _write_outputs(receipt_dir, rows, args=args)
    print(f"Wrote migration receipt: {receipt_dir}")
    print(f"selected={len(rows)} apply={bool(args.apply)} replace_with_symlink={bool(args.replace_with_symlink)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
