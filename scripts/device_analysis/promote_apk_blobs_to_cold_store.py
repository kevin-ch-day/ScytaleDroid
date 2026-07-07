#!/usr/bin/env python3
"""Promote eligible canonical APK blobs to Mercury cold storage.

Dry-run is the default. Apply mode copies verified local canonical APK blobs to
the Mercury cold store, replaces the local canonical path with a symlink, and
writes receipts. This script never touches DB rows, device_apks, dynamic
evidence, PCAPs, static reports, or sidecars.

For now the cold target is rooted at ``/mnt/MERCURY_DATA_V2``. Keep that path
available as an alias after final Mercury promotion, or run a reviewed path
migration for existing cold symlinks.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Config import app_config  # noqa: E402


DEFAULT_COLD_ROOT = Path("/mnt/MERCURY_DATA_V2/scytaledroid_artifacts/apk_store/cold")
DEFAULT_MOUNT_ROOT = Path("/mnt/MERCURY_DATA_V2")
ELIGIBLE_CLASS = "PROMOTE_COLD_PRIOR_VERSION_CANDIDATE"
BLOCKED_CLASSES = {
    "KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA",
    "KEEP_HOT_CURRENT_INSTALLED_BUILD",
    "KEEP_HOT_SELECTED_PAPER_TARGET",
    "KEEP_HOT_ACTIVE_DYNAMIC_LINEAGE",
    "KEEP_HOT_RECENT_STATIC_RUN",
}


@dataclass(frozen=True)
class PromotionInput:
    sha256: str
    size_bytes: int
    package_name: str
    version_code: str
    version_name: str
    local_path: str
    cold_path: str
    promotion_class: str


@dataclass(frozen=True)
class PromotionAction:
    sha256: str
    size_bytes: int
    package_name: str
    version_code: str
    version_name: str
    local_path: str
    cold_path: str
    promotion_class: str
    action: str
    status: str
    reason: str
    symlink_created: bool
    hash_verified_before: bool
    hash_verified_after: bool
    bytes_reclaimed: int


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Mutate selected blobs. Default is dry-run.")
    parser.add_argument("--verify", action="store_true", help="Hash selected local blobs during dry-run planning. Apply always verifies.")
    parser.add_argument("--limit", type=int, default=0, help="Limit selected eligible rows.")
    parser.add_argument("--max-bytes", type=int, default=0, help="Stop selection before exceeding this byte count.")
    parser.add_argument("--package", dest="packages", action="append", default=[], help="Only select this package; repeatable.")
    parser.add_argument("--sha256", dest="sha256s", action="append", default=[], help="Only select this SHA-256; repeatable.")
    parser.add_argument("--from-audit", type=Path, default=None, help="Path to cold-promotion candidates.csv.")
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=Path("output") / "audit" / "apk_cold_promotion_apply",
        help="Receipt root; timestamped subdirectory is created here.",
    )
    parser.add_argument("--data-root", type=Path, default=Path(app_config.DATA_DIR), help="Data root; default DATA_DIR.")
    parser.add_argument("--cold-root", type=Path, default=DEFAULT_COLD_ROOT, help="Mercury cold store root.")
    parser.add_argument("--mount-root", type=Path, default=DEFAULT_MOUNT_ROOT, help="Required Mercury mountpoint.")
    parser.add_argument("--stamp", default=None, help="Receipt stamp; default current UTC timestamp.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def load_candidates(path: Path) -> list[PromotionInput]:
    rows: list[PromotionInput] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            sha = str(row.get("sha256") or "").strip().lower()
            if len(sha) != 64:
                continue
            rows.append(
                PromotionInput(
                    sha256=sha,
                    size_bytes=_safe_int(row.get("size_bytes")),
                    package_name=str(row.get("package_name") or "").strip(),
                    version_code=str(row.get("version_code") or "").strip(),
                    version_name=str(row.get("version_name") or "").strip(),
                    local_path=str(row.get("local_canonical_path") or row.get("local_path") or "").strip(),
                    cold_path=str(row.get("proposed_mercury_cold_path") or row.get("cold_path") or "").strip(),
                    promotion_class=str(row.get("promotion_class") or "").strip(),
                )
            )
    return rows


def select_candidates(
    rows: Iterable[PromotionInput],
    *,
    packages: set[str] | None = None,
    sha256s: set[str] | None = None,
    limit: int = 0,
    max_bytes: int = 0,
) -> list[PromotionInput]:
    package_filter = {pkg.lower() for pkg in packages or set() if pkg}
    sha_filter = {sha.lower() for sha in sha256s or set() if sha}
    selected: list[PromotionInput] = []
    total = 0
    for row in rows:
        if row.promotion_class != ELIGIBLE_CLASS:
            continue
        if package_filter and row.package_name.lower() not in package_filter:
            continue
        if sha_filter and row.sha256.lower() not in sha_filter:
            continue
        if max_bytes > 0 and selected and total + int(row.size_bytes) > max_bytes:
            break
        if max_bytes > 0 and not selected and int(row.size_bytes) > max_bytes:
            continue
        selected.append(row)
        total += int(row.size_bytes)
        if limit > 0 and len(selected) >= limit:
            break
    return selected


def plan_or_apply(
    rows: Iterable[PromotionInput],
    *,
    data_root: Path,
    cold_root: Path,
    mount_root: Path,
    apply: bool = False,
    verify_hashes: bool = False,
    is_mount: Callable[[str], bool] | None = None,
    symlink_to: Callable[[Path, Path], None] | None = None,
) -> tuple[list[PromotionAction], list[PromotionAction], list[PromotionAction]]:
    actions: list[PromotionAction] = []
    blocked: list[PromotionAction] = []
    verification: list[PromotionAction] = []
    for row in rows:
        action = _process_one(
            row,
            data_root=data_root,
            cold_root=cold_root,
            mount_root=mount_root,
            apply=apply,
            verify_hashes=verify_hashes,
            is_mount=is_mount,
            symlink_to=symlink_to,
        )
        if action.status in {"blocked", "error"}:
            blocked.append(action)
        else:
            actions.append(action)
        verification.append(action)
    return actions, blocked, verification


def _process_one(
    row: PromotionInput,
    *,
    data_root: Path,
    cold_root: Path,
    mount_root: Path,
    apply: bool,
    verify_hashes: bool,
    is_mount: Callable[[str], bool] | None,
    symlink_to: Callable[[Path, Path], None] | None,
) -> PromotionAction:
    local = _resolve_local(row.local_path, data_root=data_root)
    cold = _resolve_cold(row.cold_path, cold_root=cold_root, sha=row.sha256)
    base = _base_action(row, local=local, cold=cold, action="promote_cold" if apply else "dry_run")

    blocked_reason = _preflight_block_reason(row, local=local, cold=cold, cold_root=cold_root)
    if blocked_reason:
        return _replace(base, status="blocked", reason=blocked_reason)

    if local.is_symlink():
        return _replace(base, action="already_cold", status="skipped", reason="local_path_already_symlink")

    mount_check = is_mount or os.path.ismount
    if not mount_check(str(mount_root)):
        return _replace(base, status="blocked", reason="mercury_mount_not_mounted")

    local_hash_verified = False
    if verify_hashes and not apply:
        if _sha256_file(local) != row.sha256:
            return _replace(base, status="blocked", reason="local_hash_mismatch")
        local_hash_verified = True

    existing_cold = _existing_cold_status(cold, row.sha256)
    if existing_cold == "mismatch":
        return _replace(base, status="blocked", reason="existing_cold_blob_hash_mismatch")
    if existing_cold == "unreadable":
        return _replace(base, status="blocked", reason="existing_cold_blob_unreadable")

    if not apply:
        reason = "dry_run_existing_cold_blob_reused" if existing_cold == "match" else "dry_run_copy_verify_symlink"
        return _replace(
            base,
            status="planned",
            reason=reason,
            hash_verified_before=local_hash_verified,
            hash_verified_after=bool(local_hash_verified and existing_cold == "match"),
        )

    try:
        return _apply_one(
            base,
            sha=row.sha256,
            local=local,
            cold=cold,
            existing_cold_matches=existing_cold == "match",
            symlink_to=symlink_to,
        )
    except Exception as exc:
        return _replace(base, status="error", reason=f"apply_error:{type(exc).__name__}:{exc}")


def _apply_one(
    base: PromotionAction,
    *,
    sha: str,
    local: Path,
    cold: Path,
    existing_cold_matches: bool,
    symlink_to: Callable[[Path, Path], None] | None,
) -> PromotionAction:
    size = local.stat().st_size
    if _sha256_file(local) != sha:
        return _replace(base, status="blocked", reason="local_hash_mismatch")
    if not existing_cold_matches:
        cold.parent.mkdir(parents=True, exist_ok=True)
        tmp = cold.with_name(f".{cold.name}.tmp-{os.getpid()}")
        try:
            shutil.copy2(local, tmp)
            if _sha256_file(tmp) != sha:
                tmp.unlink(missing_ok=True)
                return _replace(base, status="blocked", reason="cold_temp_hash_mismatch", hash_verified_before=True)
            tmp.replace(cold)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
    if _sha256_file(cold) != sha:
        return _replace(base, status="blocked", reason="cold_hash_mismatch_after_copy", hash_verified_before=True)

    backup = local.with_name(f".{local.name}.hot-backup-{os.getpid()}")
    local.rename(backup)
    created = False
    try:
        rel_target = Path(os.path.relpath(cold, start=local.parent))
        if symlink_to:
            symlink_to(local, rel_target)
        else:
            local.symlink_to(rel_target)
        created = True
        if not local.is_symlink() or not local.exists():
            raise RuntimeError("created symlink does not resolve")
        if _sha256_file(local) != sha:
            raise RuntimeError("local symlink hash verification failed")
        backup.unlink()
    except Exception:
        try:
            if local.is_symlink() or local.exists():
                local.unlink()
            backup.rename(local)
        finally:
            pass
        raise
    return _replace(
        base,
        status="applied",
        reason="promoted_to_cold",
        symlink_created=created,
        hash_verified_before=True,
        hash_verified_after=True,
        bytes_reclaimed=size,
    )


def _preflight_block_reason(row: PromotionInput, *, local: Path, cold: Path, cold_root: Path) -> str:
    if row.promotion_class in BLOCKED_CLASSES or row.promotion_class.startswith("BLOCKED_"):
        return f"promotion_class_not_eligible:{row.promotion_class}"
    if row.promotion_class != ELIGIBLE_CLASS:
        return f"promotion_class_not_eligible:{row.promotion_class or 'missing'}"
    if len(row.sha256) != 64:
        return "invalid_sha256"
    if not _inside(cold, cold_root):
        return "cold_path_outside_cold_root"
    expected_local = local.parent.name == row.sha256[:2] and local.name == f"{row.sha256}.apk"
    if not expected_local:
        return "local_path_sha_mismatch"
    if not local.exists() and not local.is_symlink():
        return "local_path_missing"
    if local.is_symlink():
        return ""
    if not local.is_file():
        return "local_path_not_regular_file"
    if local.stat().st_size <= 0:
        return "local_path_zero_size"
    return ""


def _existing_cold_status(path: Path, sha: str) -> str:
    if not path.exists():
        return "missing"
    if not path.is_file():
        return "unreadable"
    try:
        return "match" if _sha256_file(path) == sha else "mismatch"
    except OSError:
        return "unreadable"


def _resolve_local(value: str, *, data_root: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    repo_root = data_root.resolve().parent
    return (repo_root / path).resolve(strict=False)


def _resolve_cold(value: str, *, cold_root: Path, sha: str) -> Path:
    path = Path(value) if value else cold_root / "data" / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"
    if path.is_absolute():
        return path.resolve(strict=False)
    return (cold_root / "data" / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk").resolve(strict=False)


def _base_action(row: PromotionInput, *, local: Path, cold: Path, action: str) -> PromotionAction:
    return PromotionAction(
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        package_name=row.package_name,
        version_code=row.version_code,
        version_name=row.version_name,
        local_path=local.as_posix(),
        cold_path=cold.as_posix(),
        promotion_class=row.promotion_class,
        action=action,
        status="pending",
        reason="",
        symlink_created=False,
        hash_verified_before=False,
        hash_verified_after=False,
        bytes_reclaimed=0,
    )


def _replace(row: PromotionAction, **changes: Any) -> PromotionAction:
    return PromotionAction(**{**asdict(row), **changes})


def write_receipts(
    *,
    receipt_dir: Path,
    stamp: str,
    apply: bool,
    verify: bool,
    from_audit: Path,
    actions: list[PromotionAction],
    blocked: list[PromotionAction],
    verification: list[PromotionAction],
) -> dict[str, str]:
    out = receipt_dir / stamp
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "summary_json": (out / "summary.json").as_posix(),
        "actions_csv": (out / "actions.csv").as_posix(),
        "blocked_csv": (out / "blocked.csv").as_posix(),
        "verification_csv": (out / "verification.csv").as_posix(),
    }
    all_rows = actions + blocked
    summary = {
        "schema_version": "apk_cold_promotion_apply_v1",
        "mode": "apply" if apply else "dry_run",
        "verify_local_hashes": bool(verify or apply),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "from_audit": from_audit.as_posix(),
        "selected_rows": len(all_rows),
        "selected_bytes": sum(row.size_bytes for row in all_rows),
        "actions": len(actions),
        "blocked": len(blocked),
        "applied": sum(1 for row in actions if row.status == "applied"),
        "planned": sum(1 for row in actions if row.status == "planned"),
        "already_cold": sum(1 for row in actions if row.action == "already_cold"),
        "planned_bytes": sum(row.size_bytes for row in actions if row.status == "planned"),
        "blocked_bytes": sum(row.size_bytes for row in blocked),
        "hash_verified_before_count": sum(1 for row in all_rows if row.hash_verified_before),
        "hash_verified_after_count": sum(1 for row in all_rows if row.hash_verified_after),
        "bytes_reclaimed": sum(row.bytes_reclaimed for row in actions),
        "status_counts": dict(Counter(row.status for row in all_rows)),
        "reason_counts": dict(Counter(row.reason for row in all_rows)),
        "outputs": paths,
    }
    Path(paths["summary_json"]).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(Path(paths["actions_csv"]), actions)
    _write_csv(Path(paths["blocked_csv"]), blocked)
    _write_csv(Path(paths["verification_csv"]), verification)
    return paths


def _write_csv(path: Path, rows: list[PromotionAction]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(PromotionAction.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def _latest_candidates_csv() -> Path | None:
    root = Path(app_config.OUTPUT_DIR) / "audit" / "apk_cold_promotion"
    candidates = sorted(root.glob("*/candidates.csv"), key=lambda p: (p.parent.name, p.stat().st_mtime))
    return candidates[-1] if candidates else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    from_audit = args.from_audit or _latest_candidates_csv()
    if from_audit is None:
        sys.stderr.write("No candidates.csv found. Pass --from-audit.\n")
        return 2
    if not from_audit.exists():
        sys.stderr.write(f"Audit candidates CSV not found: {from_audit}\n")
        return 2

    rows = load_candidates(from_audit)
    selected = select_candidates(
        rows,
        packages=set(args.packages),
        sha256s=set(args.sha256s),
        limit=int(args.limit or 0),
        max_bytes=int(args.max_bytes or 0),
    )
    actions, blocked, verification = plan_or_apply(
        selected,
        data_root=args.data_root.expanduser().resolve(),
        cold_root=args.cold_root.expanduser().resolve(strict=False),
        mount_root=args.mount_root.expanduser().resolve(strict=False),
        apply=bool(args.apply),
        verify_hashes=bool(args.verify),
    )
    stamp = args.stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    paths = write_receipts(
        receipt_dir=args.receipt_dir,
        stamp=stamp,
        apply=bool(args.apply),
        verify=bool(args.verify),
        from_audit=from_audit,
        actions=actions,
        blocked=blocked,
        verification=verification,
    )
    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("APK cold-promotion apply planner")
        print(f"  Mode          : {summary['mode']}")
        print(f"  From audit    : {summary['from_audit']}")
        print(f"  Selected rows : {summary['selected_rows']}")
        print(f"  Actions       : {summary['actions']}")
        print(f"  Blocked       : {summary['blocked']}")
        print(f"  Applied       : {summary['applied']}")
        print(f"  Planned       : {summary['planned']}")
        print(f"  Planned bytes : {summary['planned_bytes']}")
        print(f"  Hash verified : {summary['hash_verified_before_count']}")
        print(f"  Reclaimed     : {summary['bytes_reclaimed']}")
        print("  Outputs:")
        for key, value in paths.items():
            print(f"    {key}: {value}")
        if not args.apply:
            print("  Dry-run only; no APK files were moved and no symlinks were created.")
    return 1 if blocked and args.apply else 0


if __name__ == "__main__":
    raise SystemExit(main())
