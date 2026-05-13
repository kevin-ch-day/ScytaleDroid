#!/usr/bin/env python3
"""Backfill APK install-set identity tables from harvest receipts.

Default mode is read-only.  ``--apply`` creates additive install-set tables and
upserts rows derived from receipt-backed observed artifacts only.  Package-level
``apk_split_groups`` is intentionally not used for membership inference.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class ReceiptMember:
    role: str
    split_name: str
    sha256: str
    file_name: str | None
    file_size: int | None
    source_path: str | None
    local_relpath: str | None
    canonical_relpath: str | None
    pull_status: str
    ordinal: int


@dataclass(frozen=True)
class ReceiptSet:
    receipt_path: Path
    session_label: str
    device_serial: str | None
    snapshot_id: int | None
    package_name: str
    version_code: str | None
    version_name: str | None
    generated_at_utc: str | None
    status: str
    base_sha256: str
    artifact_set_hash: str
    artifact_set_hash_version: str
    completeness_state: str
    members: tuple[ReceiptMember, ...]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipts-root",
        default="data/receipts/harvest",
        help="Harvest receipts root (default: data/receipts/harvest).",
    )
    parser.add_argument("--package", dest="package_name", help="Limit to one package.")
    parser.add_argument("--session-label", help="Limit to one harvest session label.")
    parser.add_argument("--limit", type=int, default=0, help="Limit parsed receipt sets.")
    parser.add_argument("--apply", action="store_true", help="Create tables and upsert rows.")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary.")
    args = parser.parse_args(argv)

    receipt_root = Path(args.receipts_root)
    sets, skipped = collect_receipt_sets(
        receipt_root,
        package_name=args.package_name,
        session_label=args.session_label,
        limit=max(args.limit, 0),
    )
    summary: dict[str, Any] = {
        "apply": bool(args.apply),
        "receipts_root": receipt_root.as_posix(),
        "receipt_sets_processed": len(sets),
        "unique_install_sets": len({item.artifact_set_hash for item in sets}),
        "unique_member_rows": len(
            {
                (item.artifact_set_hash, member.role, member.split_name, member.sha256)
                for item in sets
                for member in item.members
            }
        ),
        "members": sum(len(item.members) for item in sets),
        "skipped_receipts": skipped,
        "packages": len({item.package_name for item in sets}),
        "sessions": len({item.session_label for item in sets}),
        "completeness": _count_by(sets, "completeness_state"),
    }

    if args.apply:
        try:
            applied = apply_backfill(sets, receipt_root=receipt_root)
        except Exception as exc:
            sys.stderr.write(f"Backfill failed: {exc}\n")
            return 2
        summary.update(applied)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        _print_summary(summary)
    return 0


def collect_receipt_sets(
    receipt_root: Path,
    *,
    package_name: str | None = None,
    session_label: str | None = None,
    limit: int = 0,
) -> tuple[list[ReceiptSet], dict[str, int]]:
    sets: list[ReceiptSet] = []
    skipped = {
        "missing_root": 0,
        "invalid_json": 0,
        "filtered": 0,
        "no_observed_artifacts": 0,
        "missing_base": 0,
        "missing_hash": 0,
    }
    if not receipt_root.exists():
        skipped["missing_root"] += 1
        return sets, skipped

    package_filter = package_name.strip().lower() if package_name else None
    session_filter = session_label.strip() if session_label else None

    for path in sorted(receipt_root.glob("*/*.json")):
        if limit and len(sets) >= limit:
            break
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            skipped["invalid_json"] += 1
            continue
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        observed = execution.get("observed_artifacts") if isinstance(execution, dict) else None
        pkg_name = str(package.get("package_name") or "").strip()
        sess = str(package.get("session_label") or path.parent.name).strip()
        if package_filter and pkg_name.lower() != package_filter:
            skipped["filtered"] += 1
            continue
        if session_filter and sess != session_filter:
            skipped["filtered"] += 1
            continue
        if not isinstance(observed, list) or not observed:
            skipped["no_observed_artifacts"] += 1
            continue
        parsed = _parse_receipt(path, payload)
        if parsed is None:
            if not any(_member_sha(item) for item in observed if isinstance(item, dict)):
                skipped["missing_hash"] += 1
            else:
                skipped["missing_base"] += 1
            continue
        sets.append(parsed)
    return sets, skipped


def _parse_receipt(path: Path, payload: dict[str, Any]) -> ReceiptSet | None:
    package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
    status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    comparison = payload.get("comparison") if isinstance(payload.get("comparison"), dict) else {}
    observed = execution.get("observed_artifacts") if isinstance(execution, dict) else []
    if not isinstance(observed, list):
        return None

    members: list[ReceiptMember] = []
    for idx, item in enumerate(observed):
        if not isinstance(item, dict):
            continue
        digest = _member_sha(item)
        if not digest:
            return None
        is_base = bool(item.get("is_base")) or str(item.get("split_label") or "").lower() == "base"
        split = str(item.get("split_label") or ("base" if is_base else item.get("file_name") or "")).strip()
        if not split:
            split = "base" if is_base else f"split_{idx}"
        members.append(
            ReceiptMember(
                role="base" if is_base else "split",
                split_name=split.lower(),
                sha256=digest,
                file_name=_maybe_str(item.get("file_name")),
                file_size=_maybe_int(item.get("file_size")),
                source_path=_maybe_str(item.get("observed_source_path")),
                local_relpath=_maybe_str(item.get("local_artifact_path")),
                canonical_relpath=_maybe_str(item.get("canonical_store_path")),
                pull_status=_maybe_str(item.get("pull_outcome")) or "unknown",
                ordinal=idx,
            )
        )
    base_members = [item for item in members if item.role == "base"]
    if len(base_members) != 1:
        return None
    ordered = _ordered_members_for_hash(members)
    artifact_hash = artifact_set_hash_v1([item.sha256 for item in ordered])
    expected = _maybe_int(comparison.get("planned_artifact_count")) or len(members)
    completeness = "complete" if len(members) == expected else "partial"
    if status.get("capture_status") not in {None, "clean"}:
        completeness = "partial"
    return ReceiptSet(
        receipt_path=path,
        session_label=str(package.get("session_label") or path.parent.name),
        device_serial=_maybe_str(package.get("device_serial")),
        snapshot_id=_maybe_int(package.get("snapshot_id")),
        package_name=str(package.get("package_name") or path.stem),
        version_code=_maybe_str(package.get("version_code")),
        version_name=_maybe_str(package.get("version_name")),
        generated_at_utc=_maybe_str(payload.get("generated_at_utc")),
        status=_maybe_str(status.get("capture_status")) or "unknown",
        base_sha256=base_members[0].sha256,
        artifact_set_hash=artifact_hash,
        artifact_set_hash_version="v1",
        completeness_state=completeness,
        members=tuple(members),
    )


def artifact_set_hash_v1(ordered_hashes: list[str]) -> str:
    """Return the current static identity v1 hash for ordered APK members."""

    return sha256(json.dumps(ordered_hashes).encode("utf-8")).hexdigest()


def _ordered_members_for_hash(members: list[ReceiptMember]) -> list[ReceiptMember]:
    base = [item for item in members if item.role == "base"]
    splits = sorted((item for item in members if item.role != "base"), key=lambda item: item.split_name)
    return base + splits


def apply_backfill(sets: list[ReceiptSet], *, receipt_root: Path) -> dict[str, int]:
    from scytaledroid.Database.db_core import db_queries as core_q
    from scytaledroid.Database.db_queries.harvest import install_sets

    for ddl in install_sets._DDL_STATEMENTS:
        core_q.run_sql(ddl, query_name="backfill_apk_sets.ensure_schema")
    core_q.run_sql(
        install_sets.CREATE_V_APK_SET_COVERAGE_V1,
        query_name="backfill_apk_sets.ensure_coverage_view",
    )

    counts = {
        "harvest_sessions_upserted": 0,
        "apk_sets_upserted": 0,
        "apk_set_members_upserted": 0,
        "harvest_observations_upserted": 0,
    }
    for item in sets:
        app = _lookup_app_version(item)
        base_apk_id = _lookup_apk_id(item.base_sha256)
        session_id = _upsert_harvest_session(item, receipt_root=receipt_root)
        counts["harvest_sessions_upserted"] += 1
        apk_set_id = _upsert_apk_set(item, app=app, base_apk_id=base_apk_id)
        counts["apk_sets_upserted"] += 1
        for member in item.members:
            member_apk_id = _lookup_apk_id(member.sha256)
            _upsert_apk_set_member(apk_set_id, member, apk_id=member_apk_id)
            counts["apk_set_members_upserted"] += 1
            _upsert_observation(
                item,
                member,
                harvest_session_id=session_id,
                apk_set_id=apk_set_id,
                apk_id=member_apk_id,
            )
            counts["harvest_observations_upserted"] += 1
    counts.update(_current_db_counts())
    return counts


def _current_db_counts() -> dict[str, int]:
    from scytaledroid.Database.db_core import db_queries as core_q

    counts: dict[str, int] = {}
    for key, table in (
        ("db_harvest_sessions", "harvest_sessions"),
        ("db_apk_sets", "apk_sets"),
        ("db_apk_set_members", "apk_set_members"),
        ("db_harvest_observations", "harvest_apk_observations"),
    ):
        row = core_q.run_sql(
            f"SELECT COUNT(*) AS n FROM {table}",
            fetch="one_dict",
            query_name=f"backfill_apk_sets.count.{table}",
        )
        counts[key] = int((row or {}).get("n") or 0)
    return counts


def _lookup_app_version(item: ReceiptSet) -> dict[str, Any]:
    from scytaledroid.Database.db_core import db_queries as core_q

    row = core_q.run_sql(
        """
        SELECT a.id AS app_id, av.id AS app_version_id
        FROM apps a
        LEFT JOIN app_versions av
          ON av.app_id = a.id
         AND COALESCE(CAST(av.version_code AS CHAR), '') = COALESCE(%s, '')
         AND COALESCE(av.version_name, '') = COALESCE(%s, '')
        WHERE LOWER(TRIM(a.package_name)) = LOWER(TRIM(%s))
        ORDER BY av.id DESC
        LIMIT 1
        """,
        (item.version_code, item.version_name, item.package_name),
        fetch="one_dict",
        query_name="backfill_apk_sets.lookup_app_version",
    )
    return dict(row or {})


def _lookup_apk_id(digest: str) -> int | None:
    from scytaledroid.Database.db_core import db_queries as core_q

    row = core_q.run_sql(
        "SELECT apk_id FROM android_apk_repository WHERE LOWER(TRIM(sha256))=%s LIMIT 1",
        (digest.lower(),),
        fetch="one_dict",
        query_name="backfill_apk_sets.lookup_apk_id",
    )
    return _maybe_int(row.get("apk_id")) if row else None


def _upsert_harvest_session(item: ReceiptSet, *, receipt_root: Path) -> int:
    from scytaledroid.Database.db_core import db_queries as core_q

    return int(
        core_q.run_sql(
            """
            INSERT INTO harvest_sessions (
              session_label, device_serial, inventory_snapshot_id, generated_at_utc,
              status, receipt_root
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              harvest_session_id = LAST_INSERT_ID(harvest_session_id),
              device_serial = COALESCE(VALUES(device_serial), device_serial),
              inventory_snapshot_id = COALESCE(VALUES(inventory_snapshot_id), inventory_snapshot_id),
              generated_at_utc = COALESCE(VALUES(generated_at_utc), generated_at_utc),
              status = VALUES(status),
              receipt_root = VALUES(receipt_root),
              updated_at = CURRENT_TIMESTAMP
            """,
            (
                item.session_label,
                item.device_serial,
                item.snapshot_id,
                _parse_datetime(item.generated_at_utc),
                item.status,
                receipt_root.as_posix(),
            ),
            return_lastrowid=True,
            query_name="backfill_apk_sets.upsert_harvest_session",
        )
    )


def _upsert_apk_set(item: ReceiptSet, *, app: dict[str, Any], base_apk_id: int | None) -> int:
    from scytaledroid.Database.db_core import db_queries as core_q

    return int(
        core_q.run_sql(
            """
            INSERT INTO apk_sets (
              app_id, app_version_id, package_name, version_code, version_name,
              base_apk_id, base_apk_sha256, artifact_set_hash,
              artifact_set_hash_version, member_count, split_count,
              completeness_state, source_kind, first_seen_at, last_seen_at
            ) VALUES (
              %s, %s, %s, %s, %s,
              %s, %s, %s,
              %s, %s, %s,
              %s, 'harvest_receipt', %s, %s
            )
            ON DUPLICATE KEY UPDATE
              apk_set_id = LAST_INSERT_ID(apk_set_id),
              app_id = COALESCE(VALUES(app_id), app_id),
              app_version_id = COALESCE(VALUES(app_version_id), app_version_id),
              package_name = VALUES(package_name),
              version_code = COALESCE(VALUES(version_code), version_code),
              version_name = COALESCE(VALUES(version_name), version_name),
              base_apk_id = COALESCE(VALUES(base_apk_id), base_apk_id),
              base_apk_sha256 = VALUES(base_apk_sha256),
              member_count = GREATEST(member_count, VALUES(member_count)),
              split_count = GREATEST(split_count, VALUES(split_count)),
              completeness_state = VALUES(completeness_state),
              source_kind = 'harvest_receipt',
              first_seen_at = COALESCE(LEAST(first_seen_at, VALUES(first_seen_at)), VALUES(first_seen_at), first_seen_at),
              last_seen_at = COALESCE(GREATEST(last_seen_at, VALUES(last_seen_at)), VALUES(last_seen_at), last_seen_at),
              updated_at = CURRENT_TIMESTAMP
            """,
            (
                app.get("app_id"),
                app.get("app_version_id"),
                item.package_name,
                item.version_code,
                item.version_name,
                base_apk_id,
                item.base_sha256,
                item.artifact_set_hash,
                item.artifact_set_hash_version,
                len(item.members),
                len([m for m in item.members if m.role == "split"]),
                item.completeness_state,
                _parse_datetime(item.generated_at_utc),
                _parse_datetime(item.generated_at_utc),
            ),
            return_lastrowid=True,
            query_name="backfill_apk_sets.upsert_apk_set",
        )
    )


def _upsert_apk_set_member(apk_set_id: int, member: ReceiptMember, *, apk_id: int | None) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q

    core_q.run_sql(
        """
        INSERT INTO apk_set_members (
          apk_set_id, apk_id, role, split_name, sha256, source_path,
          local_relpath, canonical_relpath, member_status, ordinal
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          apk_id = COALESCE(VALUES(apk_id), apk_id),
          source_path = COALESCE(VALUES(source_path), source_path),
          local_relpath = COALESCE(VALUES(local_relpath), local_relpath),
          canonical_relpath = COALESCE(VALUES(canonical_relpath), canonical_relpath),
          member_status = VALUES(member_status),
          ordinal = VALUES(ordinal),
          updated_at = CURRENT_TIMESTAMP
        """,
        (
            apk_set_id,
            apk_id,
            member.role,
            member.split_name,
            member.sha256,
            member.source_path,
            member.local_relpath,
            member.canonical_relpath,
            member.pull_status,
            member.ordinal,
        ),
        query_name="backfill_apk_sets.upsert_member",
    )


def _upsert_observation(
    item: ReceiptSet,
    member: ReceiptMember,
    *,
    harvest_session_id: int,
    apk_set_id: int,
    apk_id: int | None,
) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q

    core_q.run_sql(
        """
        INSERT INTO harvest_apk_observations (
          harvest_session_id, apk_set_id, apk_id, package_name, version_code,
          version_name, role, split_name, sha256, source_path, local_relpath,
          canonical_relpath, pull_status, observed_at_utc
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          apk_set_id = COALESCE(VALUES(apk_set_id), apk_set_id),
          apk_id = COALESCE(VALUES(apk_id), apk_id),
          version_code = COALESCE(VALUES(version_code), version_code),
          version_name = COALESCE(VALUES(version_name), version_name),
          source_path = COALESCE(VALUES(source_path), source_path),
          local_relpath = COALESCE(VALUES(local_relpath), local_relpath),
          canonical_relpath = COALESCE(VALUES(canonical_relpath), canonical_relpath),
          pull_status = VALUES(pull_status),
          observed_at_utc = COALESCE(VALUES(observed_at_utc), observed_at_utc),
          updated_at = CURRENT_TIMESTAMP
        """,
        (
            harvest_session_id,
            apk_set_id,
            apk_id,
            item.package_name,
            item.version_code,
            item.version_name,
            member.role,
            member.split_name,
            member.sha256,
            member.source_path,
            member.local_relpath,
            member.canonical_relpath,
            member.pull_status,
            _parse_datetime(item.generated_at_utc),
        ),
        query_name="backfill_apk_sets.upsert_observation",
    )


def _count_by(items: list[ReceiptSet], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attr))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _member_sha(item: dict[str, Any]) -> str | None:
    digest = str(item.get("sha256") or "").strip().lower()
    if len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest):
        return digest
    return None


def _maybe_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _maybe_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return None


def _print_summary(summary: dict[str, Any]) -> None:
    mode = "APPLY" if summary["apply"] else "DRY-RUN"
    print(f"=== APK install-set receipt backfill ({mode}) ===")
    for key in (
        "receipts_root",
        "receipt_sets_processed",
        "unique_install_sets",
        "unique_member_rows",
        "members",
        "packages",
        "sessions",
    ):
        print(f"  {key}: {summary[key]}")
    print("  completeness:")
    for key, count in sorted(summary["completeness"].items()):
        print(f"    {key}: {count}")
    print("  skipped_receipts:")
    for key, count in sorted(summary["skipped_receipts"].items()):
        print(f"    {key}: {count}")
    for key in (
        "harvest_sessions_upserted",
        "apk_sets_upserted",
        "apk_set_members_upserted",
        "harvest_observations_upserted",
        "db_harvest_sessions",
        "db_apk_sets",
        "db_apk_set_members",
        "db_harvest_observations",
    ):
        if key in summary:
            print(f"  {key}: {summary[key]}")
    if not summary["apply"]:
        print("  note: no DB writes were made. Re-run with --apply to create and populate additive tables.")


if __name__ == "__main__":
    raise SystemExit(main())
