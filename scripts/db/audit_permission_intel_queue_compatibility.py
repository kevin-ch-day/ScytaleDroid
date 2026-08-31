#!/usr/bin/env python3
"""Read-only Permission Intel queue compatibility report (Scytale vs Erebus apply).

Uses ``SCYTALEDROID_PERMISSION_INTEL_DB_*`` / URL — same resolution as
``scytaledroid.Database.db_core.permission_intel``. **No DML/DDL.**

Mirrors the hardened Erebus queue vocabulary and AOSP promotion guard. Queue
rows may propose review work, but cannot create accepted AOSP platform truth.

Run from repo root::

  PYTHONPATH=. python scripts/db/audit_permission_intel_queue_compatibility.py

Exit codes:
  0 — report printed (PI configured; queue table may be empty)
  1 — import / unexpected error
  2 — Permission Intel not configured or queue table missing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_QUEUE_ACTIVE: tuple[str, ...] = ("queued", "pending")


def _semantic_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "semantic_digest"}


def _bind_semantic_digest(payload: dict[str, Any]) -> dict[str, Any]:
    semantic = json.dumps(
        _semantic_payload(payload),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return {**payload, "semantic_digest": hashlib.sha256(semantic).hexdigest()}


def _write_private_report(path: Path, payload: dict[str, Any]) -> Path:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(_REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("queue compatibility evidence must remain outside the repository")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(resolved.parent, 0o700)
    atomic_write_text(resolved, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    os.chmod(resolved, 0o600)
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary as the last line (stderr for human banner).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write a mode-0600 digest-bound JSON report outside the repository.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
        from scytaledroid.Database.db_func.permissions.queue_apply_compat_check import (
            queue_row_apply_outcome,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (PYTHONPATH=. from repo root): {exc}\n")
        return 1

    if not intel_db.is_permission_intel_configured():
        sys.stderr.write("Permission Intel not configured (set SCYTALEDROID_PERMISSION_INTEL_DB_*).\n")
        return 2

    try:
        target = intel_db.describe_target()
    except Exception as exc:
        sys.stderr.write(f"describe_target failed: {exc}\n")
        return 2

    print("# Permission Intel queue compatibility (read-only)")
    print(f"  database: {target.get('database')} @ {target.get('host')}:{target.get('port')}")
    print(f"  config_source: {target.get('source')}")

    try:
        catalog_gate = intel_db.fetch_v1_catalog_gate()
    except Exception as exc:
        sys.stderr.write(f"Permission Intel v1 catalog gate failed: {exc.__class__.__name__}\n")
        return 2

    if not intel_db.intel_table_exists(intel_db.QUEUE_DICT_TABLE):
        sys.stderr.write(f"Table missing: {intel_db.QUEUE_DICT_TABLE}\n")
        return 2

    def qall(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        rows = intel_db.run_sql(sql, params, fetch="all", dictionary=True, read_only=True)
        return list(rows or [])

    def qscalar(sql: str, params: tuple[Any, ...] = ()) -> int:
        row = intel_db.run_sql(sql, params, fetch="one", read_only=True)
        if not row:
            return 0
        v = row[0] if not isinstance(row, dict) else next(iter(row.values()))
        return int(v or 0)

    in_status = ", ".join(f"'{s}'" for s in _QUEUE_ACTIVE)

    print("\n## 1) Row counts by queue_action, status, source_system, requested_by")
    rows1 = qall(
        f"""
        SELECT
          COALESCE(NULLIF(TRIM(queue_action), ''), '(empty)') AS queue_action,
          COALESCE(NULLIF(TRIM(status), ''), '(empty)') AS status,
          COALESCE(NULLIF(TRIM(source_system), ''), '(empty)') AS source_system,
          COALESCE(NULLIF(TRIM(requested_by), ''), '(empty)') AS requested_by,
          COUNT(*) AS rows_count,
          MIN(created_at_utc) AS earliest_created,
          MAX(created_at_utc) AS latest_created
        FROM {intel_db.QUEUE_DICT_TABLE}
        GROUP BY queue_action, status, source_system, requested_by
        ORDER BY rows_count DESC, queue_action, status
        """
    )
    if not rows1:
        print("  (no rows in queue table)")
    else:
        for r in rows1:
            print(
                f"  {r.get('rows_count'):>6}  action={r.get('queue_action')!r} "
                f"status={r.get('status')!r} source_system={r.get('source_system')!r} "
                f"requested_by={r.get('requested_by')!r}"
            )
            print(f"          earliest={r.get('earliest_created')} latest={r.get('latest_created')}")

    print("\n## 2) Legacy queue_action = 'aosp_promote' (recognized but AOSP promotion remains blocked)")
    legacy_count = qscalar(
        f"""
        SELECT COUNT(*) FROM {intel_db.QUEUE_DICT_TABLE}
        WHERE LOWER(TRIM(queue_action)) = 'aosp_promote'
        """
    )
    print(f"  total rows: {legacy_count}")
    if legacy_count:
        sample = qall(
            f"""
            SELECT queue_id, permission_string, queue_action, status, source_system, requested_by,
                   triage_status, proposed_bucket, proposed_classification, created_at_utc, updated_at_utc
            FROM {intel_db.QUEUE_DICT_TABLE}
            WHERE LOWER(TRIM(queue_action)) = 'aosp_promote'
            ORDER BY created_at_utc DESC
            LIMIT 25
            """
        )
        print("  sample (up to 25):")
        for r in sample:
            print(f"    id={r.get('queue_id')} perm={r.get('permission_string')!r} status={r.get('status')!r} "
                  f"src={r.get('source_system')!r} by={r.get('requested_by')!r} created={r.get('created_at_utc')}")

    print("\n## 3) Recent rows from Scytale / static-analysis provenance")
    recent = qall(
        f"""
        SELECT queue_id, permission_string, queue_action, status, source_system, requested_by,
               triage_status, proposed_bucket, proposed_classification, created_at_utc
        FROM {intel_db.QUEUE_DICT_TABLE}
        WHERE LOWER(COALESCE(source_system, '')) IN ('static-analysis', 'scytaledroid', 'scytaledroid_static')
           OR LOWER(COALESCE(requested_by, '')) IN ('static-analysis', 'scytaledroid', 'scytaledroid_static')
        ORDER BY created_at_utc DESC
        LIMIT 50
        """
    )
    if not recent:
        print("  (no rows matched source_system/requested_by filters)")
    else:
        for r in recent:
            print(
                f"  id={r.get('queue_id')} action={r.get('queue_action')!r} status={r.get('status')!r} "
                f"perm={r.get('permission_string')!r} src={r.get('source_system')!r}"
            )

    print("\n## 4) Active-status rows: apply outcome (Erebus-shaped dry check)")
    active = qall(
        f"""
        SELECT queue_id, permission_string, queue_action, proposed_classification, proposed_bucket,
               triage_status, status, source_system, requested_by
        FROM {intel_db.QUEUE_DICT_TABLE}
        WHERE LOWER(TRIM(status)) IN ({in_status})
        ORDER BY queue_id ASC
        LIMIT 500
        """
    )
    buckets: dict[str, int] = {"apply": 0, "skipped": 0, "rejected": 0, "error": 0}
    unknown_samples: list[dict[str, Any]] = []
    error_samples: list[dict[str, Any]] = []
    null_prop: dict[str, int] = {
        "proposed_classification_null": 0,
        "proposed_bucket_null": 0,
    }
    for r in active:
        pc = r.get("proposed_classification")
        pb = r.get("proposed_bucket")
        if pc is None or (isinstance(pc, str) and not pc.strip()):
            null_prop["proposed_classification_null"] += 1
        if pb is None or (isinstance(pb, str) and not pb.strip()):
            null_prop["proposed_bucket_null"] += 1
        bucket, detail = queue_row_apply_outcome(dict(r))
        buckets[bucket] = buckets.get(bucket, 0) + 1
        if bucket == "error" and detail:
            sample = {
                "queue_id": r.get("queue_id"),
                "permission_string": r.get("permission_string"),
                "queue_action": r.get("queue_action"),
                "detail": detail,
            }
            if len(error_samples) < 15:
                error_samples.append(sample)
            if str(detail).startswith(("unknown_action", "unsupported queue action")):
                if len(unknown_samples) < 15:
                    unknown_samples.append(sample)

    print(f"  scanned active rows (limit 500): {len(active)}")
    print(f"  outcome buckets: {buckets}")
    print(
        "  NULL/empty proposed fields (informational; action vocabulary remains authoritative): "
        f"{null_prop}"
    )
    if error_samples:
        print("  sample blocked/error rows:")
        for s in error_samples:
            print(f"    {s}")
    else:
        print("  no blocked/error rows in sampled active rows")

    print("\n## 5) Blocked AOSP rows with exact accepted-catalog evidence")
    resolution_rows = qall(
        f"""
        SELECT COALESCE(p.authority_class, 'NO_EXACT_MATCH') AS authority_class,
               COUNT(*) AS rows_count
        FROM {intel_db.QUEUE_DICT_TABLE} AS q
        LEFT JOIN android_permission_v1_current_permission AS p
          ON BINARY p.canonical_permission = BINARY q.permission_string
        WHERE LOWER(TRIM(q.status)) IN ({in_status})
          AND LOWER(TRIM(q.queue_action)) IN ('aosp', 'aosp_promote')
        GROUP BY COALESCE(p.authority_class, 'NO_EXACT_MATCH')
        ORDER BY rows_count DESC, authority_class
        """
    )
    resolution_by_authority = {
        str(row.get("authority_class") or "NO_EXACT_MATCH"): int(
            row.get("rows_count") or 0
        )
        for row in resolution_rows
    }
    exact_catalog_matches = sum(
        count
        for authority, count in resolution_by_authority.items()
        if authority != "NO_EXACT_MATCH"
    )
    no_exact_catalog_match = resolution_by_authority.get("NO_EXACT_MATCH", 0)
    print(f"  exact accepted-catalog matches: {exact_catalog_matches}")
    print(f"  no exact accepted-catalog match: {no_exact_catalog_match}")
    print(f"  authority breakdown: {resolution_by_authority}")
    print("  note: matches are resolution candidates only; this report performs no mutation")

    summary = _bind_semantic_digest({
        "report_format": "scytaledroid-permission-queue-compatibility-v2",
        "production_effect": "none",
        "query_mode": "read_only",
        "pi_database": target.get("database"),
        "catalog_release_id": catalog_gate.get("catalog_release_id"),
        "catalog_digest": catalog_gate.get("catalog_digest"),
        "schema_contract_id": catalog_gate.get("schema_contract_id"),
        "schema_contract_version": catalog_gate.get("schema_contract_version"),
        "exhaustive_scope": bool(catalog_gate.get("exhaustive_scope")),
        "legacy_aosp_promote_total": legacy_count,
        "active_scanned": len(active),
        "outcome_buckets": buckets,
        "error_samples": error_samples,
        "unknown_action_samples": unknown_samples,
        "catalog_resolution_candidates": {
            "exact_catalog_matches": exact_catalog_matches,
            "no_exact_catalog_match": no_exact_catalog_match,
            "by_authority": resolution_by_authority,
        },
    })
    if args.output:
        report_path = _write_private_report(args.output, summary)
        print(f"  private report: {report_path}")
    if args.json:
        print("\nJSON_SUMMARY=" + json.dumps(summary, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
