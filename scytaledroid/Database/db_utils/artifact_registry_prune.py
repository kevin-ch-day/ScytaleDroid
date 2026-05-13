"""Targeted ``artifact_registry`` prune: old dangling rows only (ledger cleanup).

Deletes **only** ``artifact_registry`` rows — never host files. Selection uses
``v_artifact_registry_integrity`` so ``link_state = 'linked'`` rows (valid SAR /
``dynamic_sessions`` joins) are never selected.

See ``docs/maintenance/artifact_registry_cleanup_track.md`` for operator policy.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_STEM_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def effective_cutoff_days(*, min_age_days: int, cooling_off_days: int) -> int:
    """Rows must be older than ``max(min_age_days, cooling_off_days)`` days (UTC)."""

    ma = max(1, int(min_age_days))
    co = max(1, int(cooling_off_days))
    return max(ma, co)


def _sanitize_receipt_stem(stem: str) -> str:
    s = str(stem or "").strip()
    if not s:
        s = "artifact_registry_prune"
    return _STEM_SAFE.sub("_", s)[:200]


def count_artifact_registry_rows(run_sql: Callable[..., Any]) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS c FROM artifact_registry",
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_prune.total_count",
    )
    if isinstance(row, dict):
        return int(row.get("c") or 0)
    if row and row[0] is not None:
        return int(row[0])
    return 0


def select_prune_candidate_ids(
    run_sql: Callable[..., Any],
    *,
    cutoff_days: int,
    run_type_filter: str | None,
    include_null_created_at: bool,
    limit: int,
) -> list[int]:
    """Return artifact_id list (deterministic order) for rows to prune."""

    cd = max(1, int(cutoff_days))
    clauses: list[str] = ["v.link_state <> %s"]
    params: list[Any] = ["linked"]

    if run_type_filter in {"static", "dynamic"}:
        clauses.append("v.run_type = %s")
        params.append(run_type_filter)
    if include_null_created_at:
        clauses.append(
            "(v.created_at_utc IS NULL OR v.created_at_utc < (UTC_TIMESTAMP() - INTERVAL %s DAY))"
        )
        params.append(cd)
    else:
        clauses.append("v.created_at_utc IS NOT NULL")
        clauses.append("v.created_at_utc < (UTC_TIMESTAMP() - INTERVAL %s DAY)")
        params.append(cd)

    where_sql = " AND ".join(clauses)
    limit_sql = ""
    lim = int(limit)
    if lim > 0:
        limit_sql = " LIMIT %s"
        params.append(lim)

    sql = f"""
        SELECT v.artifact_id
        FROM v_artifact_registry_integrity v
        WHERE {where_sql}
        ORDER BY v.created_at_utc ASC, v.artifact_id ASC
        {limit_sql}
    """
    rows = run_sql(
        sql.strip(),
        tuple(params),
        fetch="all",
        dictionary=True,
        query_name="artifact_registry_prune.select_ids",
    ) or []
    out: list[int] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        aid = r.get("artifact_id")
        if aid is not None:
            out.append(int(aid))
    return out


def fetch_artifact_rows_for_receipt(
    run_sql: Callable[..., Any],
    artifact_ids: Sequence[int],
    *,
    chunk_size: int = 400,
) -> list[dict[str, Any]]:
    """Full row payloads + ``link_state`` from the integrity view."""

    if not artifact_ids:
        return []
    rows_out: list[dict[str, Any]] = []
    for i in range(0, len(artifact_ids), chunk_size):
        chunk = list(artifact_ids[i : i + chunk_size])
        ph = ",".join(["%s"] * len(chunk))
        sql = f"""
            SELECT
              ar.artifact_id,
              ar.run_id,
              ar.run_type,
              ar.artifact_type,
              ar.origin,
              ar.device_path,
              ar.host_path,
              ar.pull_status,
              ar.sha256,
              ar.size_bytes,
              ar.created_at_utc,
              ar.pulled_at_utc,
              ar.status_reason,
              ar.meta_json,
              v.link_state
            FROM artifact_registry ar
            INNER JOIN v_artifact_registry_integrity v
              ON v.artifact_id = ar.artifact_id
            WHERE ar.artifact_id IN ({ph})
            ORDER BY ar.artifact_id ASC
        """
        part = run_sql(
            sql.strip(),
            tuple(chunk),
            fetch="all",
            dictionary=True,
            query_name="artifact_registry_prune.export_rows",
        ) or []
        for r in part:
            if isinstance(r, dict):
                rows_out.append(dict(r))
    return rows_out


def _write_json_receipt(path: Path, *, meta: Mapping[str, Any], rows: list[dict[str, Any]]) -> None:
    """Stable envelope so receipts are not mistaken for bare row arrays."""

    payload = {
        "format": "scytaledroid.artifact_registry_prune_receipt.v1",
        "meta": dict(meta),
        "artifact_rows": rows,
    }
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    keys: list[str] = sorted({k for r in rows for k in r})
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            flat = {k: ("" if r.get(k) is None else str(r[k])) for k in keys}
            w.writerow(flat)


def _write_sql_stub(path: Path, *, artifact_ids: list[int], meta: Mapping[str, Any]) -> None:
    lines: list[str] = [
        "-- ScytaleDroid artifact_registry prune receipt (audit only; not executed by tool)",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- cutoff_days: {meta.get('cutoff_days')}",
        f"-- run_type_filter: {meta.get('run_type_filter')}",
        f"-- include_null_created_at: {meta.get('include_null_created_at')}",
        f"-- candidate_count: {meta.get('candidate_count')}",
        "-- Companion .json uses format scytaledroid.artifact_registry_prune_receipt.v1 (meta + artifact_rows).",
        "-- Never deletes host files; registry rows are derived from rerunnable inputs.",
        "",
    ]
    chunk = 200
    for i in range(0, len(artifact_ids), chunk):
        batch = artifact_ids[i : i + chunk]
        ids_sql = ",".join(str(x) for x in batch)
        lines.append(f"-- DELETE FROM artifact_registry WHERE artifact_id IN ({ids_sql});")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_prune_receipt_bundle(
    receipt_dir: Path,
    *,
    stem: str,
    rows: list[dict[str, Any]],
    artifact_ids: list[int],
    meta: Mapping[str, Any],
    formats: set[str],
) -> dict[str, str]:
    """Write json/csv/sql files; returns map format -> absolute path.

    JSON is ``scytaledroid.artifact_registry_prune_receipt.v1`` (``meta`` + ``artifact_rows``).
    """

    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    written: dict[str, str] = {}
    if "json" in formats:
        p = receipt_dir / f"{base}.json"
        _write_json_receipt(p, meta=meta, rows=rows)
        written["json"] = str(p.resolve())
    if "csv" in formats:
        p = receipt_dir / f"{base}.csv"
        _write_csv(p, rows)
        written["csv"] = str(p.resolve())
    if "sql" in formats:
        p = receipt_dir / f"{base}.sql"
        _write_sql_stub(p, artifact_ids=artifact_ids, meta=meta)
        written["sql"] = str(p.resolve())
    return written


def delete_artifact_registry_ids(
    run_sql_rowcount: Callable[..., int],
    artifact_ids: Sequence[int],
    *,
    chunk_size: int = 200,
) -> int:
    """``DELETE FROM artifact_registry`` in batches; returns rows removed."""

    if not artifact_ids:
        return 0
    deleted = 0
    cs = max(1, int(chunk_size))
    for i in range(0, len(artifact_ids), cs):
        batch = list(artifact_ids[i : i + cs])
        ph = ",".join(["%s"] * len(batch))
        sql = f"DELETE FROM artifact_registry WHERE artifact_id IN ({ph})"
        deleted += int(
            run_sql_rowcount(
                sql,
                tuple(batch),
                query_name="artifact_registry_prune.delete_batch",
            )
        )
    return deleted


@dataclass(frozen=True)
class PruneOperationResult:
    total_rows_before: int
    candidate_count: int
    cutoff_days: int
    receipt_paths: dict[str, str] | None
    deleted_count: int
    total_rows_after: int | None
    dry_run: bool
    sample_artifact_ids: tuple[int, ...] = ()


def run_prune_dangling_artifact_registry(
    run_sql: Callable[..., Any],
    run_sql_rowcount: Callable[..., int],
    *,
    min_age_days: int = 90,
    cooling_off_days: int = 7,
    run_type_filter: str | None = None,
    include_null_created_at: bool = False,
    limit: int = 0,
    receipt_dir: Path | None = None,
    receipt_stem: str | None = None,
    receipt_formats: set[str] | None = None,
    apply: bool = False,
    sample_id_limit: int = 0,
) -> PruneOperationResult:
    """Dry-run lists candidates; ``apply`` deletes after optional receipt write."""

    cutoff = effective_cutoff_days(min_age_days=min_age_days, cooling_off_days=cooling_off_days)
    total_before = count_artifact_registry_rows(run_sql)
    ids = select_prune_candidate_ids(
        run_sql,
        cutoff_days=cutoff,
        run_type_filter=run_type_filter,
        include_null_created_at=include_null_created_at,
        limit=limit,
    )
    lim_sample = max(0, min(int(sample_id_limit), 5000))
    sample_ids = tuple(ids[:lim_sample]) if lim_sample else ()
    if apply and ids and receipt_dir is None:
        raise ValueError("receipt_dir is required when apply=True and candidate rows exist")

    fmts = receipt_formats or {"json", "csv", "sql"}
    receipt_paths: dict[str, str] | None = None
    deleted = 0
    total_after: int | None = None

    if ids and receipt_dir is not None:
        rows = fetch_artifact_rows_for_receipt(run_sql, ids)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = receipt_stem or f"artifact_registry_prune_{stamp}"
        meta = {
            "generated_utc": stamp,
            "cutoff_days": cutoff,
            "min_age_days": int(min_age_days),
            "cooling_off_days": int(cooling_off_days),
            "run_type_filter": run_type_filter or "all",
            "include_null_created_at": include_null_created_at,
            "limit": int(limit),
            "apply": bool(apply),
            "receipt_formats": sorted(fmts),
            "candidate_count": len(ids),
        }
        receipt_paths = write_prune_receipt_bundle(
            receipt_dir,
            stem=stem,
            rows=rows,
            artifact_ids=ids,
            meta=meta,
            formats=fmts,
        )

    if apply and ids:
        deleted = delete_artifact_registry_ids(run_sql_rowcount, ids)
        total_after = count_artifact_registry_rows(run_sql)

    return PruneOperationResult(
        total_rows_before=total_before,
        candidate_count=len(ids),
        cutoff_days=cutoff,
        receipt_paths=receipt_paths,
        deleted_count=deleted,
        total_rows_after=total_after,
        dry_run=not apply,
        sample_artifact_ids=sample_ids,
    )


__all__ = [
    "PruneOperationResult",
    "count_artifact_registry_rows",
    "delete_artifact_registry_ids",
    "effective_cutoff_days",
    "fetch_artifact_rows_for_receipt",
    "run_prune_dangling_artifact_registry",
    "select_prune_candidate_ids",
    "write_prune_receipt_bundle",
]
