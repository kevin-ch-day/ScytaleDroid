"""Dynamic DB maintenance utilities (derived, rebuildable).

Paper #2 contract:
- Evidence packs are authoritative.
- The DB is a derived index/cache that may drift (e.g., runs deleted locally).

These utilities help keep the derived DB consistent with the current workspace
without impacting evidence-pack correctness.
"""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_core.db_queries import run_sql, run_sql_write


def _resolve_evidence_path(p: str, *, repo_root: Path) -> Path:
    path = Path(p)
    if path.is_absolute():
        return path
    return (repo_root / path).resolve()


def find_dynamic_db_orphans(*, repo_root: Path) -> list[dict[str, object]]:
    """Return dynamic_sessions rows whose evidence path does not exist on disk.

    Orphan definition (derived DB hygiene):
    - evidence_path missing, or
    - evidence_path directory missing, or
    - evidence_path exists but lacks run_manifest.json
    """
    rows = run_sql(
        """
        SELECT dynamic_run_id, package_name, status, evidence_path
        FROM dynamic_sessions
        WHERE evidence_path IS NOT NULL AND evidence_path != ''
        ORDER BY started_at_utc DESC
        """,
        fetch="all",
    )
    out: list[dict[str, object]] = []
    for rid, pkg, status, ev_path in rows or []:
        evs = str(ev_path or "").strip()
        if not evs:
            out.append(
                {
                    "dynamic_run_id": str(rid),
                    "package_name": str(pkg or ""),
                    "status": str(status or ""),
                    "evidence_path": evs,
                    "reason": "missing_evidence_path",
                }
            )
            continue
        resolved = _resolve_evidence_path(evs, repo_root=repo_root)
        mf = resolved / "run_manifest.json"
        if not resolved.exists():
            out.append(
                {
                    "dynamic_run_id": str(rid),
                    "package_name": str(pkg or ""),
                    "status": str(status or ""),
                    "evidence_path": evs,
                    "reason": "path_missing",
                }
            )
        elif not mf.exists():
            out.append(
                {
                    "dynamic_run_id": str(rid),
                    "package_name": str(pkg or ""),
                    "status": str(status or ""),
                    "evidence_path": evs,
                    "reason": "manifest_missing",
                }
            )
    return out


def delete_dynamic_sessions_by_id(dynamic_run_ids: list[str]) -> int:
    """Delete dynamic_sessions rows for run IDs (cascades to derived tables via FK)."""
    if not dynamic_run_ids:
        return 0
    deleted = 0
    chunk = 100
    for i in range(0, len(dynamic_run_ids), chunk):
        batch = dynamic_run_ids[i : i + chunk]
        placeholders = ",".join(["%s"] * len(batch))
        # run_sql_write() is intentionally void; compute a deterministic "would delete"
        # count first so callers can report what happened.
        count_sql = f"SELECT COUNT(*) FROM dynamic_sessions WHERE dynamic_run_id IN ({placeholders})"
        try:
            row = run_sql(count_sql, tuple(batch), fetch="one")
            batch_count = int(row[0]) if row and row[0] is not None else 0
        except Exception:
            batch_count = 0
        sql = f"DELETE FROM dynamic_sessions WHERE dynamic_run_id IN ({placeholders})"
        run_sql_write(sql, tuple(batch))
        deleted += batch_count
    return deleted


def find_dangling_dynamic_static_links() -> list[dict[str, object]]:
    """Return dynamic-session rows whose static_run_id no longer resolves."""

    rows = run_sql(
        """
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.static_run_id,
          ds.static_handoff_hash,
          ds.started_at_utc,
          ds.evidence_path
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar
          ON sar.id = ds.static_run_id
        WHERE ds.static_run_id IS NOT NULL
          AND sar.id IS NULL
        ORDER BY ds.started_at_utc DESC, ds.dynamic_run_id ASC
        """,
        fetch="all",
    )
    out: list[dict[str, object]] = []
    for dynamic_run_id, package_name, static_run_id, static_handoff_hash, started_at_utc, evidence_path in rows or []:
        out.append(
            {
                "dynamic_run_id": str(dynamic_run_id or ""),
                "package_name": str(package_name or ""),
                "static_run_id": int(static_run_id) if static_run_id is not None else None,
                "static_handoff_hash": str(static_handoff_hash or "") or None,
                "started_at_utc": started_at_utc,
                "evidence_path": str(evidence_path or ""),
            }
        )
    return out


def clear_dangling_dynamic_static_links(dynamic_run_ids: list[str]) -> int:
    """Null out dangling static_run_id values for specific dynamic runs."""

    if not dynamic_run_ids:
        return 0
    repaired = 0
    chunk = 100
    for i in range(0, len(dynamic_run_ids), chunk):
        batch = dynamic_run_ids[i : i + chunk]
        placeholders = ",".join(["%s"] * len(batch))
        count_sql = f"""
            SELECT COUNT(*)
            FROM dynamic_sessions ds
            LEFT JOIN static_analysis_runs sar
              ON sar.id = ds.static_run_id
            WHERE ds.dynamic_run_id IN ({placeholders})
              AND ds.static_run_id IS NOT NULL
              AND sar.id IS NULL
        """
        try:
            row = run_sql(count_sql, tuple(batch), fetch="one")
            batch_count = int(row[0]) if row and row[0] is not None else 0
        except Exception:
            batch_count = 0
        sql = f"""
            UPDATE dynamic_sessions ds
            LEFT JOIN static_analysis_runs sar
              ON sar.id = ds.static_run_id
            SET ds.static_run_id = NULL
            WHERE ds.dynamic_run_id IN ({placeholders})
              AND ds.static_run_id IS NOT NULL
              AND sar.id IS NULL
        """
        run_sql_write(sql, tuple(batch))
        repaired += batch_count
    return repaired


def find_artifact_registry_orphans(*, run_type: str | None = None) -> list[dict[str, object]]:
    """Return artifact_registry rows whose linked run no longer resolves."""

    clauses = ["link_state != 'linked'"]
    params: list[object] = []
    if run_type:
        clauses.append("run_type = %s")
        params.append(str(run_type))
    where_sql = " AND ".join(clauses)
    rows = run_sql(
        f"""
        SELECT
          artifact_id,
          run_id,
          run_type,
          artifact_type,
          origin,
          host_path,
          device_path,
          pull_status,
          link_state,
          created_at_utc
        FROM v_artifact_registry_integrity
        WHERE {where_sql}
        ORDER BY created_at_utc DESC, artifact_id DESC
        """,
        tuple(params),
        fetch="all",
    )
    out: list[dict[str, object]] = []
    for artifact_id, run_id, found_run_type, artifact_type, origin, host_path, device_path, pull_status, link_state, created_at_utc in rows or []:
        out.append(
            {
                "artifact_id": int(artifact_id) if artifact_id is not None else None,
                "run_id": str(run_id or ""),
                "run_type": str(found_run_type or ""),
                "artifact_type": str(artifact_type or ""),
                "origin": str(origin or ""),
                "host_path": str(host_path or ""),
                "device_path": str(device_path or ""),
                "pull_status": str(pull_status or ""),
                "link_state": str(link_state or ""),
                "created_at_utc": created_at_utc,
            }
        )
    return out


def delete_artifact_registry_rows(artifact_ids: list[int]) -> int:
    """Delete artifact_registry rows by primary key."""

    if not artifact_ids:
        return 0
    deleted = 0
    chunk = 200
    for i in range(0, len(artifact_ids), chunk):
        batch = artifact_ids[i : i + chunk]
        placeholders = ",".join(["%s"] * len(batch))
        count_sql = f"SELECT COUNT(*) FROM artifact_registry WHERE artifact_id IN ({placeholders})"
        try:
            row = run_sql(count_sql, tuple(batch), fetch="one")
            batch_count = int(row[0]) if row and row[0] is not None else 0
        except Exception:
            batch_count = 0
        sql = f"DELETE FROM artifact_registry WHERE artifact_id IN ({placeholders})"
        run_sql_write(sql, tuple(batch))
        deleted += batch_count
    return deleted


__all__ = [
    "delete_artifact_registry_rows",
    "clear_dangling_dynamic_static_links",
    "delete_dynamic_sessions_by_id",
    "find_artifact_registry_orphans",
    "find_dangling_dynamic_static_links",
    "find_dynamic_db_orphans",
]
