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


__all__ = ["delete_dynamic_sessions_by_id", "find_dynamic_db_orphans"]
