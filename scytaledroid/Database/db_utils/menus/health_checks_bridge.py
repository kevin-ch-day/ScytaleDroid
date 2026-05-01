"""Bridge/run-linkage helper queries for DB health checks."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_core import run_sql


def fetch_netstats_missing_summary() -> list[dict[str, object]]:
    rows = run_sql(
        """
        SELECT
          package_name,
          COUNT(*) AS run_count,
          SUM(COALESCE(netstats_missing_rows,0)) AS total_missing,
          MAX(COALESCE(netstats_missing_rows,0)) AS max_missing,
          SUM(COALESCE(netstats_rows,0)) AS total_rows
        FROM dynamic_sessions
        WHERE tier='dataset'
        GROUP BY package_name
        ORDER BY total_missing DESC
        """,
        fetch="all",
        dictionary=True,
    )
    summary: list[dict[str, object]] = []
    for row in rows or []:
        total_missing = float(row.get("total_missing") or 0)
        total_rows = float(row.get("total_rows") or 0)
        missing_pct = None
        if total_rows > 0:
            missing_pct = total_missing / total_rows
        summary.append(
            {
                "package_name": row.get("package_name"),
                "run_count": row.get("run_count"),
                "total_missing": row.get("total_missing"),
                "max_missing": row.get("max_missing"),
                "missing_pct": f"{missing_pct:.1%}" if missing_pct is not None else "n/a",
                "missing_pct_value": missing_pct or 0.0,
            }
        )
    return summary


def fetch_pcap_audit_counts() -> dict[str, int]:
    linked_rows = run_sql(
        """
        SELECT dynamic_run_id, evidence_path, pcap_relpath, pcap_valid
        FROM dynamic_sessions
        WHERE tier='dataset'
          AND pcap_relpath IS NOT NULL
        """,
        fetch="all",
        dictionary=True,
    ) or []
    linked = len(linked_rows)
    exists = 0
    valid = 0
    for row in linked_rows:
        if row.get("pcap_valid") == 1:
            valid += 1
        evidence_path = row.get("evidence_path")
        relpath = row.get("pcap_relpath")
        if not evidence_path or not relpath:
            continue
        try:
            pcap_path = Path(str(evidence_path)) / str(relpath)
            if pcap_path.exists():
                exists += 1
        except Exception:
            continue
    return {"linked": linked, "exists": exists, "valid": valid}


def fetch_network_quality_rollup() -> list[dict[str, object]]:
    rows = run_sql(
        """
        SELECT
          COALESCE(network_signal_quality, 'unknown') AS quality,
          COUNT(*) AS runs
        FROM dynamic_sessions
        WHERE tier='dataset'
        GROUP BY COALESCE(network_signal_quality, 'unknown')
        ORDER BY runs DESC
        """,
        fetch="all",
        dictionary=True,
    ) or []
    return rows
