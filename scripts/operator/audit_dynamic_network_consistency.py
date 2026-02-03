#!/usr/bin/env python3
"""Audit PCAP vs netstats consistency for recent dynamic runs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from urllib.parse import urlparse

import mysql.connector

from scytaledroid.DynamicAnalysis.exports import dataset_export


ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = Path(os.environ.get("SCYTALEDROID_ENV_FILE", ROOT_DIR / ".env"))


def _load_env() -> None:
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _db_connect():
    url = os.environ.get("SCYTALEDROID_DB_URL")
    if not url:
        raise SystemExit("SCYTALEDROID_DB_URL not set (add to .env).")
    parsed = urlparse(url)
    if parsed.scheme not in {"mysql", "mariadb"}:
        raise SystemExit(f"Unsupported DB scheme: {parsed.scheme}")
    return mysql.connector.connect(
        user=parsed.username,
        password=parsed.password,
        host=parsed.hostname or "localhost",
        port=parsed.port or 3306,
        database=(parsed.path or "").lstrip("/"),
    )


def _fetchall(cur, sql, params=()):
    cur.execute(sql, params)
    return cur.fetchall()


def _fetch_netstats_totals(cur) -> dict[str, float]:
    rows = _fetchall(
        cur,
        """
        SELECT dynamic_run_id,
               SUM(COALESCE(bytes_in, 0) + COALESCE(bytes_out, 0)) AS netstats_bytes
        FROM dynamic_telemetry_network
        WHERE source = 'netstats'
        GROUP BY dynamic_run_id
        """,
    )
    totals: dict[str, float] = {}
    for row in rows:
        if row and row[0]:
            totals[str(row[0])] = float(row[1] or 0)
    return totals


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit PCAP vs netstats consistency for dynamic runs.")
    ap.add_argument("--limit", type=int, default=25, help="Number of runs to inspect (default: 25)")
    ap.add_argument(
        "--ratio-min",
        type=float,
        default=dataset_export.NETSTATS_PCAP_RATIO_MIN,
        help="Min netstats/pcap ratio (default: export threshold)",
    )
    ap.add_argument(
        "--ratio-max",
        type=float,
        default=dataset_export.NETSTATS_PCAP_RATIO_MAX,
        help="Max netstats/pcap ratio (default: export threshold)",
    )
    ap.add_argument(
        "--missing-max",
        type=float,
        default=dataset_export.NETSTATS_MISSING_RATIO_MAX,
        help="Max netstats missing ratio (default: export threshold)",
    )
    args = ap.parse_args()

    _load_env()
    conn = _db_connect()
    cur = conn.cursor()

    rows = _fetchall(
        cur,
        """
        SELECT dynamic_run_id,
               package_name,
               tier,
               started_at_utc,
               pcap_bytes,
               netstats_rows,
               netstats_missing_rows
        FROM dynamic_sessions
        ORDER BY started_at_utc DESC
        LIMIT %s
        """,
        (args.limit,),
    )
    if not rows:
        print("No dynamic sessions found.")
        return 0

    netstats_totals = _fetch_netstats_totals(cur)
    print("PCAP vs netstats consistency audit")
    print("----------------------------------")
    print(
        f"ratio threshold: {args.ratio_min:.2f}–{args.ratio_max:.2f} | "
        f"missing ratio max: {args.missing_max:.2f}"
    )
    print()

    failures = 0
    for row in rows:
        dynamic_run_id = str(row[0])
        package_name = row[1] or "unknown"
        tier = row[2] or "unknown"
        started_at = row[3] or "unknown"
        pcap_bytes = float(row[4] or 0)
        netstats_rows = float(row[5] or 0)
        netstats_missing = float(row[6] or 0)
        netstats_bytes = float(netstats_totals.get(dynamic_run_id, 0))

        ratio = None
        if pcap_bytes > 0:
            ratio = netstats_bytes / pcap_bytes

        missing_ratio = None
        if (netstats_rows + netstats_missing) > 0:
            missing_ratio = netstats_missing / (netstats_rows + netstats_missing)

        status = "ok"
        if ratio is None:
            status = "no_pcap"
        elif ratio < args.ratio_min or ratio > args.ratio_max:
            status = "ratio_outlier"
        if missing_ratio is not None and missing_ratio > args.missing_max:
            status = "missing_outlier" if status == "ok" else f"{status}+missing"

        if status != "ok":
            failures += 1
        ratio_label = f"{ratio:.3f}" if ratio is not None else "n/a"
        missing_label = f"{missing_ratio:.2f}" if missing_ratio is not None else "n/a"
        print(
            f"{dynamic_run_id} | {package_name} | tier={tier} | "
            f"pcap={int(pcap_bytes)}B | netstats={int(netstats_bytes)}B | "
            f"ratio={ratio_label} | missing={missing_label} | {status} | {started_at}"
        )

    print()
    print(f"Flagged runs: {failures}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
