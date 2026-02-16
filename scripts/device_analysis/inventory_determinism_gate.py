#!/usr/bin/env python3
"""Run strict inventory determinism comparison between two snapshots."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DeviceAnalysis.inventory.determinism import (
    build_snapshot_payload,
    compare_inventory_payloads,
)
from scytaledroid.Utils.version_utils import get_git_commit


def _configure_db_target(db_target: str) -> None:
    parsed = urlparse(db_target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"mysql", "mariadb", "sqlite", "file"}:
        raise RuntimeError("Unsupported --db-target scheme. Use mysql://... or sqlite:///...")
    os.environ["SCYTALEDROID_DB_URL"] = db_target
    if scheme in {"sqlite", "file"}:
        db_path = parsed.path or parsed.netloc
        if not db_path:
            raise RuntimeError("sqlite --db-target must include a path, e.g. sqlite:///abs/path.db")
        db_config.DB_CONFIG = {
            "engine": "sqlite",
            "database": db_path,
            "charset": "utf8",
            "readonly": False,
        }
        db_config.DB_CONFIG_SOURCE = "cli:--db-target"
        print(f"[DB TARGET] backend=sqlite path={db_path}")
        return

    db_config.DB_CONFIG = {
        "engine": "mysql",
        "host": parsed.hostname or "localhost",
        "port": int(parsed.port or 3306),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "database": (parsed.path or "").lstrip("/"),
        "charset": "utf8mb4",
    }
    db_config.DB_CONFIG_SOURCE = "cli:--db-target"
    print(
        "[DB TARGET] "
        f"backend=mysql host={db_config.DB_CONFIG['host']} "
        f"port={db_config.DB_CONFIG['port']} db={db_config.DB_CONFIG['database']}"
    )


def _latest_two_snapshot_ids(device_serial: str) -> tuple[int, int]:
    rows = core_q.run_sql(
        """
        SELECT snapshot_id
        FROM device_inventory_snapshots
        WHERE device_serial=%s
        ORDER BY snapshot_id DESC
        LIMIT 2
        """,
        (device_serial,),
        fetch="all",
    ) or []
    if len(rows) < 2:
        raise RuntimeError(
            f"Need at least two snapshots for serial={device_serial}; found {len(rows)}."
        )
    left = int(rows[1][0])
    right = int(rows[0][0])
    return left, right


def _load_snapshot(snapshot_id: int) -> dict[str, object]:
    row = core_q.run_sql(
        """
        SELECT
          snapshot_id,
          device_serial,
          package_count,
          package_list_hash,
          package_signature_hash,
          scope_hash,
          captured_at
        FROM device_inventory_snapshots
        WHERE snapshot_id = %s
        """,
        (snapshot_id,),
        fetch="one_dict",
    )
    if not row:
        raise RuntimeError(f"Snapshot not found: {snapshot_id}")
    return dict(row)


def _load_rows(snapshot_id: int) -> list[dict[str, object]]:
    rows = core_q.run_sql(
        """
        SELECT
          package_name,
          version_code,
          app_label,
          version_name,
          installer,
          primary_path,
          split_count,
          extras,
          apk_paths
        FROM device_inventory
        WHERE snapshot_id = %s
        ORDER BY package_name ASC
        """,
        (snapshot_id,),
        fetch="all_dict",
    ) or []
    return [dict(row) for row in rows]


def _resolve_output_path(output: str | None) -> Path:
    if output:
        return Path(output)
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return Path("output") / "audit" / "comparators" / "inventory_guard" / stamp / "diff.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory determinism comparator.")
    parser.add_argument(
        "--db-target",
        required=True,
        help="Explicit DB target DSN (mysql://... or sqlite:///...).",
    )
    parser.add_argument("--device-serial", required=True, help="Device serial to compare.")
    parser.add_argument("--left-snapshot-id", type=int, default=None, help="Left snapshot id.")
    parser.add_argument("--right-snapshot-id", type=int, default=None, help="Right snapshot id.")
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON path. Default: output/audit/comparators/inventory_guard/<stamp>/diff.json",
    )
    args = parser.parse_args(argv)

    _configure_db_target(str(args.db_target))
    if args.left_snapshot_id is None or args.right_snapshot_id is None:
        left_id, right_id = _latest_two_snapshot_ids(str(args.device_serial))
    else:
        left_id, right_id = int(args.left_snapshot_id), int(args.right_snapshot_id)

    left_snapshot = _load_snapshot(left_id)
    right_snapshot = _load_snapshot(right_id)
    if str(left_snapshot.get("device_serial")) != str(args.device_serial):
        raise RuntimeError(f"left snapshot {left_id} does not belong to serial={args.device_serial}")
    if str(right_snapshot.get("device_serial")) != str(args.device_serial):
        raise RuntimeError(f"right snapshot {right_id} does not belong to serial={args.device_serial}")

    left_rows = _load_rows(left_id)
    right_rows = _load_rows(right_id)

    left_payload = build_snapshot_payload(snapshot=left_snapshot, rows=left_rows)
    right_payload = build_snapshot_payload(snapshot=right_snapshot, rows=right_rows)
    compare = compare_inventory_payloads(
        left_payload=left_payload,
        right_payload=right_payload,
        left_meta={
            "run_id": left_id,
            "source": "db:device_inventory",
            "timestamp_utc": str(left_snapshot.get("captured_at") or ""),
        },
        right_meta={
            "run_id": right_id,
            "source": "db:device_inventory",
            "timestamp_utc": str(right_snapshot.get("captured_at") or ""),
        },
        tool_semver=app_config.APP_VERSION,
        git_commit=get_git_commit(),
        compare_type="inventory_guard",
    )

    output_path = _resolve_output_path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(compare.payload, indent=2, sort_keys=True, ensure_ascii=True),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS" if compare.passed else "FAIL",
                "left_snapshot_id": left_id,
                "right_snapshot_id": right_id,
                "diff_count": compare.payload.get("result", {}).get("diff_counts", {}).get("disallowed", 0),
                "output": str(output_path),
            },
            indent=2,
        )
    )
    return 0 if compare.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

