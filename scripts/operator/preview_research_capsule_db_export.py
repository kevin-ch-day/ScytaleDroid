#!/usr/bin/env python3
"""Preview a reviewed, scoped research-capsule DB export without exporting rows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Count rows for a reviewed scoped research-capsule DB export.")
    parser.add_argument("--spec", required=True, help="Scoped DB-export specification JSON.")
    parser.add_argument("--out", default="", help="Optional preview JSON output path.")
    args = parser.parse_args(argv)

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from scytaledroid.Database.db_core.optional import require_database
    from scytaledroid.Publication.research_capsule_ledgers import (
        load_json_object,
        preview_db_export_spec,
    )

    spec = load_json_object(args.spec)
    engine = require_database()

    def row_counter(schema: str, table: str, predicate: str) -> int:
        row = engine.fetch_one(
            f"SELECT COUNT(*) FROM `{schema}`.`{table}` WHERE {predicate}",
            query_name="research_capsule_db_export_preview",
            context={"paper_id": str(spec.get("paper_id") or "")},
        )
        return int((row or [0])[0])

    preview = preview_db_export_spec(spec, row_counter=row_counter)
    print(json.dumps(preview, indent=2, sort_keys=True))
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if preview["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
