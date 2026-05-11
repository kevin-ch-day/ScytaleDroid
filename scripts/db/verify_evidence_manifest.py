#!/usr/bin/env python3
"""Verify session ``evidence_manifest.json`` (filesystem + optional DB handoff parity).

Checks manifest shape, on-disk files, and sha256 fields where present. With
``--db``, compares handoff JSON file hashes to ``static_analysis_runs.static_handoff_hash``.

From repo root::

  PYTHONPATH=. python scripts/db/verify_evidence_manifest.py --session 20260510-all-full
  PYTHONPATH=. python scripts/db/verify_evidence_manifest.py --path data/sessions/foo/evidence_manifest.json
  PYTHONPATH=. python scripts/db/verify_evidence_manifest.py --session STAMP --db

Exit codes: 0 OK, 1 verification or DB failure, 2 usage / missing file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--session",
        help="Session stamp; reads ``data/sessions/<stamp>/evidence_manifest.json`` (via app_config.DATA_DIR).",
    )
    g.add_argument(
        "--path",
        type=Path,
        help="Explicit path to evidence_manifest.json",
    )
    parser.add_argument(
        "--db",
        action="store_true",
        help="Also compare handoff JSON sha256 on disk to analyst DB ``static_handoff_hash``.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the first issue line (or OK).",
    )
    ns = parser.parse_args(argv)

    try:
        from scytaledroid.Config import app_config
        from scytaledroid.StaticAnalysis.cli.persistence.evidence_manifest_verify import (
            load_evidence_manifest,
            verify_evidence_manifest_payload,
            verify_manifest_handoff_hash_vs_database,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (use repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if ns.path is not None:
        path = ns.path
    else:
        stamp = str(ns.session or "").strip()
        if not stamp:
            sys.stderr.write("Empty --session.\n")
            return 2
        path = Path(app_config.DATA_DIR) / "sessions" / stamp / "evidence_manifest.json"

    if not path.is_file():
        sys.stderr.write(f"No manifest at {path}\n")
        return 1

    try:
        manifest = load_evidence_manifest(path)
    except Exception as exc:
        sys.stderr.write(f"Invalid JSON at {path}: {exc}\n")
        return 1

    issues = verify_evidence_manifest_payload(manifest)
    if ns.db:
        try:
            from scytaledroid.Database.db_core import db_config
            from scytaledroid.Database.db_core import db_queries as core_q

            if not db_config.db_enabled():
                sys.stderr.write("Database disabled; omit --db or configure SCYTALEDROID_DB_*.\n")
                return 1
            issues.extend(verify_manifest_handoff_hash_vs_database(manifest, run_sql=core_q.run_sql))
        except Exception as exc:
            sys.stderr.write(f"DB verification failed: {exc.__class__.__name__}: {exc}\n")
            return 1

    if issues:
        if ns.quiet:
            print(issues[0])
        else:
            print(f"Evidence manifest issues ({len(issues)}):")
            for line in issues:
                print(f"  {line}")
        return 1

    if not ns.quiet:
        print(f"OK: {path}")
    else:
        print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
