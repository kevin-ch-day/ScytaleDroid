"""Lightweight smoke test: bootstrap DB, run a dummy static scan, emit a report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _write_dummy_report(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    report = output_dir / "smoke_static_report.md"
    timestamp = datetime.now(timezone.utc).isoformat() + "Z"
    content = f"""# Static Analysis Smoke Report

- Status: success
- Generated: {timestamp}
- Notes: Dummy static scan placeholder (no APK required).

"""
    report.write_text(content, encoding="utf-8")
    log.info(f"Wrote smoke report to {report}", category="application")


def main() -> None:
    bootstrap_database()
    # In lieu of a real static scan, emit a placeholder report to confirm pipeline wiring.
    _write_dummy_report(Path("output") / "smoke")


if __name__ == "__main__":
    main()
