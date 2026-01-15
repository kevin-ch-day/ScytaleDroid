"""Marker helpers for behavior sessions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from scytaledroid.Utils.LoggingUtils import logging_utils as log


def append_marker(session_dir: Path, label: str) -> None:
    markers_path = session_dir / "markers.jsonl"
    markers_path.parent.mkdir(parents=True, exist_ok=True)
    entry: Dict[str, object] = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "label": label,
    }
    with markers_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    log.info(f"Marker added: {label}", category="behavior")
