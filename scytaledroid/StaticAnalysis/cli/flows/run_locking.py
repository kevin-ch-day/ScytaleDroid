"""Filesystem lock and execution marker helpers for static analysis runs."""

from __future__ import annotations

import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config

from ..core.models import RunParameters


def _static_run_lock_root() -> Path:
    return Path(app_config.DATA_DIR) / "locks"


def _static_run_lock_path() -> Path:
    return _static_run_lock_root() / "static_analysis.lock"


def _read_static_run_lock(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _acquire_static_run_lock(params: RunParameters) -> Path:
    lock_root = _static_run_lock_root()
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = _static_run_lock_path()

    payload = {
        "execution_id": getattr(params, "execution_id", None),
        "session_stamp": params.session_stamp,
        "session_label": params.session_label,
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "started_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }

    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        existing = _read_static_run_lock(lock_path)
        existing_session = existing.get("session_label") or existing.get("session_stamp") or "unknown"
        existing_exec = existing.get("execution_id") or "unknown"
        existing_pid = existing.get("pid") or "unknown"
        raise RuntimeError(
            "Another static analysis run is already active. "
            f"session={existing_session} execution_id={existing_exec} pid={existing_pid}"
        ) from exc

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(lock_path)
        except OSError:
            pass
        raise

    return lock_path


def _release_static_run_lock(lock_path: Path | None) -> None:
    if lock_path is None:
        return

    try:
        if lock_path.exists():
            os.unlink(lock_path)
    except OSError:
        pass


def _write_execution_marker(params: RunParameters) -> None:
    stamp = (params.session_stamp or "").strip()
    if not stamp:
        return

    session_dir = Path(app_config.DATA_DIR) / "sessions" / stamp
    session_dir.mkdir(parents=True, exist_ok=True)

    marker = {
        "execution_id": getattr(params, "execution_id", None),
        "session_stamp": params.session_stamp,
        "session_label": params.session_label or params.session_stamp,
        "canonical_action": params.canonical_action,
        "started_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }

    (session_dir / "execution.json").write_text(
        json.dumps(marker, indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = [
    "_acquire_static_run_lock",
    "_release_static_run_lock",
    "_static_run_lock_path",
    "_static_run_lock_root",
    "_write_execution_marker",
]