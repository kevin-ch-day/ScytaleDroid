"""Filesystem lock and execution marker helpers for static analysis runs."""

from __future__ import annotations

import json
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages

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


def _unix_pid_alive(pid: int) -> bool:
    """Best-effort: return True if ``pid`` looks like a running local process."""

    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists under another uid; assume active.
        return True
    except OSError:
        return False
    return True


def _lock_recorded_pid(existing: dict[str, object]) -> int | None:
    raw = existing.get("pid")
    if isinstance(raw, bool):  # JSON cannot, but paranoid for odd payloads.
        return None
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _static_lock_is_reclaimable(lock_path: Path, existing: dict[str, object]) -> bool:
    """True if lock file appears stale so we may unlink and retry."""

    pid = _lock_recorded_pid(existing)
    if pid is None:
        # Corrupt/legacy lock — safer to reclaim than deadlock the operator indefinitely.
        return True
    if sys.platform.startswith("win"):
        # PID liveness probes differ on Windows; do not auto-reclaim here.
        return False
    return not _unix_pid_alive(pid)


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

    for attempt in range(2):
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            existing = _read_static_run_lock(lock_path)
            existing_session = existing.get("session_label") or existing.get("session_stamp") or "unknown"
            existing_exec = existing.get("execution_id") or "unknown"
            recorded_pid = _lock_recorded_pid(existing)
            existing_pid_str = recorded_pid if recorded_pid is not None else existing.get("pid") or "unknown"

            reclaim = _static_lock_is_reclaimable(lock_path, existing)
            if reclaim and attempt == 0:
                try:
                    if recorded_pid is not None:
                        print(
                            status_messages.status(
                                f"Stale static-analysis lock removed (PID {recorded_pid} not running): "
                                f"{lock_path.resolve()}",
                                level="warn",
                            )
                        )
                    else:
                        print(
                            status_messages.status(
                                f"Stale or unreadable static-analysis lock removed: {lock_path.resolve()}",
                                level="warn",
                            )
                        )
                    os.unlink(lock_path)
                    continue
                except OSError:
                    pass

            hint = (
                f"If no scan is running: delete {lock_path.resolve()} "
                f"(same machine; previous session_label may differ from your new session_stamp)."
            )
            raise RuntimeError(
                "Another static analysis run is already active. "
                f"session={existing_session} execution_id={existing_exec} pid={existing_pid_str}. "
                + hint
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

    raise RuntimeError("Unable to acquire static analysis lock after reclaim attempt.")


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