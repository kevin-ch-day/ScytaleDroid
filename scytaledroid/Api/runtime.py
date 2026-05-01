"""Runtime controls for the ScytaleDroid API server."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .service import build_api_app


@dataclass
class ApiRuntimeState:
    running: bool
    host: str
    port: int
    status: str
    detail: str | None = None


_api_thread: threading.Thread | None = None
_api_server: object | None = None
_api_host = "127.0.0.1"
_api_port = 8765
_api_error: str | None = None


def _env_flag(name: str, default: str = "1") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value not in {"0", "false", "no", "off", ""}


def _resolve_host() -> str:
    return os.getenv("SCYTALEDROID_API_HOST", _api_host)


def _resolve_port() -> int:
    raw = os.getenv("SCYTALEDROID_API_PORT", str(_api_port)).strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return _api_port


def _require_api_key_configured() -> str:
    api_key = os.getenv("SCYTALEDROID_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("SCYTALEDROID_API_KEY is required; refusing to start JSON API without authentication.")
    return api_key


def api_status() -> ApiRuntimeState:
    running = _api_server is not None and bool(getattr(_api_server, "started", False))
    detail = _api_error
    return ApiRuntimeState(
        running=running,
        host=_api_host,
        port=_api_port,
        status="running" if running else "stopped",
        detail=detail,
    )


def start_api_server(*, force: bool = False) -> ApiRuntimeState:
    """Start the API server in a background thread."""

    global _api_thread, _api_server, _api_host, _api_port, _api_error

    if not force and _api_server is not None:
        return api_status()

    if not _env_flag("SCYTALEDROID_API_ENABLED", "1"):
        _api_error = "disabled"
        return ApiRuntimeState(
            running=False,
            host=_api_host,
            port=_api_port,
            status="disabled",
            detail="SCYTALEDROID_API_ENABLED is false",
        )
    try:
        _require_api_key_configured()
    except RuntimeError as exc:
        _api_error = str(exc)
        log.error(str(exc), category="api")
        raise

    try:
        import uvicorn  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        _api_error = f"uvicorn unavailable: {exc}"
        log.warning(
            "API server unavailable (uvicorn missing). Install fastapi/uvicorn to enable.",
            category="api",
        )
        return ApiRuntimeState(
            running=False,
            host=_api_host,
            port=_api_port,
            status="unavailable",
            detail="uvicorn not installed",
        )

    try:
        app = build_api_app()
    except Exception as exc:  # pragma: no cover - optional dependency
        _api_error = f"api init failed: {exc}"
        log.warning(
            f"API server unavailable: {exc}",
            category="api",
        )
        return ApiRuntimeState(
            running=False,
            host=_api_host,
            port=_api_port,
            status="unavailable",
            detail=str(exc),
        )

    _api_host = _resolve_host()
    _api_port = _resolve_port()
    _api_error = None
    config = uvicorn.Config(app, host=_api_host, port=_api_port, log_level="warning")
    server = uvicorn.Server(config)
    _api_server = server

    def _run() -> None:
        log.info(
            f"API server starting on {_api_host}:{_api_port}",
            category="api",
        )
        server.run()
        log.info("API server stopped", category="api")

    _api_thread = threading.Thread(target=_run, name="scytaledroid-api", daemon=True)
    _api_thread.start()

    time.sleep(0.1)
    return api_status()


def stop_api_server() -> ApiRuntimeState:
    """Stop the API server if it is running."""

    global _api_thread, _api_server
    if _api_server is None:
        return api_status()

    try:
        _api_server.should_exit = True
    except Exception:  # pragma: no cover - defensive
        pass

    if _api_thread and _api_thread.is_alive():
        _api_thread.join(timeout=2)

    _api_thread = None
    _api_server = None
    return api_status()


__all__ = ["api_status", "start_api_server", "stop_api_server", "ApiRuntimeState"]
