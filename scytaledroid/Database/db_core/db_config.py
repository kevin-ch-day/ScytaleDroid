"""db_config.py - Environment-aware database configuration.

Default is a local SQLite file under ``data/db/scytaledroid.sqlite``.
MySQL/MariaDB remains available via DSN (e.g., mysql://user:pass@host:3306/dbname).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Union
from urllib.parse import urlparse

from scytaledroid.Config import app_config

_BASE_DIR = Path(__file__).resolve().parents[3]
_DOTENV_DEFAULT = _BASE_DIR / ".env"


def _load_dotenv() -> None:
    """Lightweight .env loader (no external dependency)."""

    env_path = Path(os.environ.get("SCYTALEDROID_ENV_FILE") or _DOTENV_DEFAULT)
    if not env_path.exists():
        return
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except Exception:
        # Silent failure to avoid blocking startup if .env unreadable.
        return


def _default_sqlite_path() -> Path:
    base = Path(app_config.DATA_DIR) / "db"
    base.mkdir(parents=True, exist_ok=True)
    return base / "scytaledroid.sqlite"


def _load_from_env() -> Dict[str, Union[str, int]]:
    _load_dotenv()
    raw_url = os.environ.get("SCYTALEDROID_DB_URL")
    if not raw_url:
        # Default: SQLite under data/db/
        sqlite_path = _default_sqlite_path()
        return {
            "engine": "sqlite",
            "database": str(sqlite_path),
            "charset": "utf8",
        }

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    if scheme in {"sqlite", "file"}:
        db_path = parsed.path or parsed.netloc
        if not db_path:
            db_path = str(_default_sqlite_path())
        return {
            "engine": "sqlite",
            "database": db_path,
            "charset": "utf8",
        }

    if scheme in {"mysql", "mariadb"}:
        return {
            "engine": "mysql",
            "host": parsed.hostname or "localhost",
            "port": int(parsed.port or 3306),
            "user": parsed.username or "",
            "password": parsed.password or "",
            "database": (parsed.path or "").lstrip("/") or "",
            "charset": "utf8mb4",
        }

    raise ValueError(f"Unsupported DB scheme in SCYTALEDROID_DB_URL: {scheme}")


DB_CONFIG: Dict[str, Union[str, int]] = _load_from_env()
DB_CONFIG_SOURCE: str = "env:SCYTALEDROID_DB_URL" if os.environ.get("SCYTALEDROID_DB_URL") else "default-sqlite"

_DEFAULT_DATABASE = DB_CONFIG.get("database", "")
_DEFAULT_ENGINE = DB_CONFIG.get("engine", "sqlite")


def override_database(database: str | None) -> None:
    """Temporarily override the target database schema/path."""

    global DB_CONFIG
    if database:
        DB_CONFIG["database"] = database
    else:
        DB_CONFIG["database"] = _DEFAULT_DATABASE
        DB_CONFIG["engine"] = _DEFAULT_ENGINE


__all__ = ["DB_CONFIG", "DB_CONFIG_SOURCE", "override_database"]
