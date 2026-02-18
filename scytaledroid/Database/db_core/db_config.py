"""db_config.py - Environment-aware database configuration.

Default is a local SQLite file under ``data/db/scytaledroid.sqlite``.
MySQL/MariaDB remains available via DSN (e.g., mysql://user:pass@host:3306/dbname).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from scytaledroid.Config import app_config

_BASE_DIR = Path(__file__).resolve().parents[3]
_DOTENV_DEFAULT = _BASE_DIR / ".env"


def _load_dotenv() -> bool:
    """Lightweight .env loader (no external dependency)."""

    if os.environ.get("SCYTALEDROID_NO_DOTENV") == "1":
        return False
    # Avoid pulling production/dev settings into unit tests.
    if "PYTEST_CURRENT_TEST" in os.environ or any("pytest" in arg for arg in sys.argv[:1]):
        return False
    env_path = Path(os.environ.get("SCYTALEDROID_ENV_FILE") or _DOTENV_DEFAULT)
    if not env_path.exists():
        return False
    loaded_any = False
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
                loaded_any = True
    except Exception:
        # Silent failure to avoid blocking startup if .env unreadable.
        return False
    return loaded_any


def _default_sqlite_path() -> Path:
    base = Path(app_config.DATA_DIR) / "db"
    base.mkdir(parents=True, exist_ok=True)
    return base / "scytaledroid.sqlite"


def _sqlite_allow_write() -> bool:
    raw = os.environ.get("SCYTALEDROID_SQLITE_ALLOW_WRITE", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _validate_db_parts() -> None:
    name = os.environ.get("SCYTALEDROID_DB_NAME")
    if not name:
        return
    user = (os.environ.get("SCYTALEDROID_DB_USER") or "").strip()
    passwd = (os.environ.get("SCYTALEDROID_DB_PASSWD") or "").strip()
    port = os.environ.get("SCYTALEDROID_DB_PORT", "").strip()
    if port and not port.isdigit():
        raise RuntimeError("SCYTALEDROID_DB_PORT must be numeric.")
    if passwd and not user:
        raise RuntimeError("SCYTALEDROID_DB_USER is required when SCYTALEDROID_DB_PASSWD is set.")
    for key in ("SCYTALEDROID_DB_NAME", "SCYTALEDROID_DB_USER", "SCYTALEDROID_DB_PASSWD", "SCYTALEDROID_DB_HOST"):
        value = os.environ.get(key)
        if value and any(ch in value for ch in ("\n", "\r", "\x00")):
            raise RuntimeError(f"{key} contains an invalid control character.")


def _compose_db_url_from_parts() -> str | None:
    _validate_db_parts()
    name = (os.environ.get("SCYTALEDROID_DB_NAME") or "").strip()
    if not name:
        return None
    user = (os.environ.get("SCYTALEDROID_DB_USER") or "").strip()
    passwd = (os.environ.get("SCYTALEDROID_DB_PASSWD") or "").strip()
    host = (os.environ.get("SCYTALEDROID_DB_HOST") or "").strip() or "localhost"
    port = (os.environ.get("SCYTALEDROID_DB_PORT") or "").strip() or "3306"
    scheme = (os.environ.get("SCYTALEDROID_DB_SCHEME") or "mysql").strip().lower()
    if scheme not in {"mysql", "mariadb"}:
        scheme = "mysql"
    safe_user = quote(user, safe="") if user else ""
    safe_passwd = quote(passwd, safe="") if passwd else ""
    auth = safe_user
    if passwd:
        auth = f"{safe_user}:{safe_passwd}" if safe_user else f":{safe_passwd}"
    if auth:
        return f"{scheme}://{auth}@{host}:{port}/{name}"
    return f"{scheme}://{host}:{port}/{name}"


def _load_from_env() -> dict[str, str | int]:
    loaded_dotenv = _load_dotenv()
    # When running tests via pytest, force default SQLite to avoid hitting real DBs.
    if any("pytest" in arg for arg in sys.argv[:1]) or "PYTEST_CURRENT_TEST" in os.environ:
        raw_url = None
    else:
        raw_url = os.environ.get("SCYTALEDROID_DB_URL")
        if raw_url is not None:
            raw_url = raw_url.strip()
        if not raw_url:
            raw_url = _compose_db_url_from_parts()
        if not raw_url and not os.environ.get("SCYTALEDROID_ALLOW_SQLITE"):
            env_path = Path(os.environ.get("SCYTALEDROID_ENV_FILE") or _DOTENV_DEFAULT)
            source = "missing"
            if env_path.exists():
                source = "empty" if loaded_dotenv else "missing_key"
            raise RuntimeError(
                "Database configuration is required for non-test runs. "
                f"({source} in .env). Set SCYTALEDROID_DB_URL or set "
                "SCYTALEDROID_DB_NAME/USER/PASSWD/HOST/PORT, or set "
                "SCYTALEDROID_ALLOW_SQLITE=1 to use the local SQLite fallback."
            )
    if not raw_url:
        # Default: SQLite under data/db/
        sqlite_path = _default_sqlite_path()
        readonly = not _sqlite_allow_write()
        if any("pytest" in arg for arg in sys.argv[:1]) or "PYTEST_CURRENT_TEST" in os.environ:
            readonly = False
        return {
            "engine": "sqlite",
            "database": str(sqlite_path),
            "charset": "utf8",
            "readonly": readonly,
        }

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    if scheme in {"sqlite", "file"}:
        db_path = parsed.path or parsed.netloc
        if not db_path:
            db_path = str(_default_sqlite_path())
        readonly = not _sqlite_allow_write()
        if any("pytest" in arg for arg in sys.argv[:1]) or "PYTEST_CURRENT_TEST" in os.environ:
            readonly = False
        return {
            "engine": "sqlite",
            "database": db_path,
            "charset": "utf8",
            "readonly": readonly,
        }

    if scheme in {"mysql", "mariadb"}:
        try:
            connect_timeout = int((os.environ.get("SCYTALEDROID_DB_CONNECT_TIMEOUT") or "5").strip())
        except Exception:
            connect_timeout = 5
        try:
            read_timeout = int((os.environ.get("SCYTALEDROID_DB_READ_TIMEOUT") or "120").strip())
        except Exception:
            read_timeout = 120
        try:
            write_timeout = int((os.environ.get("SCYTALEDROID_DB_WRITE_TIMEOUT") or "120").strip())
        except Exception:
            write_timeout = 120
        return {
            "engine": "mysql",
            "host": parsed.hostname or "localhost",
            "port": int(parsed.port or 3306),
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            "database": (parsed.path or "").lstrip("/") or "",
            "charset": "utf8mb4",
            "connect_timeout": max(1, connect_timeout),
            "read_timeout": max(5, read_timeout),
            "write_timeout": max(5, write_timeout),
        }

    raise ValueError(f"Unsupported DB scheme in SCYTALEDROID_DB_URL: {scheme}")


DB_CONFIG: dict[str, str | int] = _load_from_env()
DB_CONFIG_SOURCE: str = (
    "env:SCYTALEDROID_DB_URL"
    if os.environ.get("SCYTALEDROID_DB_URL")
    else ("env:SCYTALEDROID_DB_*" if os.environ.get("SCYTALEDROID_DB_NAME") else "default-sqlite")
)

_DEFAULT_DATABASE = DB_CONFIG.get("database", "")
_DEFAULT_ENGINE = DB_CONFIG.get("engine", "sqlite")


def allow_auto_create() -> bool:
    """Allow runtime CREATE TABLE calls when the DB is missing tables."""

    raw = os.environ.get("SCYTALEDROID_DB_AUTO_CREATE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def override_database(database: str | None) -> None:
    """Temporarily override the target database schema/path."""

    global DB_CONFIG
    if database:
        DB_CONFIG["database"] = database
    else:
        DB_CONFIG["database"] = _DEFAULT_DATABASE
        DB_CONFIG["engine"] = _DEFAULT_ENGINE


__all__ = ["DB_CONFIG", "DB_CONFIG_SOURCE", "allow_auto_create", "override_database"]
