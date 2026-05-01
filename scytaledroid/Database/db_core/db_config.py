"""db_config.py - Environment-aware database configuration.

OSS vNext posture:
- Filesystem artifacts are canonical.
- Database support is optional.
- When enabled, MySQL/MariaDB is required (no SQLite fallback).

Unit tests may still use SQLite as a local backend for isolated execution.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from scytaledroid.Config import app_config

_BASE_DIR = Path(__file__).resolve().parents[3]
_DOTENV_DEFAULT = _BASE_DIR / ".env"
_PRIMARY_DB_ROOT = "SCYTALEDROID_DB"


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


def _env_key(root: str, suffix: str) -> str:
    return f"{root}_{suffix}"


def _env_value(root: str, suffix: str) -> str | None:
    return os.environ.get(_env_key(root, suffix))


def _validate_db_parts(root: str = _PRIMARY_DB_ROOT) -> None:
    name = _env_value(root, "NAME")
    if not name:
        return
    user = (_env_value(root, "USER") or "").strip()
    passwd = (_env_value(root, "PASSWD") or "").strip()
    port = (_env_value(root, "PORT") or "").strip()
    if port and not port.isdigit():
        raise RuntimeError(f"{_env_key(root, 'PORT')} must be numeric.")
    if passwd and not user:
        raise RuntimeError(
            f"{_env_key(root, 'USER')} is required when {_env_key(root, 'PASSWD')} is set."
        )
    for suffix in ("NAME", "USER", "PASSWD", "HOST"):
        key = _env_key(root, suffix)
        value = os.environ.get(key)
        if value and any(ch in value for ch in ("\n", "\r", "\x00")):
            raise RuntimeError(f"{key} contains an invalid control character.")


def _compose_db_url_from_parts(root: str = _PRIMARY_DB_ROOT) -> str | None:
    _validate_db_parts(root)
    name = (_env_value(root, "NAME") or "").strip()
    if not name:
        return None
    user = (_env_value(root, "USER") or "").strip()
    passwd = (_env_value(root, "PASSWD") or "").strip()
    host = (_env_value(root, "HOST") or "").strip() or "localhost"
    port = (_env_value(root, "PORT") or "").strip() or "3306"
    scheme = (_env_value(root, "SCHEME") or "mysql").strip().lower()
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


def resolve_db_config_from_root(root: str) -> tuple[dict[str, str | int] | None, str | None]:
    """Resolve a DB config from a prefixed env namespace, or return ``None``.

    This does not invent a SQLite fallback when the namespace is absent. It is
    intended for optional logical targets such as ``permission_intel`` that may
    fall back to the primary operational DB in compatibility mode.
    """

    _load_dotenv()
    raw_url = _env_value(root, "URL")
    if raw_url is not None:
        raw_url = raw_url.strip()
    if not raw_url:
        raw_url = _compose_db_url_from_parts(root)
    if not raw_url:
        return None, None

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    if scheme in {"sqlite", "file"}:
        raise RuntimeError(
            f"{_env_key(root, 'URL')} uses an unsupported SQLite/file scheme. "
            "Configure a mysql/mariadb DSN instead."
        )

    if scheme in {"mysql", "mariadb"}:
        try:
            connect_timeout = int((_env_value(root, "CONNECT_TIMEOUT") or "5").strip())
        except Exception:
            connect_timeout = 5
        try:
            read_timeout = int((_env_value(root, "READ_TIMEOUT") or "120").strip())
        except Exception:
            read_timeout = 120
        try:
            write_timeout = int((_env_value(root, "WRITE_TIMEOUT") or "120").strip())
        except Exception:
            write_timeout = 120
        source = (
            f"env:{_env_key(root, 'URL')}"
            if _env_value(root, "URL")
            else f"env:{root}_*"
        )
        return (
            {
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
            },
            source,
        )

    raise ValueError(f"Unsupported DB scheme in {_env_key(root, 'URL')}: {scheme}")


def _load_from_env() -> dict[str, str | int]:
    _load_dotenv()
    # When running tests via pytest, force default SQLite to avoid hitting real DBs.
    if any("pytest" in arg for arg in sys.argv[:1]) or "PYTEST_CURRENT_TEST" in os.environ:
        raw_url = None
    else:
        raw_url = os.environ.get("SCYTALEDROID_DB_URL")
        if raw_url is not None:
            raw_url = raw_url.strip()
        if not raw_url:
            raw_url = _compose_db_url_from_parts(_PRIMARY_DB_ROOT)
        if not raw_url:
            # OSS posture: DB is optional. Absence of config means "DB disabled".
            return {
                "engine": "disabled",
                "database": "",
                "charset": "utf8",
                "readonly": 1,
            }
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
        # OSS posture: no SQLite backend when DB is explicitly configured.
        raise RuntimeError(
            "SQLite backend is not supported for OSS vNext. "
            "Remove SCYTALEDROID_DB_URL (to disable DB) or configure a mysql/mariadb DSN."
        )

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
if str(DB_CONFIG.get("engine", "")).lower() == "disabled":
    DB_CONFIG_SOURCE = "disabled"
else:
    DB_CONFIG_SOURCE = (
        f"env:{_env_key(_PRIMARY_DB_ROOT, 'URL')}"
        if os.environ.get(_env_key(_PRIMARY_DB_ROOT, "URL"))
        else (f"env:{_PRIMARY_DB_ROOT}_*" if os.environ.get(_env_key(_PRIMARY_DB_ROOT, "NAME")) else "default-sqlite")
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


def db_enabled() -> bool:
    """Return True when the DB backend is enabled (MySQL/MariaDB)."""

    return str(DB_CONFIG.get("engine", "")).lower() in {"mysql", "mariadb"}

def is_test_env() -> bool:
    """Return True when running under pytest/unit tests.

    SQLite is allowed in tests only. In normal operator runs, DB is either
    disabled or MySQL/MariaDB-backed.
    """

    return ("PYTEST_CURRENT_TEST" in os.environ) or any("pytest" in arg for arg in sys.argv[:1])


__all__ = [
    "DB_CONFIG",
    "DB_CONFIG_SOURCE",
    "allow_auto_create",
    "db_enabled",
    "is_test_env",
    "override_database",
    "resolve_db_config_from_root",
]
