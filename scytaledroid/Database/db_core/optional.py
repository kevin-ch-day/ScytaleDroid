"""Explicit optional database access helpers.

This module is the narrow boundary for workflows that are intentionally
filesystem-only when the operational database is disabled.  It does not provide
a no-op database backend; callers that require persistence must use
``require_database`` so disabled or failed database configuration is visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from scytaledroid.Database.db_core import db_config

if TYPE_CHECKING:
    from scytaledroid.Database.db_core.db_engine import DatabaseEngine

DatabaseAvailabilityState = Literal["enabled", "disabled", "connection_failed"]


@dataclass(frozen=True, slots=True)
class DatabaseAvailability:
    """Database availability classification safe for operator output."""

    state: DatabaseAvailabilityState
    message: str
    source: str | None = None

    @property
    def available(self) -> bool:
        return self.state == "enabled"


class DatabaseUnavailableError(RuntimeError):
    """Raised when a DB-required workflow has no usable database."""

    def __init__(self, availability: DatabaseAvailability) -> None:
        self.availability = availability
        super().__init__(availability.message)


def database_availability() -> DatabaseAvailability:
    """Return the configured database availability without opening a connection."""

    if db_config.db_enabled():
        return DatabaseAvailability(
            state="enabled",
            message="database enabled",
            source=getattr(db_config, "DB_CONFIG_SOURCE", None),
        )
    return DatabaseAvailability(
        state="disabled",
        message=(
            "database disabled; configure SCYTALEDROID_DB_URL or "
            "SCYTALEDROID_DB_NAME/USER/PASSWD/HOST/PORT for DB-required workflows"
        ),
        source=getattr(db_config, "DB_CONFIG_SOURCE", None),
    )


def maybe_get_database() -> DatabaseEngine | None:
    """Return a database engine when enabled, otherwise ``None``.

    Connection failures remain explicit and are not converted into filesystem-only
    operation because that would mask a configured but broken persistence path.
    """

    availability = database_availability()
    if availability.state == "disabled":
        return None
    try:
        from scytaledroid.Database.db_core.db_engine import DatabaseEngine

        return DatabaseEngine()
    except Exception as exc:  # noqa: BLE001 - classify external DB boundary
        raise DatabaseUnavailableError(
            DatabaseAvailability(
                state="connection_failed",
                message=f"database connection failed: {type(exc).__name__}",
                source=availability.source,
            )
        ) from exc


def require_database() -> DatabaseEngine:
    """Return a database engine or raise a typed unavailable error."""

    availability = database_availability()
    if availability.state == "disabled":
        raise DatabaseUnavailableError(availability)
    engine = maybe_get_database()
    if engine is None:  # defensive: disabled is handled above
        raise DatabaseUnavailableError(availability)
    return engine
