"""Core database primitives and execution helpers."""

from .db_engine import (
    DatabaseEngine,
    DatabaseError,
    IntegrityDbError,
    ParamStyleError,
    TransientDbError,
    connect,
    detect_placeholder_style,
    sanity_probe,
)
from .db_queries import run_sql, run_sql_many
from .session import database_session

__all__ = [
    "DatabaseEngine",
    "DatabaseError",
    "IntegrityDbError",
    "ParamStyleError",
    "TransientDbError",
    "connect",
    "database_session",
    "detect_placeholder_style",
    "run_sql",
    "run_sql_many",
    "sanity_probe",
]
