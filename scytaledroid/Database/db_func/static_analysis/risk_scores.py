"""DB helpers for persisting permission risk scores (per run).

See :mod:`docs.database.permission_analysis_schema` for the column layout
mirrored by :class:`RiskScoreRecord`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Union

from ...db_core import database_session, run_sql
from ...db_queries.static_analysis import risk_scores as queries


@dataclass(slots=True)
class RiskScoreRecord:
    """Typed payload representing a row in ``risk_scores``."""

    package_name: str
    session_stamp: str
    scope_label: str
    risk_score: float
    risk_grade: str
    dangerous: int
    signature: int
    vendor: int
    app_label: str | None = None

    def to_parameters(self) -> dict[str, object]:
        return {
            "package_name": self.package_name,
            "app_label": self.app_label,
            "session_stamp": self.session_stamp,
            "scope_label": self.scope_label,
            "risk_score": float(self.risk_score),
            "risk_grade": self.risk_grade,
            "dangerous": int(self.dangerous),
            "signature": int(self.signature),
            "vendor": int(self.vendor),
        }


RiskRow = Union[RiskScoreRecord, Mapping[str, object]]


def ensure_table() -> bool:
    try:
        run_sql(queries.CREATE_TABLE)
        row = run_sql(
            """
            SELECT CHARACTER_MAXIMUM_LENGTH
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'risk_scores'
              AND column_name = 'session_stamp'
            """,
            fetch="one",
        )
        if row and row[0] is not None and int(row[0]) < 64:
            run_sql("ALTER TABLE risk_scores MODIFY session_stamp VARCHAR(64) NOT NULL")
        return True
    except Exception:
        return False


def table_exists() -> bool:
    try:
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def _normalise_payload(payload: RiskRow) -> MutableMapping[str, object]:
    if isinstance(payload, RiskScoreRecord):
        return payload.to_parameters()
    return dict(payload)


def upsert_risk(payload: RiskRow) -> None:
    run_sql(queries.UPSERT_RISK, _normalise_payload(payload))


def bulk_upsert_risks(rows: Iterable[RiskRow]) -> int:
    count = 0
    with database_session():
        for row in rows:
            try:
                upsert_risk(row)
                count += 1
            except Exception:
                continue
    return count


__all__ = [
    "RiskScoreRecord",
    "ensure_table",
    "table_exists",
    "upsert_risk",
    "bulk_upsert_risks",
]
