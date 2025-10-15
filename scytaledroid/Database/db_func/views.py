"""Create/refresh convenience views."""

from __future__ import annotations

from ..db_core import run_sql
from ..db_queries import views as q


def ensure_views() -> bool:
    try:
        run_sql(q.CREATE_VW_LATEST_APK_PER_PACKAGE)
        run_sql(q.CREATE_VW_LATEST_PERMISSION_RISK)
        return True
    except Exception:
        return False


__all__ = ["ensure_views"]

