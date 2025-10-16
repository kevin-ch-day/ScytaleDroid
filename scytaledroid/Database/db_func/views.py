"""Create/refresh convenience views."""

from __future__ import annotations

from ..db_core import run_sql
from ..db_queries import views as q


def ensure_views() -> bool:
    """Create reporting views.

    Always creates ``vw_latest_apk_per_package``. Attempts to create
    ``vw_latest_permission_risk`` only when its backing table exists; errors
    from the second view do not fail the whole operation.
    """
    try:
        run_sql(q.CREATE_VW_LATEST_APK_PER_PACKAGE)
    except Exception:
        return False

    # Create the second view best-effort; ignore failures if the table
    # (static_permission_risk) is not present in this deployment.
    try:
        run_sql(q.CREATE_VW_LATEST_PERMISSION_RISK)
    except Exception:
        pass

    return True


__all__ = ["ensure_views"]
