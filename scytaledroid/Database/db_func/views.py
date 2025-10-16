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

    # Create canonical FQN view for detections
    try:
        run_sql(q.CREATE_VW_DETECTED_PERMISSIONS_FQN)
    except Exception:
        pass

    # Create the second view best-effort; ignore failures if the table
    # (static_permission_risk) is not present in this deployment.
    try:
        run_sql(q.CREATE_VW_LATEST_PERMISSION_RISK)
    except Exception:
        pass

    # Convenience view for latest permission audit per package
    try:
        run_sql(q.CREATE_VW_PERMISSION_AUDIT_LATEST)
    except Exception:
        pass

    try:
        run_sql(q.CREATE_VW_STATIC_MODULE_COVERAGE)
    except Exception:
        pass

    try:
        run_sql(q.CREATE_VW_STORAGE_SURFACE_RISK)
    except Exception:
        pass

    try:
        run_sql(q.CREATE_VW_DYNLOAD_HOTSPOTS)
    except Exception:
        pass

    return True


__all__ = ["ensure_views"]
