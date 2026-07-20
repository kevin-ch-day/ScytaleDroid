"""Database lookups used by dynamic plan validation."""

from __future__ import annotations

from scytaledroid.Database.db_core import DatabaseError
from scytaledroid.Database.db_core import db_queries as core_q


def missing_db_fields(row: dict[str, object]) -> list[str]:
    required = ("run_signature", "run_signature_version", "artifact_set_hash", "static_handoff_hash")
    return [req_field for req_field in required if not row.get(req_field)]


def fetch_static_run_row(static_run_id: object | None) -> dict[str, object]:
    if static_run_id is None:
        return {}
    query = """
        SELECT sar.id AS static_run_id,
               sar.run_signature,
               sar.run_signature_version,
               sar.apk_set_id,
               sar.artifact_set_hash,
               sar.static_handoff_hash,
               sar.base_apk_sha256,
               sar.pipeline_version,
               a.package_name
        FROM static_analysis_runs sar
        LEFT JOIN app_versions av ON av.id = sar.app_version_id
        LEFT JOIN apps a ON a.id = av.app_id
        WHERE sar.id=%s
        """
    try:
        row = core_q.run_sql(
            query,
            (static_run_id,),
            fetch="one_dict",
        )
    except DatabaseError as exc:
        if not is_missing_static_handoff_hash_error(exc):
            raise
        row = core_q.run_sql(
            """
            SELECT sar.id AS static_run_id,
                   sar.run_signature,
                   sar.run_signature_version,
                   sar.apk_set_id,
                   sar.artifact_set_hash,
                   sar.base_apk_sha256,
                   sar.pipeline_version,
                   a.package_name
            FROM static_analysis_runs sar
            LEFT JOIN app_versions av ON av.id = sar.app_version_id
            LEFT JOIN apps a ON a.id = av.app_id
            WHERE sar.id=%s
            """,
            (static_run_id,),
            fetch="one_dict",
        )
    if not isinstance(row, dict):
        return {}
    row.setdefault("static_handoff_hash", None)
    return row


def is_missing_static_handoff_hash_error(exc: Exception) -> bool:
    message = str(exc).strip().lower()
    if "static_handoff_hash" not in message:
        return False
    return "no such column" in message or "unknown column" in message


def cross_check_session_link(
    session_stamp: str,
    package_name: str,
    static_run_id: object | None,
) -> str | None:
    row = core_q.run_sql(
        """
        SELECT static_run_id
        FROM static_session_run_links
        WHERE session_stamp=%s AND package_name=%s
        LIMIT 1
        """,
        (session_stamp, package_name),
        fetch="one",
    )
    if not row:
        return None
    try:
        resolved = int(row[0])
        if static_run_id is not None and int(static_run_id) != resolved:
            return f"static_run_id mismatch vs session link (plan={static_run_id} link={resolved})"
    except (TypeError, ValueError):
        return "static_run_id invalid in session link"
    return None
