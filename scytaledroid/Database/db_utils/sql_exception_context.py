"""Extract errno / SQLSTATE / message from nested DB exceptions (PyMySQL, etc.)."""

from __future__ import annotations

from collections.abc import Iterator


def _walk_exception_chain(exc: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def extract_sql_exception_context(exc: BaseException) -> dict[str, object | None]:
    """
    Best-effort extraction for persistence audit / operator logs.

    PyMySQL OperationalError: (errno, errval) or (errno, errval, sqlstate) depending on version.
    """

    errno: int | None = None
    sqlstate: str | None = None
    message = str(exc)
    for cur in _walk_exception_chain(exc):
        args = getattr(cur, "args", None)
        if isinstance(args, tuple) and args:
            if isinstance(args[0], int):
                errno = int(args[0])
            if len(args) > 1 and isinstance(args[1], str):
                message = args[1]
            if len(args) > 2 and args[2] is not None:
                sqlstate_candidate = str(args[2]).strip()
                if sqlstate_candidate:
                    sqlstate = sqlstate_candidate
    return {
        "errno": errno,
        "sqlstate": sqlstate,
        "message": message,
    }


def infer_failing_table(*, exception_message: str, failure_stage: str | None) -> str | None:
    text = f"{exception_message} {failure_stage or ''}".lower()
    if "risk_scores" in text:
        return "risk_scores"
    if "static_permission_risk_vnext" in text:
        return "static_permission_risk_vnext"
    if "permission_matrix" in text:
        return "static_permission_matrix"
    if "static_findings_summary" in text or "findings_summary" in text:
        return "static_findings_summary"
    if "static_analysis_findings" in text:
        return "static_analysis_findings"
    if "static_string" in text:
        return "static_string_summary_or_samples"
    return None


__all__ = ["extract_sql_exception_context", "infer_failing_table"]
