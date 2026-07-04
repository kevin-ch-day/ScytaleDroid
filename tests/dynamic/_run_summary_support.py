from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult


def blocked_result(tmp_path) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name="com.example.app",
        duration_seconds=30,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="blocked",
        notes="Dynamic execution blocked by plan validation.",
        errors=["fallback blocker", "secondary blocker"],
        dynamic_run_id="run-123",
        evidence_path=str(tmp_path),
    )
