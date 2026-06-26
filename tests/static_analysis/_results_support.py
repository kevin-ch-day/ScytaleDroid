from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    ArtifactOutcome,
    RunOutcome,
    RunParameters,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.StaticAnalysis.cli.execution import results


def now_utc() -> datetime:
    return datetime.now(UTC)


def make_report(
    *,
    package_name: str = "com.example.app",
    app_label: str = "Example",
    file_path: str = "/tmp/example.apk",
    duration_seconds: float = 0.5,
    providers: list[str] | None = None,
    detector_results: list[Any] | None = None,
    hashes: dict[str, Any] | None = None,
    analysis_version: str = "1.0",
    detector_metrics: dict[str, Any] | None = None,
) -> SimpleNamespace:
    manifest = SimpleNamespace(app_label=app_label, package_name=package_name)
    return SimpleNamespace(
        manifest=manifest,
        exported_components=SimpleNamespace(providers=providers or []),
        detector_results=detector_results or [],
        file_path=file_path,
        metadata={"duration_seconds": duration_seconds},
        hashes=hashes or {},
        analysis_version=analysis_version,
        detector_metrics=detector_metrics or {},
    )


def make_artifact(
    *,
    report: Any,
    tmp_path: Path,
    label: str = "base.apk",
    saved_path: str | None | object = ...,
    duration_seconds: float = 0.5,
    metadata: dict[str, Any] | None = None,
) -> ArtifactOutcome:
    current = now_utc()
    if saved_path is ...:
        saved = str(tmp_path / "report.json")
    else:
        saved = saved_path
    return ArtifactOutcome(
        label=label,
        report=report,
        severity=Counter(),
        duration_seconds=duration_seconds,
        saved_path=saved,
        started_at=current,
        finished_at=current,
        metadata=metadata or {},
    )


def make_app_result(
    *,
    tmp_path: Path,
    package_name: str = "com.example.app",
    app_label: str = "Example",
    static_run_id: int | None = None,
    category: str = "Test",
    report: Any | None = None,
    saved_path: str | None | object = ...,
    version_name: str | None = None,
    version_code: int | None = None,
    base_apk_sha256: str | None = None,
    base_string_data: dict[str, Any] | None = None,
) -> AppRunResult:
    base_report = report or make_report(package_name=package_name, app_label=app_label)
    artifact = make_artifact(report=base_report, tmp_path=tmp_path, saved_path=saved_path)
    return AppRunResult(
        package_name=package_name,
        category=category,
        artifacts=[artifact],
        app_label=app_label,
        static_run_id=static_run_id,
        version_name=version_name,
        version_code=version_code,
        base_apk_sha256=base_apk_sha256,
        base_string_data=base_string_data,
    )


def make_outcome(
    *,
    tmp_path: Path,
    app_results: list[AppRunResult],
    scope: str = "all",
    scope_label: str = "All apps",
    failures: list[str] | None = None,
) -> RunOutcome:
    current = now_utc()
    return RunOutcome(
        results=app_results,
        started_at=current,
        finished_at=current,
        scope=ScopeSelection(scope=scope, label=scope_label, groups=tuple()),
        base_dir=tmp_path,
        failures=failures or [],
    )


def make_params(
    *,
    profile: str = "full",
    scope: str = "all",
    scope_label: str = "All apps",
    session_stamp: str | None = None,
    session_label: str | None = None,
    dry_run: bool = False,
    verbose_output: bool = False,
    persistence_ready: bool = False,
    paper_grade_requested: bool = False,
) -> RunParameters:
    return RunParameters(
        profile=profile,
        scope=scope,
        scope_label=scope_label,
        session_stamp=session_stamp,
        session_label=session_label,
        dry_run=dry_run,
        verbose_output=verbose_output,
        persistence_ready=persistence_ready,
        paper_grade_requested=paper_grade_requested,
    )


def make_run_ctx(*, params: RunParameters) -> StaticRunContext:
    return StaticRunContext(
        run_mode="batch",
        quiet=True,
        batch=True,
        noninteractive=True,
        show_splits=False,
        scan_splits_enabled=True,
        session_stamp=params.session_stamp,
        persistence_ready=params.persistence_ready,
        paper_grade_requested=params.paper_grade_requested,
    )


def patch_results_render_baseline(
    monkeypatch,
    *,
    highlight_stats: dict[str, Any] | None = None,
    output_context: dict[str, Any] | None = None,
    render_app_result=None,
    db_severity_table=False,
) -> None:
    monkeypatch.setattr(
        results,
        "_derive_highlight_stats",
        lambda *_a, **_k: highlight_stats
        or {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0},
    )
    monkeypatch.setattr(results, "_build_permission_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_component_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_build_static_risk_row", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_secret_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_collect_masvs_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_finding_signatures", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_bulk_trend_deltas", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "_apply_display_names", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_post_run_views", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_db_masvs_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_db_severity_table", lambda *_a, **_k: db_severity_table)
    monkeypatch.setattr(results, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(
        results,
        "_collect_static_output_context",
        lambda *_a, **_k: output_context
        or {
            "session_id": "sess-default",
            "device_serial": "n/a",
            "snapshot_id": None,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical",
            "analyzed_apps": 1,
            "planned_artifacts": 1,
            "observed_artifacts": 1,
            "acquisition": {},
        },
    )
    monkeypatch.setattr(
        AppRunResult,
        "base_artifact_outcome",
        lambda self: self.artifacts[0],
        raising=False,
    )
    if render_app_result is None:
        monkeypatch.setattr(
            results,
            "render_app_result",
            lambda *_a, **_k: (
                ["line"],
                {"baseline": {"findings": []}},
                {"High": 0, "Medium": 0, "Low": 0, "Info": 0},
            ),
        )
    else:
        monkeypatch.setattr(results, "render_app_result", render_app_result)
