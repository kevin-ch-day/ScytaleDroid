from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    RunOutcome,
    RunParameters,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.execution.cohort_scan_notes import emit_post_scan_cohort_notes
from scytaledroid.StaticAnalysis.cli.flows import research_cohort as flow
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def _group(
    package_name: str,
    version_code: str,
    *,
    session_stamp: str,
    split_count: int = 0,
) -> ArtifactGroup:
    artifacts = [
        RepositoryArtifact(
            path=Path(f"/tmp/{package_name}-{version_code}-base.apk"),
            display_path=f"{package_name}-{version_code}-base.apk",
            metadata={
                "package_name": package_name,
                "version_code": version_code,
                "version_name": f"{version_code}.0",
                "artifact": "base",
                "split_name": "base",
                "is_split_member": False,
            },
        )
    ]
    for index in range(1, split_count + 1):
        artifacts.append(
            RepositoryArtifact(
                path=Path(f"/tmp/{package_name}-{version_code}-split{index}.apk"),
                display_path=f"{package_name}-{version_code}-split{index}.apk",
                metadata={
                    "package_name": package_name,
                    "version_code": version_code,
                    "version_name": f"{version_code}.0",
                    "artifact": f"split_config.{index}",
                    "split_name": f"split_config.{index}",
                    "is_split_member": True,
                },
            )
        )
    return ArtifactGroup(
        group_key=f"{package_name}:{version_code}",
        package_name=package_name,
        version_display=f"{version_code}.0",
        session_stamp=session_stamp,
        capture_id=f"capture-{version_code}",
        artifacts=tuple(artifacts),
    )


def test_prepare_research_cohort_scope_resolves_newest_harvests(monkeypatch) -> None:
    monkeypatch.setattr(
        flow,
        "fetch_research_cohort",
        lambda _key: {
            "cohort_key": "research_dataset_beta",
            "display_name": "Research Dataset Beta",
            "description": "Expanded paper cohort",
        },
    )
    monkeypatch.setattr(
        flow,
        "fetch_active_research_cohort_members",
        lambda _key: [
            {"package_name": "com.example.alpha"},
            {"package_name": "com.example.beta"},
            {"package_name": "com.example.missing"},
        ],
    )

    groups = (
        _group("com.example.alpha", "1", session_stamp="20260610-alpha", split_count=2),
        _group("com.example.alpha", "2", session_stamp="20260611-alpha", split_count=1),
        _group("com.example.beta", "9", session_stamp="20260612-beta", split_count=0),
    )

    prepared = flow.prepare_research_cohort_scope(groups, "research_dataset_beta")

    assert prepared is not None
    assert prepared.display_name == "Research Dataset Beta"
    assert prepared.package_names == (
        "com.example.alpha",
        "com.example.beta",
        "com.example.missing",
    )
    assert prepared.missing_packages == ("com.example.missing",)
    assert [group.package_name for group in prepared.selection.groups] == [
        "com.example.alpha",
        "com.example.beta",
    ]
    assert prepared.selection.older_captures_excluded == 1
    assert prepared.total_apk_files == 3
    assert prepared.base_apk_count == 2
    assert prepared.split_apk_count == 1
    assert prepared.largest_split_heavy_apps[0] == ("com.example.alpha", "com.example.alpha", 2)


def test_choose_research_cohort_scope_lists_db_backed_cohorts(monkeypatch, capsys) -> None:
    selection = ScopeSelection("research_cohort", "Research Dataset Beta", tuple())

    monkeypatch.setattr(
        flow,
        "list_active_research_cohorts",
        lambda: [
            {
                "cohort_key": "research_dataset_alpha",
                "display_name": "Research Dataset Alpha",
                "active_member_count": 12,
            },
            {
                "cohort_key": "research_dataset_beta",
                "display_name": "Research Dataset Beta",
                "active_member_count": 15,
            },
        ],
    )
    monkeypatch.setattr(flow.prompt_utils, "get_choice", lambda *_a, **_k: "2")
    monkeypatch.setattr(
        flow,
        "prepare_research_cohort_scope",
        lambda _groups, cohort_key: flow.ResearchCohortPreparedSelection(
            cohort_key=cohort_key,
            display_name="Research Dataset Beta",
            description="Expanded paper cohort",
            package_names=("com.example.alpha",),
            missing_packages=tuple(),
            selection=selection,
            total_apk_files=1,
            base_apk_count=1,
            split_apk_count=0,
            largest_split_heavy_apps=tuple(),
        ),
    )
    monkeypatch.setattr(flow, "render_research_cohort_workload", lambda prepared: prepared.selection)

    scoped = flow.choose_research_cohort_scope(tuple())

    out = capsys.readouterr().out
    assert "Research Dataset Alpha" in out
    assert "Research Dataset Beta" in out
    assert scoped is selection


def test_render_research_cohort_workload_uses_research_cohort_wording(monkeypatch, capsys) -> None:
    selection = ScopeSelection("research_cohort", "Research Dataset Beta", tuple())
    prepared = flow.ResearchCohortPreparedSelection(
        cohort_key="research_dataset_beta",
        display_name="Research Dataset Beta",
        description="Expanded paper cohort",
        package_names=("com.example.alpha",),
        missing_packages=tuple(),
        selection=selection,
        total_apk_files=1,
        base_apk_count=1,
        split_apk_count=0,
        largest_split_heavy_apps=tuple(),
    )
    monkeypatch.setattr(flow.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(flow, "_render_profile_selection_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(flow, "_print_prior_profile_session_snapshot", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(flow, "fetch_prior_profile_session_snapshot", lambda *_args, **_kwargs: None)

    flow.render_research_cohort_workload(prepared)

    out = capsys.readouterr().out
    assert "Research cohort: Research Dataset Beta" in out
    assert "Profile: Research Dataset Beta" not in out


def test_emit_post_scan_cohort_notes_reports_split_merge_coverage(capsys) -> None:
    outcome = RunOutcome(
        results=[
            AppRunResult(
                "com.example.one",
                "News",
                discovered_artifacts=3,
                base_string_data={"aggregation_scope": "artifact_merged"},
            ),
            AppRunResult(
                "com.example.two",
                "News",
                discovered_artifacts=2,
                base_string_data={"aggregation_scope": "base_apk_only"},
            ),
        ],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        scope=ScopeSelection(scope="profile", label="Research Dataset Beta", groups=tuple()),
        base_dir=Path("/tmp"),
    )
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Research Dataset Beta",
        verbose_output=False,
        dry_run=False,
    )

    emit_post_scan_cohort_notes(outcome, params)

    out = capsys.readouterr().out
    assert "String rollup summary" in out
    assert "merged=1/2" in out


def test_emit_post_scan_cohort_notes_supports_research_cohort_scope(capsys) -> None:
    outcome = RunOutcome(
        results=[
            AppRunResult(
                "com.example.one",
                "Research Dataset Beta",
                discovered_artifacts=2,
                base_string_data={"aggregation_scope": "artifact_merged"},
            ),
            AppRunResult(
                "com.example.two",
                "Research Dataset Beta",
                discovered_artifacts=2,
                base_string_data={"aggregation_scope": "artifact_merged"},
            ),
        ],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        scope=ScopeSelection(scope="research_cohort", label="Research Dataset Beta", groups=tuple()),
        base_dir=Path("/tmp"),
    )
    params = RunParameters(
        profile="full",
        scope="research_cohort",
        scope_label="Research Dataset Beta",
        verbose_output=False,
        dry_run=False,
    )

    emit_post_scan_cohort_notes(outcome, params)

    out = capsys.readouterr().out
    assert "String rollup summary" in out
    assert "merged=2/2" in out
