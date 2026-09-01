from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation import (
    build_static_completion_reconciliation,
)


def _outcome(*, reports: list[str], final_status: str = "complete") -> RunOutcome:
    app = AppRunResult(
        "com.example.app",
        "Test",
        final_status=final_status,
        static_run_id=1,
        persistence_transaction_state="committed",
    )
    app.artifacts = [SimpleNamespace(report=SimpleNamespace(file_path=path)) for path in reports]
    group = SimpleNamespace(package_name="com.example.app")
    return RunOutcome(
        [app], datetime.now(UTC), datetime.now(UTC),
        ScopeSelection(scope="all", label="All", groups=(group,)), Path("/tmp"), [], [],
    )


def test_reconciliation_accounts_for_frozen_selected_artifacts(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk", "/f/split.apk"])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(display_path="/f/base.apk"), SimpleNamespace(display_path="/f/split.apk")
        ],
    )
    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert receipt["status"] == "COMPLETE_RECONCILED"
    assert receipt["selected_artifacts"] == 2
    assert receipt["unexplained_artifacts"] == 0


def test_reconciliation_matches_repository_display_path_to_resolved_report_path(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk = tmp_path / "library" / "base.apk"
    apk.parent.mkdir()
    apk.write_bytes(b"apk")
    outcome = _outcome(reports=[str(apk.resolve())])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(path=apk, display_path="library/base.apk")
        ],
    )

    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)

    assert receipt["status"] == "COMPLETE_RECONCILED"
    assert receipt["accounted_artifacts"] == 1
    assert receipt["foreign_terminal_artifact_identities"] == []
    assert receipt["unexplained_artifact_identities"] == []


def test_reconciliation_reports_invalid_terminal_path_instead_of_crashing(monkeypatch) -> None:
    outcome = _outcome(reports=["\x00invalid-path"])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [SimpleNamespace(display_path="/f/base.apk")],
    )

    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)

    assert receipt["status"] == "INCONSISTENT"
    assert receipt["accounted_artifacts"] == 0
    assert receipt["foreign_terminal_artifact_identities"]


def test_reconciliation_rejects_missing_duplicate_and_foreign_terminal_artifacts(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk", "/f/base.apk", "/foreign.apk"])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(display_path="/f/base.apk"), SimpleNamespace(display_path="/f/split.apk")
        ],
    )
    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert receipt["status"] == "INCONSISTENT"
    assert receipt["accounted_artifacts"] == 1
    assert receipt["unexplained_artifacts"] == 1
    assert receipt["duplicate_terminal_artifact_identities"]
    assert receipt["foreign_terminal_artifact_identities"]


def test_reconciliation_uses_frozen_scope_not_current_library(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/frozen.apk"])
    calls: list[object] = []

    def _selected(group, *, scan_splits):
        calls.append(group)
        return [SimpleNamespace(display_path="/f/frozen.apk")]

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts", _selected
    )
    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert receipt["selection_source"] == "frozen_outcome_scope"
    assert calls == list(outcome.scope.groups)


def test_selection_digest_is_order_independent_and_changes_with_hash(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/a.apk", "/f/b.apk"])
    artifacts = [
        SimpleNamespace(display_path="/f/a.apk", sha256="a" * 64, artifact_label="base"),
        SimpleNamespace(display_path="/f/b.apk", sha256="b" * 64, artifact_label="split_config.en"),
    ]
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: artifacts,
    )
    first = build_static_completion_reconciliation(outcome, scan_splits=True)
    artifacts.reverse()
    second = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert first["selection_artifact_manifest_sha256"] == second["selection_artifact_manifest_sha256"]
    artifacts[0].sha256 = "c" * 64
    third = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert third["selection_artifact_manifest_sha256"] != first["selection_artifact_manifest_sha256"]


def test_missing_artifact_is_incomplete_but_identity_substitution_is_inconsistent(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/a.apk", "/f/b.apk"])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(display_path="/f/a.apk"), SimpleNamespace(display_path="/f/b.apk"), SimpleNamespace(display_path="/f/c.apk")
        ],
    )
    assert build_static_completion_reconciliation(outcome, scan_splits=True)["status"] == "INCOMPLETE"
    outcome.results[0].artifacts[-1].report.file_path = "/f/x.apk"
    assert build_static_completion_reconciliation(outcome, scan_splits=True)["status"] == "INCONSISTENT"


def test_reconciliation_does_not_require_canonical_row_when_persistence_is_disabled(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk"])
    outcome.results[0].static_run_id = None
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [SimpleNamespace(display_path="/f/base.apk")],
    )
    receipt = build_static_completion_reconciliation(
        outcome,
        scan_splits=True,
        require_canonical_persistence=False,
    )
    assert receipt["status"] == "COMPLETE_RECONCILED"
    assert receipt["canonical_persistence_required"] is False
    assert receipt["missing_canonical_package_rows"] == []


def test_reconciliation_rejects_empty_or_duplicate_frozen_selection(monkeypatch) -> None:
    outcome = _outcome(reports=[])
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [],
    )
    empty = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert empty["status"] == "INCOMPLETE"
    assert empty["empty_selection"] is True

    duplicate = SimpleNamespace(display_path="/f/base.apk")
    outcome.results[0].artifacts = [SimpleNamespace(report=SimpleNamespace(file_path="/f/base.apk"))]
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [duplicate, duplicate],
    )
    repeated = build_static_completion_reconciliation(outcome, scan_splits=True)
    assert repeated["status"] == "INCONSISTENT"
    assert repeated["duplicate_selected_artifact_identities"]


def test_reconciliation_rejects_terminal_content_hash_substitution(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk"])
    outcome.results[0].artifacts[0].report.hashes = {"sha256": "b" * 64}
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(display_path="/f/base.apk", sha256="a" * 64)
        ],
    )

    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)

    assert receipt["status"] == "INCONSISTENT"
    assert receipt["content_verified_artifacts"] == 0
    assert receipt["content_hash_mismatches"]


def test_reconciliation_requires_terminal_hash_and_committed_canonical_row(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk"])
    outcome.results[0].persistence_transaction_state = "rolled_back"
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [
            SimpleNamespace(display_path="/f/base.apk", sha256="a" * 64)
        ],
    )

    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)

    assert receipt["status"] == "INCOMPLETE"
    assert receipt["missing_terminal_content_hashes"]
    assert receipt["uncommitted_canonical_package_rows"] == ["com.example.app"]


def test_reconciliation_surfaces_canonical_finalization_failure(monkeypatch) -> None:
    outcome = _outcome(reports=["/f/base.apk"])
    outcome.canonical_failed = True
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.completion_reconciliation.select_group_artifacts",
        lambda _group, *, scan_splits: [SimpleNamespace(display_path="/f/base.apk")],
    )

    receipt = build_static_completion_reconciliation(outcome, scan_splits=True)

    assert receipt["status"] == "INCOMPLETE"
    assert receipt["canonical_finalization_failed"] is True
