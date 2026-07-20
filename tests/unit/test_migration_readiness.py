from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Workspace.migration_readiness import (
    build_migration_readiness_report,
    render_migration_readiness_report,
)


@dataclass
class _Incomplete:
    total_runs: int
    pre_capture_runs: tuple[Path, ...]
    pcap_artifact_runs: tuple[Path, ...]


@dataclass
class _Mercury:
    mountpoint_mounted: bool = True
    user_media_mounted: bool = False
    mountpoint: Path = Path("/mnt/MERCURY_DATA_V2")
    compatibility_alias_exists: bool = True


def _repo(tmp_path: Path) -> Path:
    for name in (".git", "data/store/apk", "output/paper/freeze", "logs"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / ".env").write_text("SCYTALEDROID_DB_PASSWD=secret\n", encoding="utf-8")
    (tmp_path / ".env").chmod(0o600)
    (tmp_path / "data/store/apk/session_run_health.json").write_text(
        json.dumps({"session_stamp": "session", "workflow_completion_status": "complete", "db_persistence_status": "ok"}),
        encoding="utf-8",
    )
    (tmp_path / "output/paper/freeze/summary.json").write_text(
        json.dumps({"apps_total": 15, "ready": 13, "needs_baseline": 0, "needs_interactive": 2, "evidence_tier_summary": {"paper_usable": 15}}),
        encoding="utf-8",
    )
    (tmp_path / "output/paper/freeze/paper_freeze_manifest.json").write_text("{}", encoding="utf-8")
    return tmp_path


def _report(root: Path, *, incomplete: _Incomplete | None = None):
    return build_migration_readiness_report(
        root,
        size_resolver=lambda path: 4096 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True, "upstream": "origin/main", "ahead": 0, "behind": 0},
        database_probe=lambda: {"configured": True, "reachable": True, "database": "core", "detail": "read probe passed"},
        cold_store_loader=lambda _root: {"links": 0, "missing": 0, "bytes": 0, "roots": []},
        alias_loader=lambda _root: {
            "available": True,
            "canonical_runs": 0,
            "valid": 0,
            "missing": 0,
            "stale": 0,
            "conflicts": 0,
            "orphaned": 0,
        },
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "governance_ok": True, "detail": "ready"},
        definer_probe=lambda: {
            "core": {"available": True, "definers": ["root@localhost"]},
            "permission_intel": {"available": True, "definers": ["erebus_app@localhost"]},
        },
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: incomplete or _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
    )


def test_migration_readiness_reports_transfer_surfaces_without_env_values(tmp_path: Path) -> None:
    report = _report(_repo(tmp_path))

    assert report["overall_status"] == "READY"
    assert [row["name"] for row in report["transfer_roots"]] == ["data", "output", "logs"]
    assert report["paper_freeze"]["paper_usable"] == 15
    assert report["environment"]["present"] is True
    assert "secret" not in json.dumps(report)
    assert "Database: reachable" in render_migration_readiness_report(report)
    assert "Latest static session: session | workflow=complete" in render_migration_readiness_report(report)
    assert "Filesystem transfer estimate" in render_migration_readiness_report(report)
    assert "Rsync command templates" in render_migration_readiness_report(report)


def test_migration_readiness_blocks_missing_corpus_or_database(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "logs").rmdir()
    report = build_migration_readiness_report(
        root,
        size_resolver=lambda path: 1 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True},
        database_probe=lambda: {"configured": True, "reachable": False, "detail": "read probe failed: ConnectionError"},
        cold_store_loader=lambda _root: {"links": 0, "missing": 0, "bytes": 0, "roots": []},
        alias_loader=lambda _root: {"available": True},
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "detail": "ready"},
        definer_probe=lambda: {"core": {"available": True, "definers": []}},
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
    )

    assert report["overall_status"] == "BLOCKED"
    assert any("logs" in detail for detail in report["blockers"])
    assert any("ConnectionError" in detail for detail in report["blockers"])


def test_migration_readiness_preserves_incomplete_pcap_as_warning(tmp_path: Path) -> None:
    report = _report(_repo(tmp_path), incomplete=_Incomplete(1, (), (Path("run-with-pcap"),)))

    assert report["overall_status"] == "READY_WITH_WARNINGS"
    evidence_check = next(check for check in report["checks"] if check["name"] == "incomplete dynamic evidence")
    assert evidence_check["status"] == "warning"
    assert "preserve and classify" in evidence_check["detail"]


def test_migration_readiness_blocks_insufficient_destination_capacity(tmp_path: Path) -> None:
    root = _repo(tmp_path / "source")
    destination = tmp_path / "destination"
    destination.mkdir()
    report = build_migration_readiness_report(
        root,
        size_resolver=lambda path: 10**20 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True},
        database_probe=lambda: {"configured": True, "reachable": True, "detail": "read probe passed"},
        cold_store_loader=lambda _root: {"links": 0, "missing": 0, "bytes": 0, "roots": []},
        alias_loader=lambda _root: {"available": True},
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "detail": "ready"},
        definer_probe=lambda: {"core": {"available": True, "definers": []}},
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
        destination_root=destination,
    )

    capacity_check = next(check for check in report["checks"] if check["name"] == "destination capacity")
    assert capacity_check["status"] == "blocker"
    assert report["destination"]["capacity_sufficient"] is False
    assert report["overall_status"] == "BLOCKED"


def test_migration_readiness_warns_when_git_is_not_synchronized(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    report = build_migration_readiness_report(
        root,
        size_resolver=lambda path: 1 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True, "ahead": 1, "behind": 0},
        database_probe=lambda: {"configured": True, "reachable": True, "detail": "read probe passed"},
        cold_store_loader=lambda _root: {"links": 0, "missing": 0, "bytes": 0, "roots": []},
        alias_loader=lambda _root: {"available": True},
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "detail": "ready"},
        definer_probe=lambda: {"core": {"available": True, "definers": []}},
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
    )

    git_check = next(check for check in report["checks"] if check["name"] == "git checkpoint")
    assert git_check["status"] == "warning"
    assert "ahead=1" in git_check["detail"]


def test_migration_readiness_accounts_for_cold_store_and_alias_repair(tmp_path: Path) -> None:
    report = build_migration_readiness_report(
        _repo(tmp_path),
        size_resolver=lambda path: 100 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True},
        database_probe=lambda: {"configured": True, "reachable": True, "detail": "read probe passed"},
        cold_store_loader=lambda _root: {"links": 2, "missing": 0, "bytes": 500, "roots": ["/cold"]},
        alias_loader=lambda _root: {
            "available": True,
            "canonical_runs": 4,
            "valid": 3,
            "missing": 0,
            "stale": 0,
            "conflicts": 0,
            "orphaned": 1,
        },
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "detail": "ready"},
        definer_probe=lambda: {"core": {"available": True, "definers": ["root@localhost"]}},
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
    )

    alias_check = next(check for check in report["checks"] if check["name"] == "dynamic compatibility aliases")
    assert report["transfer_footprint"]["external_cold_bytes"] == 500
    assert report["transfer_footprint"]["source_bytes"] == 800
    assert alias_check["status"] == "warning"
    assert "--prune-orphans" in alias_check["detail"]
    assert "External cold APK store: 2 target(s)" in render_migration_readiness_report(report)


def test_migration_readiness_blocks_missing_external_apk_targets(tmp_path: Path) -> None:
    _repo(tmp_path)
    report = build_migration_readiness_report(
        tmp_path,
        size_resolver=lambda path: 1 if path.exists() else None,
        tool_resolver=lambda _name: "/usr/bin/tool",
        git_state_loader=lambda _root: {"repository_detected": True, "branch": "main", "revision": "abc123", "clean": True},
        database_probe=lambda: {"configured": True, "reachable": True, "detail": "read probe passed"},
        cold_store_loader=lambda _root: {"links": 2, "missing": 1, "bytes": 500, "roots": ["/cold"]},
        alias_loader=lambda _root: {"available": True},
        permission_intel_probe=lambda: {"configured": True, "reachable": True, "detail": "ready"},
        definer_probe=lambda: {"core": {"available": True, "definers": []}},
        handoff_loader=lambda: {"ready_for_guided_dataset_run": True, "dataset_packages_with_plan": 15, "dataset_packages_total": 15},
        incomplete_loader=lambda: _Incomplete(0, (), ()),
        mercury_loader=_Mercury,
    )

    cold_check = next(check for check in report["checks"] if check["name"] == "external cold APK store")
    assert cold_check["status"] == "blocker"
    assert report["overall_status"] == "BLOCKED"
