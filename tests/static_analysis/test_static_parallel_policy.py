from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution.static_parallel_workers import (
    effective_parallel_artifact_worker_count,
)


def test_parallel_workers_default_serial(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", raising=False)
    assert (
        effective_parallel_artifact_worker_count(
            resolved_worker_budget=8,
            artifact_count=5,
        )
        == 1
    )


def test_parallel_workers_env_and_budget(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", "6")
    assert (
        effective_parallel_artifact_worker_count(
            resolved_worker_budget=4,
            artifact_count=10,
        )
        == 4
    )


def test_parallel_workers_capped_by_artifact_count(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", "8")
    assert (
        effective_parallel_artifact_worker_count(
            resolved_worker_budget=16,
            artifact_count=3,
        )
        == 3
    )


def test_parallel_workers_invalid_env_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", "bogus")
    assert (
        effective_parallel_artifact_worker_count(
            resolved_worker_budget=4,
            artifact_count=5,
        )
        == 1
    )
