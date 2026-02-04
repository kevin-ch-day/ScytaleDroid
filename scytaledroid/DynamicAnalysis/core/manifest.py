"""Run manifest models for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _sorted_artifacts(artifacts: list[ArtifactRecord]) -> list[ArtifactRecord]:
    return sorted(artifacts, key=lambda record: record.relative_path)


@dataclass(frozen=True)
class ArtifactRecord:
    relative_path: str
    type: str
    sha256: str
    produced_by: str
    size_bytes: int | None = None
    origin: str | None = None
    device_path: str | None = None
    pull_status: str | None = None


@dataclass
class ObserverRecord:
    observer_id: str
    status: str
    error: str | None = None
    artifacts: list[ArtifactRecord] = field(default_factory=list)

    def finalize(self) -> None:
        self.artifacts = _sorted_artifacts(self.artifacts)


@dataclass
class RunManifest:
    run_manifest_version: int
    dynamic_run_id: str
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    status: str = "pending"
    target: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    scenario: dict[str, Any] = field(default_factory=dict)
    observers: list[ObserverRecord] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    outputs: list[ArtifactRecord] = field(default_factory=list)
    operator: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add_artifacts(self, records: list[ArtifactRecord]) -> None:
        self.artifacts.extend(records)

    def add_outputs(self, records: list[ArtifactRecord]) -> None:
        self.outputs.extend(records)

    def finalize(self) -> None:
        for observer in self.observers:
            observer.finalize()
        self.artifacts = _sorted_artifacts(self.artifacts)
        self.outputs = _sorted_artifacts(self.outputs)


def manifest_to_dict(manifest: RunManifest) -> dict[str, Any]:
    return {
        "run_manifest_version": manifest.run_manifest_version,
        "dynamic_run_id": manifest.dynamic_run_id,
        "created_at": manifest.created_at,
        "started_at": manifest.started_at,
        "ended_at": manifest.ended_at,
        "status": manifest.status,
        "target": manifest.target,
        "environment": manifest.environment,
        "scenario": manifest.scenario,
        "observers": [
            {
                "observer_id": observer.observer_id,
                "status": observer.status,
                "error": observer.error,
                "artifacts": [
                    {
                        "relative_path": artifact.relative_path,
                        "type": artifact.type,
                        "sha256": artifact.sha256,
                        "size_bytes": artifact.size_bytes,
                        "produced_by": artifact.produced_by,
                        "origin": artifact.origin,
                        "device_path": artifact.device_path,
                        "pull_status": artifact.pull_status,
                    }
                    for artifact in observer.artifacts
                ],
            }
            for observer in manifest.observers
        ],
        "artifacts": [
            {
                "relative_path": artifact.relative_path,
                "type": artifact.type,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "produced_by": artifact.produced_by,
                "origin": artifact.origin,
                "device_path": artifact.device_path,
                "pull_status": artifact.pull_status,
            }
            for artifact in manifest.artifacts
        ],
        "outputs": [
            {
                "relative_path": artifact.relative_path,
                "type": artifact.type,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "produced_by": artifact.produced_by,
                "origin": artifact.origin,
                "device_path": artifact.device_path,
                "pull_status": artifact.pull_status,
            }
            for artifact in manifest.outputs
        ],
        "operator": manifest.operator,
        "notes": manifest.notes,
    }


__all__ = [
    "ArtifactRecord",
    "ObserverRecord",
    "RunManifest",
    "manifest_to_dict",
]
