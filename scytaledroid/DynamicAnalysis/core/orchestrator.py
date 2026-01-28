"""Dynamic analysis orchestrator."""

from __future__ import annotations

import getpass
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from scytaledroid.Utils.LoggingUtils import logging_engine

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
from scytaledroid.DynamicAnalysis.core.environment import EnvironmentManager
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.observers.base import Observer
from scytaledroid.DynamicAnalysis.scenarios import ManualScenarioRunner


class DynamicRunOrchestrator:
    def __init__(
        self,
        config: DynamicSessionConfig,
        *,
        observers: Iterable[Observer],
    ) -> None:
        self.config = config
        self.observers = list(observers)
        self.logger = logging_engine.get_dynamic_logger()

    def run(self) -> tuple[RunManifest, Path]:
        dynamic_run_id = str(uuid.uuid4())
        output_root = Path(self.config.output_root or "output/evidence/dynamic")
        run_dir = output_root / dynamic_run_id
        writer = EvidencePackWriter(run_dir)
        writer.ensure_layout()

        run_ctx = RunContext(
            dynamic_run_id=dynamic_run_id,
            package_name=self.config.package_name,
            duration_seconds=self.config.duration_seconds,
            scenario_id=self.config.scenario_id,
            run_dir=run_dir,
            artifacts_dir=writer.artifacts_dir,
            analysis_dir=writer.analysis_dir,
            notes_dir=writer.notes_dir,
            interactive=self.config.interactive,
            device_serial=self.config.device_serial,
        )

        manifest = self._build_manifest(run_ctx)
        manifest.started_at = self._now()
        env_manager = EnvironmentManager()
        env_snapshot = env_manager.prepare(run_ctx)
        manifest.environment.update(env_snapshot.metadata)
        manifest.add_artifacts(env_snapshot.artifacts)
        self._emit_marker(run_ctx, "RUN_START")

        observer_records, observer_handles = self._start_observers(run_ctx)
        manifest.observers = observer_records

        scenario_runner = ManualScenarioRunner()
        self._emit_marker(run_ctx, "SCENARIO_START")
        scenario_result = scenario_runner.run(run_ctx)
        self._emit_marker(run_ctx, "SCENARIO_END")
        manifest.scenario.update(
            {
                "started_at": scenario_result.started_at.isoformat(),
                "ended_at": scenario_result.ended_at.isoformat(),
                "notes": scenario_result.notes,
            }
        )

        observer_artifacts: list[ArtifactRecord] = []
        run_status = "success"
        if any(record.status != "started" for record in observer_records):
            run_status = "degraded"
        for observer in self.observers:
            handle = observer_handles.get(observer.observer_id)
            record = self._stop_observer(observer, run_ctx, handle)
            observer_record = next(
                existing for existing in manifest.observers if existing.observer_id == observer.observer_id
            )
            observer_record.status = record.status
            observer_record.error = record.error
            observer_record.artifacts.extend(record.artifacts)
            observer_artifacts.extend(record.artifacts)
            if record.status != "success":
                run_status = "degraded"

        manifest.add_artifacts(observer_artifacts)
        env_finalize = env_manager.finalize(run_ctx)
        manifest.add_artifacts(env_finalize.artifacts)
        self._emit_marker(run_ctx, "RUN_END")
        marker_artifact = self._marker_artifact(run_ctx)
        if marker_artifact:
            manifest.add_artifacts([marker_artifact])
        manifest.status = run_status
        manifest.ended_at = self._now()
        manifest.finalize()

        summarizer = DynamicRunSummarizer(writer)
        outputs = summarizer.summarize(manifest)
        manifest.add_outputs(outputs)
        manifest.finalize()
        writer.write_manifest(manifest)

        self.logger.info(
            "Dynamic run complete",
            extra={
                "dynamic_run_id": dynamic_run_id,
                "status": manifest.status,
                "evidence_path": str(run_dir),
            },
        )

        return manifest, run_dir

    def _build_manifest(self, run_ctx: RunContext) -> RunManifest:
        created_at = self._now()
        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=run_ctx.dynamic_run_id,
            created_at=created_at,
            target={
                "package_name": run_ctx.package_name,
                "duration_seconds": run_ctx.duration_seconds,
                "static_run_id": self.config.static_run_id,
                "harvest_session_id": self.config.harvest_session_id,
            },
            environment={
                "device_serial": run_ctx.device_serial,
                "host": platform.node(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
            },
            scenario={
                "id": run_ctx.scenario_id,
                "label": run_ctx.scenario_id.replace("_", " ").title(),
            },
            observers=[
                ObserverRecord(observer_id=observer.observer_id, status="pending")
                for observer in self.observers
            ],
            operator={
                "user": getpass.getuser(),
                "host": platform.node(),
            },
        )
        return manifest

    def _start_observers(self, run_ctx: RunContext) -> tuple[list[ObserverRecord], dict[str, object]]:
        handles: dict[str, object] = {}
        records: list[ObserverRecord] = []
        for observer in self.observers:
            try:
                handles[observer.observer_id] = observer.start(run_ctx)
                records.append(ObserverRecord(observer_id=observer.observer_id, status="started"))
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(
                    "Observer start failed",
                    extra={"observer_id": observer.observer_id, "error": str(exc)},
                )
                records.append(
                    ObserverRecord(
                        observer_id=observer.observer_id,
                        status="failed",
                        error=str(exc),
                    )
                )
        return records, handles

    def _stop_observer(
        self,
        observer: Observer,
        run_ctx: RunContext,
        handle: object | None,
    ) -> ObserverRecord:
        try:
            result = observer.stop(run_ctx=run_ctx, handle=handle)  # type: ignore[arg-type]
            return ObserverRecord(
                observer_id=result.observer_id,
                status=result.status,
                error=result.error,
                artifacts=result.artifacts,
            )
        except Exception as exc:  # noqa: BLE001
            error_path = run_ctx.artifacts_dir / observer.observer_id / "observer_error.txt"
            error_path.parent.mkdir(parents=True, exist_ok=True)
            error_path.write_text(str(exc))
            digest = EvidencePackWriter(run_ctx.run_dir).hash_file(error_path)
            artifact = ArtifactRecord(
                relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                type="observer_error",
                sha256=digest,
                size_bytes=error_path.stat().st_size,
                produced_by=observer.observer_id,
            )
            return ObserverRecord(
                observer_id=observer.observer_id,
                status="failed",
                error=str(exc),
                artifacts=[artifact],
            )

    def _emit_marker(self, run_ctx: RunContext, label: str) -> None:
        timestamp = self._now()
        marker_line = f"{timestamp} {label}"
        marker_path = run_ctx.run_dir / "artifacts/markers/run_markers.txt"
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        with marker_path.open("a", encoding="utf-8") as handle:
            handle.write(marker_line + "\n")
        if run_ctx.device_serial:
            try:
                adb_utils.run_shell(
                    run_ctx.device_serial,
                    ["log", "-t", "SCYTALE_DYNAMIC", marker_line],
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(
                    "Failed to emit device marker",
                    extra={"error": str(exc)},
                )

    def _marker_artifact(self, run_ctx: RunContext) -> ArtifactRecord | None:
        marker_path = run_ctx.run_dir / "artifacts/markers/run_markers.txt"
        if not marker_path.exists():
            return None
        digest = EvidencePackWriter(run_ctx.run_dir).hash_file(marker_path)
        return ArtifactRecord(
            relative_path=str(marker_path.relative_to(run_ctx.run_dir)),
            type="run_markers",
            sha256=digest,
            size_bytes=marker_path.stat().st_size,
            produced_by="orchestrator",
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()


__all__ = ["DynamicRunOrchestrator"]
