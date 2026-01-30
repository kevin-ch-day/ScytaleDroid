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
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.environment import EnvironmentManager
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.plans.loader import (
    PlanValidationError,
    build_plan_validation_event,
    load_dynamic_plan,
    render_plan_validation_block,
    validate_dynamic_plan,
)
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.core.target_manager import TargetManager
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle
from scytaledroid.DynamicAnalysis.scenarios import ManualScenarioRunner
from scytaledroid.DynamicAnalysis.telemetry.sampler import TelemetrySampler


class DynamicRunOrchestrator:
    def __init__(
        self,
        config: DynamicSessionConfig,
        *,
        observers: Iterable[Observer],
        plan_payload: dict[str, object] | None = None,
    ) -> None:
        self.config = config
        self.observers = list(observers)
        self.plan_payload = plan_payload
        self.logger = logging_engine.get_dynamic_logger()
        self._last_plan_validation = None

    def run(self) -> tuple[RunManifest, Path, dict[str, object]]:
        dynamic_run_id = str(uuid.uuid4())
        output_root = Path(self.config.output_root or "output/evidence/dynamic")
        run_dir = output_root / dynamic_run_id
        writer = EvidencePackWriter(run_dir)
        writer.ensure_layout()

        try:
            plan_payload = self.plan_payload or self._load_plan_payload()
        except PlanValidationError as exc:
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
                clear_logcat=self.config.clear_logcat,
                static_run_id=self.config.static_run_id,
                harvest_session_id=self.config.harvest_session_id,
                static_plan=None,
                proxy_port=self.config.proxy_port,
                scenario_hint=None,
            )
            event_logger = RunEventLogger(run_ctx)
            event_logger.log("plan.validation", build_plan_validation_event(exc.outcome))
            event_artifact = event_logger.finalize()
            if event_artifact:
                manifest = RunManifest(
                    run_manifest_version=1,
                    dynamic_run_id=dynamic_run_id,
                    created_at=self._now(),
                    status="blocked",
                    target={"package_name": run_ctx.package_name},
                )
                manifest.add_artifacts([event_artifact])
                manifest.finalize()
                writer.write_manifest(manifest)
            raise
        scenario_hint = None
        if self.config.scenario_id == "permission_trigger":
            scenario_hint = self._build_permission_trigger_hint(plan_payload)
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
            clear_logcat=self.config.clear_logcat,
            static_run_id=self.config.static_run_id,
            harvest_session_id=self.config.harvest_session_id,
            static_plan=plan_payload,
            proxy_port=self.config.proxy_port,
            scenario_hint=scenario_hint,
        )

        manifest = self._build_manifest(run_ctx, plan_payload, writer)
        manifest.started_at = self._now()
        event_logger = RunEventLogger(run_ctx)
        if self._last_plan_validation:
            event_logger.log(
                "plan.validation",
                build_plan_validation_event(self._last_plan_validation),
            )
        elif self.config.plan_validation:
            event_logger.log(
                "plan.validation",
                build_plan_validation_event(self.config.plan_validation),
            )
        event_logger.log(
            "run_initialized",
            {
                "package_name": run_ctx.package_name,
                "scenario_id": run_ctx.scenario_id,
                "duration_seconds": run_ctx.duration_seconds,
                "device_serial": run_ctx.device_serial,
            },
        )
        env_manager = EnvironmentManager()
        env_snapshot = env_manager.prepare(run_ctx)
        manifest.environment.update(env_snapshot.metadata)
        manifest.add_artifacts(env_snapshot.artifacts)
        event_logger.log("environment_prepared", {"artifact_count": len(env_snapshot.artifacts)})

        target_manager = TargetManager()
        target_snapshot = target_manager.prepare(run_ctx)
        if target_snapshot.metadata:
            manifest.target.update(target_snapshot.metadata)
        manifest.add_artifacts(target_snapshot.artifacts)
        event_logger.log("target_prepared", {"artifact_count": len(target_snapshot.artifacts)})
        self._emit_marker(run_ctx, "RUN_START")
        event_logger.log("run_started")

        observer_records, observer_handles = self._start_observers(run_ctx)
        manifest.observers = observer_records
        for record in observer_records:
            if record.artifacts:
                manifest.add_artifacts(record.artifacts)
        for record in observer_records:
            event_logger.log(
                "observer_started",
                {
                    "observer_id": record.observer_id,
                    "status": record.status,
                    "error": record.error,
                },
            )

        scenario_runner = ManualScenarioRunner()
        telemetry_payload: dict[str, object] = {}
        sampler = None
        if run_ctx.device_serial:
            sampler = TelemetrySampler(
                device_serial=run_ctx.device_serial,
                package_name=run_ctx.package_name,
                sample_rate_s=self.config.sampling_rate_s,
            )
            sampler.start()
        self._emit_marker(run_ctx, "SCENARIO_START")
        if run_ctx.scenario_hint:
            event_logger.log("scenario_hint", {"hint": run_ctx.scenario_hint})
        event_logger.log("scenario_started", {"scenario_id": run_ctx.scenario_id})
        scenario_result = scenario_runner.run(run_ctx)
        if sampler:
            capture = sampler.stop()
            telemetry_payload = {
                "telemetry_process": capture.process_rows,
                "telemetry_network": capture.network_rows,
                "telemetry_stats": capture.stats,
                "sampling_rate_s": self.config.sampling_rate_s,
            }
        self._emit_marker(run_ctx, "SCENARIO_END")
        event_logger.log("scenario_ended", {"notes": scenario_result.notes})
        manifest.scenario.update(
            {
                "started_at": scenario_result.started_at.isoformat(),
                "ended_at": scenario_result.ended_at.isoformat(),
                "notes": scenario_result.notes,
            }
        )

        observer_artifacts: list[ArtifactRecord] = []
        run_status = "success"
        if any(record.status == "failed" for record in observer_records):
            run_status = "degraded"
        for observer in self.observers:
            observer_record = next(
                existing for existing in manifest.observers if existing.observer_id == observer.observer_id
            )
            if observer_record.status == "skipped":
                event_logger.log(
                    "observer_skipped",
                    {
                        "observer_id": observer_record.observer_id,
                        "status": observer_record.status,
                        "error": observer_record.error,
                    },
                )
                continue
            if observer_record.status != "started":
                event_logger.log(
                    "observer_skipped",
                    {
                        "observer_id": observer_record.observer_id,
                        "status": observer_record.status,
                        "error": observer_record.error,
                    },
                )
                run_status = "degraded"
                continue
            handle = observer_handles.get(observer.observer_id)
            record = self._stop_observer(observer, run_ctx, handle)
            observer_record.status = record.status
            observer_record.error = record.error
            observer_record.artifacts.extend(record.artifacts)
            observer_artifacts.extend(record.artifacts)
            event_logger.log(
                "observer_stopped",
                {
                    "observer_id": observer.observer_id,
                    "status": record.status,
                    "artifact_count": len(record.artifacts),
                },
            )
            if record.status != "success":
                if record.status != "skipped":
                    run_status = "degraded"

        manifest.add_artifacts(observer_artifacts)
        target_finalize = target_manager.finalize(run_ctx)
        manifest.add_artifacts(target_finalize.artifacts)
        event_logger.log("target_finalized", {"artifact_count": len(target_finalize.artifacts)})
        env_finalize = env_manager.finalize(run_ctx)
        manifest.add_artifacts(env_finalize.artifacts)
        event_logger.log("environment_finalized", {"artifact_count": len(env_finalize.artifacts)})
        self._emit_marker(run_ctx, "RUN_END")
        event_logger.log("run_ended")
        marker_artifact = self._marker_artifact(run_ctx)
        if marker_artifact:
            manifest.add_artifacts([marker_artifact])
        manifest.status = run_status
        manifest.ended_at = self._now()
        event_artifact = event_logger.finalize()
        if event_artifact:
            manifest.add_artifacts([event_artifact])
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

        return manifest, run_dir, telemetry_payload

    def _build_manifest(
        self,
        run_ctx: RunContext,
        plan_payload: dict[str, object] | None,
        writer: EvidencePackWriter,
    ) -> RunManifest:
        created_at = self._now()
        plan_artifact = None
        if plan_payload:
            plan_path = writer.write_json(
                "inputs/static_dynamic_plan.json",
                plan_payload,
            )
            plan_artifact = ArtifactRecord(
                relative_path=str(plan_path.relative_to(writer.run_dir)),
                type="static_dynamic_plan",
                sha256=writer.hash_file(plan_path),
                size_bytes=plan_path.stat().st_size,
                produced_by="dynamic_orchestrator",
            )
        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=run_ctx.dynamic_run_id,
            created_at=created_at,
            target={
                "package_name": run_ctx.package_name,
                "duration_seconds": run_ctx.duration_seconds,
                "static_run_id": self.config.static_run_id,
                "harvest_session_id": self.config.harvest_session_id,
                "static_plan_path": plan_artifact.relative_path if plan_artifact else None,
                "static_plan_summary": self._summarize_plan(plan_payload),
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
        if plan_artifact:
            manifest.add_artifacts([plan_artifact])
        return manifest

    def _start_observers(self, run_ctx: RunContext) -> tuple[list[ObserverRecord], dict[str, object]]:
        handles: dict[str, object] = {}
        records: list[ObserverRecord] = []
        for observer in self.observers:
            try:
                handle = observer.start(run_ctx)
                if (
                    isinstance(handle, ObserverHandle)
                    and isinstance(handle.payload, dict)
                    and handle.payload.get("skipped")
                ):
                    reason = str(handle.payload.get("reason") or "skipped")
                    records.append(
                        ObserverRecord(
                            observer_id=observer.observer_id,
                            status="skipped",
                            error=reason,
                        )
                    )
                    continue
                handles[observer.observer_id] = handle
                records.append(ObserverRecord(observer_id=observer.observer_id, status="started"))
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(
                    "Observer start failed",
                    extra={"observer_id": observer.observer_id, "error": str(exc)},
                )
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
                records.append(
                    ObserverRecord(
                        observer_id=observer.observer_id,
                        status="failed",
                        error=str(exc),
                        artifacts=[artifact],
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

    def _load_plan_payload(self) -> dict[str, object] | None:
        if not self.config.plan_path:
            return None
        try:
            payload = load_dynamic_plan(self.config.plan_path)
            validation = validate_dynamic_plan(
                payload,
                package_name=self.config.package_name,
                static_run_id=self.config.static_run_id,
            )
            self._emit_plan_validation(validation)
            if not validation.is_pass:
                self.logger.warning(
                    "Dynamic plan validation failed",
                    extra={"plan_path": self.config.plan_path, "validation": build_plan_validation_event(validation)},
                )
                raise PlanValidationError(validation)
            return payload
        except PlanValidationError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "Failed to load dynamic plan",
                extra={"plan_path": self.config.plan_path, "error": str(exc)},
            )
            return None

    def _emit_plan_validation(self, validation) -> None:
        if self.config.interactive:
            print(render_plan_validation_block(validation))
        self._last_plan_validation = validation
        self.logger.info(
            "Dynamic plan validation",
            extra=build_plan_validation_event(validation),
        )

    def _summarize_plan(self, plan_payload: dict[str, object] | None) -> dict[str, object] | None:
        if not plan_payload:
            return None
        perms = plan_payload.get("permissions") if isinstance(plan_payload.get("permissions"), dict) else {}
        network = plan_payload.get("network_targets") if isinstance(plan_payload.get("network_targets"), dict) else {}
        risk_flags = plan_payload.get("risk_flags") if isinstance(plan_payload.get("risk_flags"), dict) else {}
        declared = perms.get("declared") if isinstance(perms.get("declared"), list) else []
        dangerous = perms.get("dangerous") if isinstance(perms.get("dangerous"), list) else []
        high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
        domains = network.get("domains") if isinstance(network.get("domains"), list) else []
        cleartext = network.get("cleartext_domains") if isinstance(network.get("cleartext_domains"), list) else []
        return {
            "declared_permissions_count": len(declared),
            "dangerous_permissions_count": len(dangerous),
            "high_value_permissions_count": len(high_value),
            "network_targets_count": len(domains),
            "network_targets_sample": sorted(domains)[:5],
            "cleartext_targets_sample": sorted(cleartext)[:5],
            "risk_flags": risk_flags,
        }

    def _build_permission_trigger_hint(self, plan_payload: dict[str, object] | None) -> str | None:
        if not plan_payload:
            return (
                "Trigger permissions relevant to the app (camera/mic/location/contacts). "
                "If unsure: open app settings → permissions and attempt the related feature."
            )
        perms = plan_payload.get("permissions") if isinstance(plan_payload.get("permissions"), dict) else {}
        high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
        if high_value:
            shortlist = ", ".join(sorted(str(p) for p in high_value)[:6])
            return (
                "Trigger permissions relevant to the app. "
                f"High-value candidates: {shortlist}. "
                "If unsure: open app settings → permissions and attempt the related feature."
            )
        return (
            "Trigger permissions relevant to the app (camera/mic/location/contacts). "
            "If unsure: open app settings → permissions and attempt the related feature."
        )


__all__ = ["DynamicRunOrchestrator"]
