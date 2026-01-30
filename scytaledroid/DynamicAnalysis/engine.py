"""Dynamic analysis engine entrypoint."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping
import uuid

from scytaledroid.Utils.LoggingUtils import logging_engine

from scytaledroid.DynamicAnalysis.core import DynamicSessionConfig, DynamicSessionResult, run_dynamic_session
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.plans.loader import (
    build_plan_validation_event,
    load_dynamic_plan,
    render_plan_validation_block,
    validate_dynamic_plan,
)
from scytaledroid.DynamicAnalysis.probes.registry import run_probe_set
from scytaledroid.DynamicAnalysis.storage.persistence import persist_dynamic_summary


@dataclass(frozen=True)
class DynamicEngineResult:
    config: DynamicSessionConfig
    session: DynamicSessionResult
    plan: Mapping[str, Any] | None
    probe_summary: Mapping[str, Any]
    summary_payload: Mapping[str, Any]


class DynamicAnalysisEngine:
    def __init__(
        self,
        config: DynamicSessionConfig,
        *,
        plan_payload: Mapping[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.plan_payload = plan_payload
        self.logger = logging_engine.get_dynamic_logger()

    def run(self) -> DynamicEngineResult:
        plan_payload, validation = self._resolve_plan_payload()
        if validation and not validation.is_pass:
            now = datetime.now(timezone.utc)
            dynamic_run_id, evidence_path = self._write_blocked_event(validation)
            blocked = DynamicSessionResult(
                package_name=self.config.package_name,
                duration_seconds=self.config.duration_seconds,
                started_at=now,
                ended_at=now,
                status="blocked",
                notes="Dynamic execution blocked by plan validation.",
                errors=list(validation.reasons) if validation.reasons else ["dynamic plan validation failed"],
                dynamic_run_id=dynamic_run_id,
                evidence_path=evidence_path,
            )
            summary_payload = {
                "dynamic_run_id": dynamic_run_id,
                "package_name": self.config.package_name,
                "status": blocked.status,
                "evidence_path": evidence_path,
                "plan": None,
                "probes": {},
                "plan_validation": build_plan_validation_event(validation),
            }
            return DynamicEngineResult(
                config=self.config,
                session=blocked,
                plan=None,
                probe_summary={},
                summary_payload=summary_payload,
            )
        run_config = self.config
        if validation is not None:
            run_config = replace(self.config, plan_validation=validation)
        session_result = run_dynamic_session(run_config, plan_payload=dict(plan_payload) if plan_payload else None)
        probe_summary = run_probe_set(self.config, plan_payload)
        summary_payload = {
            "dynamic_run_id": session_result.dynamic_run_id,
            "package_name": self.config.package_name,
            "status": session_result.status,
            "evidence_path": session_result.evidence_path,
            "plan": plan_payload,
            "probes": probe_summary,
            "telemetry_process": session_result.telemetry_process,
            "telemetry_network": session_result.telemetry_network,
            "telemetry_stats": session_result.telemetry_stats,
            "sampling_rate_s": self.config.sampling_rate_s,
        }
        self._attach_engine_outputs(session_result, plan_payload, probe_summary, summary_payload)
        self._persist_summary(session_result, summary_payload)
        return DynamicEngineResult(
            config=self.config,
            session=session_result,
            plan=plan_payload,
            probe_summary=probe_summary,
            summary_payload=summary_payload,
        )

    def _resolve_plan_payload(self) -> tuple[Mapping[str, Any] | None, object | None]:
        if self.plan_payload is not None:
            return self.plan_payload, None
        if not self.config.plan_path:
            return None, None
        try:
            payload = load_dynamic_plan(self.config.plan_path)
        except (OSError, ValueError) as exc:
            self.logger.warning(
                "Failed to load dynamic plan",
                extra={"plan_path": self.config.plan_path, "error": str(exc)},
            )
            return None, None
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
            return None, validation
        return payload, validation

    def _write_blocked_event(self, validation) -> tuple[str | None, str | None]:
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
            clear_logcat=self.config.clear_logcat,
            static_run_id=self.config.static_run_id,
            harvest_session_id=self.config.harvest_session_id,
            static_plan=None,
            proxy_port=self.config.proxy_port,
        )
        event_logger = RunEventLogger(run_ctx)
        event_logger.log("plan.validation", build_plan_validation_event(validation))
        event_artifact = event_logger.finalize()
        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=dynamic_run_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="blocked",
            target={
                "package_name": self.config.package_name,
                "static_run_id": self.config.static_run_id,
            },
            scenario={"id": self.config.scenario_id},
        )
        if event_artifact:
            manifest.add_artifacts([event_artifact])
        manifest.finalize()
        writer.write_manifest(manifest)
        return dynamic_run_id, str(run_dir)

    def _emit_plan_validation(self, validation) -> None:
        if self.config.interactive:
            print(render_plan_validation_block(validation))
        self.logger.info(
            "Dynamic plan validation",
            extra=build_plan_validation_event(validation),
        )

    def _persist_summary(
        self,
        session_result: DynamicSessionResult,
        summary_payload: Mapping[str, Any],
    ) -> None:
        try:
            persist_dynamic_summary(self.config, session_result, dict(summary_payload))
        except NotImplementedError:
            self.logger.info("Dynamic persistence not enabled yet.")
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "Failed to persist dynamic summary",
                extra={"error": str(exc)},
            )

    def _attach_engine_outputs(
        self,
        session_result: DynamicSessionResult,
        plan_payload: Mapping[str, Any] | None,
        probe_summary: Mapping[str, Any],
        summary_payload: Mapping[str, Any],
    ) -> None:
        if not session_result.evidence_path:
            self.logger.warning(
                "Dynamic evidence path missing; engine outputs not written",
                extra={"dynamic_run_id": session_result.dynamic_run_id},
            )
            return
        run_dir = Path(session_result.evidence_path)
        writer = EvidencePackWriter(run_dir)
        outputs: list[ArtifactRecord] = []

        summary_path = writer.write_json("analysis/engine_summary.json", dict(summary_payload))
        outputs.append(self._output_record(writer, summary_path, "engine_summary"))

        probe_path = writer.write_json("analysis/probe_summary.json", dict(probe_summary))
        outputs.append(self._output_record(writer, probe_path, "probe_summary"))

        if plan_payload:
            plan_path = writer.write_json("notes/dynamic_plan.json", dict(plan_payload))
            outputs.append(self._output_record(writer, plan_path, "dynamic_plan_snapshot"))

        try:
            self._update_manifest_outputs(writer, outputs)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "Failed to update run manifest with engine outputs",
                extra={"error": str(exc)},
            )

    def _output_record(
        self,
        writer: EvidencePackWriter,
        path: Path,
        output_type: str,
    ) -> ArtifactRecord:
        digest = writer.hash_file(path)
        return ArtifactRecord(
            relative_path=str(path.relative_to(writer.run_dir)),
            type=output_type,
            sha256=digest,
            size_bytes=path.stat().st_size,
            produced_by="dynamic_engine",
        )

    def _update_manifest_outputs(
        self,
        writer: EvidencePackWriter,
        outputs: list[ArtifactRecord],
    ) -> None:
        manifest_path = writer.run_dir / "run_manifest.json"
        if not manifest_path.exists():
            return
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        existing_outputs = payload.get("outputs")
        if not isinstance(existing_outputs, list):
            existing_outputs = []
        for record in outputs:
            existing_outputs.append(
                {
                    "relative_path": record.relative_path,
                    "type": record.type,
                    "sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "produced_by": record.produced_by,
                }
            )
        existing_outputs.sort(key=lambda item: str(item.get("relative_path", "")))
        payload["outputs"] = existing_outputs
        manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def run_dynamic_engine(config: DynamicSessionConfig) -> DynamicEngineResult:
    engine = DynamicAnalysisEngine(config)
    return engine.run()


__all__ = ["DynamicAnalysisEngine", "DynamicEngineResult", "run_dynamic_engine"]
