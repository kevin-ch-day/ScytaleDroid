"""Dynamic analysis engine entrypoint."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from scytaledroid.Utils.LoggingUtils import logging_engine

from scytaledroid.DynamicAnalysis.core import DynamicSessionConfig, DynamicSessionResult, run_dynamic_session
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.plans.loader import load_dynamic_plan
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
        plan_payload = self._resolve_plan_payload()
        session_result = run_dynamic_session(self.config)
        probe_summary = run_probe_set(self.config, plan_payload)
        summary_payload = {
            "dynamic_run_id": session_result.dynamic_run_id,
            "package_name": self.config.package_name,
            "status": session_result.status,
            "evidence_path": session_result.evidence_path,
            "plan": plan_payload,
            "probes": probe_summary,
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

    def _resolve_plan_payload(self) -> Mapping[str, Any] | None:
        if self.plan_payload is not None:
            return self.plan_payload
        if not self.config.plan_path:
            return None
        try:
            payload = load_dynamic_plan(self.config.plan_path)
        except (OSError, ValueError) as exc:
            self.logger.warning(
                "Failed to load dynamic plan",
                extra={"plan_path": self.config.plan_path, "error": str(exc)},
            )
            return None
        package = payload.get("package_name")
        if package and package != self.config.package_name:
            self.logger.warning(
                "Dynamic plan package mismatch",
                extra={
                    "plan_package": package,
                    "config_package": self.config.package_name,
                },
            )
        return payload

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
