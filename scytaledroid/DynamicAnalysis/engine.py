"""Dynamic analysis engine entrypoint."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.DynamicAnalysis.core import (
    DynamicSessionConfig,
    DynamicSessionResult,
    run_dynamic_session,
)
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import peek_next_run_protocol
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools
from scytaledroid.DynamicAnalysis.plans.loader import (
    build_plan_validation_event,
    load_dynamic_plan,
    render_plan_validation_block,
    validate_dynamic_plan,
)
from scytaledroid.DynamicAnalysis.probes.registry import run_probe_set
from scytaledroid.DynamicAnalysis.storage.persistence import persist_dynamic_summary
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.version_utils import get_git_commit


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
        self.logger.info(
            "Dynamic engine run start",
            extra={
                "package_name": self.config.package_name,
                "duration_seconds": self.config.duration_seconds,
                "device_serial": self.config.device_serial,
                "tier": self.config.tier,
                "observer_ids": list(self.config.observer_ids or ()),
                "plan_path": self.config.plan_path,
            },
        )
        plan_payload, validation = self._resolve_plan_payload()
        if validation and not validation.is_pass:
            now = datetime.now(UTC)
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

        # Dataset-tier preflight: host toolchain must be complete (Paper #2).
        missing_tools = missing_required_tools(tier=self.config.tier)
        if missing_tools:
            now = datetime.now(UTC)
            dynamic_run_id, evidence_path = self._write_blocked_tools_missing(plan_payload, missing_tools)
            blocked = DynamicSessionResult(
                package_name=self.config.package_name,
                duration_seconds=self.config.duration_seconds,
                started_at=now,
                ended_at=now,
                status="blocked",
                notes="Environment not dataset-ready (missing tools).",
                errors=[f"missing_tools:{','.join(missing_tools)}"],
                dynamic_run_id=dynamic_run_id,
                evidence_path=evidence_path,
            )
            summary_payload = {
                "dynamic_run_id": dynamic_run_id,
                "package_name": self.config.package_name,
                "status": blocked.status,
                "evidence_path": evidence_path,
                "plan": plan_payload,
                "probes": {},
                "diagnostics_warnings": ["missing_tools"],
            }
            # Persist blocked dataset-tier runs so validity is auditable in DB.
            self._persist_summary(blocked, summary_payload)
            return DynamicEngineResult(
                config=self.config,
                session=blocked,
                plan=plan_payload,
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
            "telemetry_stats": session_result.telemetry_stats,
            "sampling_rate_s": self.config.sampling_rate_s,
            "telemetry_counts": {
                "process": len(session_result.telemetry_process),
                "network": len(session_result.telemetry_network),
            },
        }
        if isinstance(plan_payload, dict) and plan_payload.get("pcap_required") is not None:
            summary_payload["pcap_required"] = bool(plan_payload.get("pcap_required"))
        for key in (
            "host_time_utc_start",
            "host_time_utc_end",
            "device_time_utc_start",
            "device_time_utc_end",
            "device_uptime_ms_start",
            "device_uptime_ms_end",
            "drift_ms_start",
            "drift_ms_end",
        ):
            if key in (session_result.telemetry_stats or {}):
                summary_payload[key] = session_result.telemetry_stats.get(key)
        summary_payload["diagnostics_warnings"] = self._collect_diagnostics_warnings(session_result)
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
            raise RuntimeError(
                "Dynamic analysis requires a static baseline plan. "
                "Run static analysis to generate a dynamic plan first."
            )
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
            batch_id=self.config.batch_id,
        )
        event_logger = RunEventLogger(run_ctx)
        event_logger.log("plan.validation", build_plan_validation_event(validation))
        event_artifact = event_logger.finalize()
        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=dynamic_run_id,
            created_at=datetime.now(UTC).isoformat(),
            batch_id=self.config.batch_id,
            status="blocked",
            target={
                "package_name": self.config.package_name,
                "static_run_id": self.config.static_run_id,
                "run_type": "dynamic",
            },
            scenario={"id": self.config.scenario_id},
            environment={
                "device_serial": self.config.device_serial,
                "host_tools": collect_host_tools(),
            },
            operator={
                "tool_semver": app_config.APP_VERSION,
                "tool_git_commit": get_git_commit(),
                "schema_version": db_diagnostics.get_schema_version() or "<unknown>",
            },
        )
        if event_artifact:
            manifest.add_artifacts([event_artifact])
        manifest.finalize()
        writer.write_manifest(manifest)
        return dynamic_run_id, str(run_dir)

    def _write_blocked_tools_missing(
        self,
        plan_payload: Mapping[str, Any] | None,
        missing_tools: list[str],
    ) -> tuple[str | None, str | None]:
        """Write a blocked evidence pack for missing host tools (dataset tier)."""
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
            static_plan=dict(plan_payload) if isinstance(plan_payload, Mapping) else None,
            proxy_port=self.config.proxy_port,
            batch_id=self.config.batch_id,
        )
        event_logger = RunEventLogger(run_ctx)
        event_logger.log("preflight.tools_missing", {"missing_tools": missing_tools, "tier": self.config.tier})
        event_artifact = event_logger.finalize()

        protocol = peek_next_run_protocol(self.config.package_name, tier=self.config.tier)
        run_profile = (protocol or {}).get("run_profile") if isinstance(protocol, dict) else None
        run_sequence = (protocol or {}).get("run_sequence") if isinstance(protocol, dict) else None
        interaction_level = "minimal" if str(run_profile or "").lower().startswith("baseline") else "interactive"

        # Deterministic invalid reason code: pick one (no lists) per PM contract.
        missing = {str(t).lower() for t in missing_tools}
        invalid_reason = "MISSING_TOOLS_CAPINFOS" if "capinfos" in missing else "MISSING_TOOLS_TSHARK"

        dataset_validity = {
            "valid_dataset_run": False,
            "invalid_reason_code": invalid_reason,
            "min_pcap_bytes": getattr(app_config, "DYNAMIC_MIN_PCAP_BYTES", 100000),
            "sampling_duration_seconds": None,
            "short_run": 0,
            "no_traffic_observed": 0,
            "missing_tools": sorted(missing_tools),
        }

        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=dynamic_run_id,
            created_at=datetime.now(UTC).isoformat(),
            batch_id=self.config.batch_id,
            status="blocked",
            target={
                "package_name": self.config.package_name,
                "static_run_id": self.config.static_run_id,
                "run_type": "dynamic",
                "static_plan_path": self.config.plan_path,
            },
            scenario={"id": self.config.scenario_id},
            operator={
                "tool_semver": app_config.APP_VERSION,
                "tool_git_commit": get_git_commit(),
                "schema_version": db_diagnostics.get_schema_version() or "<unknown>",
                "host_tools": collect_host_tools(),
                "tier": self.config.tier,
                "run_profile": run_profile,
                "run_sequence": run_sequence,
                "interaction_level": interaction_level,
                "dataset_validity": dataset_validity,
            },
            notes=["Environment not dataset-ready (missing tools)."],
        )
        if event_artifact:
            manifest.add_artifacts([event_artifact])
        manifest.finalize()
        writer.write_manifest(manifest)
        if self.config.interactive:
            print(
                status_messages.status(
                    f"Environment not dataset-ready (missing tools): {', '.join(sorted(missing_tools))}",
                    level="error",
                )
            )
        return dynamic_run_id, str(run_dir)

    def _emit_plan_validation(self, validation) -> None:
        if self.config.interactive:
            if getattr(validation, "is_pass", False):
                print(status_messages.status("Plan validation: PASS (baseline shown above).", level="success"))
            else:
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
            payload = dict(summary_payload)
            # Include telemetry rows for DB persistence without bloating engine_summary.json.
            payload["telemetry_process"] = session_result.telemetry_process
            payload["telemetry_network"] = session_result.telemetry_network
            payload["telemetry_stats"] = session_result.telemetry_stats
            persist_dynamic_summary(self.config, session_result, payload)
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

    def _collect_diagnostics_warnings(
        self,
        session_result: DynamicSessionResult,
    ) -> list[str]:
        warnings: list[str] = []
        stats = session_result.telemetry_stats or {}
        if isinstance(stats, dict):
            net_rows = stats.get("netstats_rows")
            net_missing = stats.get("netstats_missing_rows")
            if (net_rows == 0 or net_rows is None) and isinstance(net_missing, int) and net_missing > 0:
                warnings.append("netstats_missing_rows_present")

        run_dir = resolve_evidence_path(session_result.evidence_path)
        if not run_dir:
            return warnings
        manifest_path = run_dir / "run_manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return warnings

        observers = manifest.get("observers") or []
        pcap_observer_ids = {"pcapdroid_capture"}
        pcap_observer_success = any(
            isinstance(obs, dict)
            and obs.get("observer_id") in pcap_observer_ids
            and obs.get("status") == "success"
            for obs in observers
        )
        if not pcap_observer_success:
            return warnings

        artifacts = manifest.get("artifacts") or []
        pcap_relpath = None
        meta_relpath = None
        for entry in artifacts:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") in pcap_observer_ids:
                pcap_relpath = entry.get("relative_path")
                break
            if entry.get("type") == "pcapdroid_capture_meta":
                meta_relpath = entry.get("relative_path")

        if not pcap_relpath and meta_relpath:
            meta_path = run_dir / meta_relpath
            try:
                meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta_payload = {}
            pcap_valid = meta_payload.get("pcap_valid")
            pcap_size = meta_payload.get("pcap_size_bytes")
            min_bytes = meta_payload.get("min_pcap_bytes")
            if pcap_valid is False:
                if isinstance(pcap_size, int) and isinstance(min_bytes, int):
                    warnings.append("pcap_invalid_small")
                else:
                    warnings.append("pcap_invalid")
                return warnings

        if not pcap_relpath:
            warnings.append("pcap_observer_success_without_artifact")
            return warnings

        pcap_path = run_dir / pcap_relpath
        if not pcap_path.exists():
            warnings.append("pcap_relpath_missing_on_disk")
            return warnings
        try:
            if pcap_path.stat().st_size <= 0:
                warnings.append("pcap_file_empty")
        except OSError:
            warnings.append("pcap_file_stat_failed")
        return warnings


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
            origin="host",
            pull_status="n/a",
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
