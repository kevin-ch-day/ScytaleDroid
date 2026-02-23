"""Dynamic analysis orchestrator."""

from __future__ import annotations

import getpass
import platform
import shutil
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
from scytaledroid.DynamicAnalysis.core.environment import EnvironmentManager
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.core.static_context import (
    build_operator_guidance,
    compute_static_context,
)
from scytaledroid.DynamicAnalysis.core.target_manager import TargetManager
from scytaledroid.DynamicAnalysis.monitor import RunMonitor, RunMonitorConfig
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle
from scytaledroid.DynamicAnalysis.pcap.correlate import write_static_dynamic_overlap
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    MIN_WINDOWS_PER_RUN,
    derive_three_verdicts_for_row,
    evaluate_dataset_validity,
    load_dataset_tracker,
    peek_next_run_protocol,
    update_dataset_tracker,
)
from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
from scytaledroid.DynamicAnalysis.pcap.indexer import index_pcap_by_app
from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools
from scytaledroid.DynamicAnalysis.paper_contract import (
    PAPER_CONTRACT_VERSION as PAPER_MODE_CONTRACT_VERSION,
    build_paper_contract_snapshot,
    paper_contract_hash,
)
from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
from scytaledroid.DynamicAnalysis.plans.loader import (
    PlanValidationError,
    build_plan_validation_event,
    load_dynamic_plan,
    render_plan_validation_block,
    validate_dynamic_plan,
)
from scytaledroid.DynamicAnalysis.scenarios import ManualScenarioRunner, SCRIPT_PROTOCOL_VERSION
from scytaledroid.DynamicAnalysis.telemetry.sampler import TelemetrySampler
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.version_utils import get_git_commit


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
                batch_id=self.config.batch_id,
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
        protocol = peek_next_run_protocol(
            self.config.package_name,
            tier=self.config.tier,
        )
        # Allow entrypoint/UI to provide explicit operator protocol metadata. This does not
        # change scoring/QA semantics; it is used only for tagging and stratified analysis.
        if isinstance(protocol, dict):
            if getattr(self.config, "run_profile", None):
                protocol = dict(protocol)
                protocol["run_profile"] = self.config.run_profile
        elif getattr(self.config, "run_profile", None):
            protocol = {"run_profile": self.config.run_profile}
        static_hint_lines = build_operator_guidance(
            plan_payload,
            run_profile=(protocol or {}).get("run_profile") if isinstance(protocol, dict) else None,
        )
        if static_hint_lines:
            static_hint = "\n".join(static_hint_lines)
            scenario_hint = f"{scenario_hint}\n{static_hint}" if scenario_hint else static_hint
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
            run_profile=(protocol or {}).get("run_profile") if isinstance(protocol, dict) else None,
            run_sequence=(protocol or {}).get("run_sequence") if isinstance(protocol, dict) else None,
            interaction_level=getattr(self.config, "interaction_level", None),
            messaging_activity=getattr(self.config, "messaging_activity", None),
            counts_toward_completion=getattr(self.config, "counts_toward_completion", None),
            device_serial=self.config.device_serial,
            clear_logcat=self.config.clear_logcat,
            static_run_id=self.config.static_run_id,
            harvest_session_id=self.config.harvest_session_id,
            static_plan=plan_payload,
            proxy_port=self.config.proxy_port,
            scenario_hint=scenario_hint,
            batch_id=self.config.batch_id,
        )

        self.logger.info(
            "RunContext snapshot",
            extra={
                "dynamic_run_id": run_ctx.dynamic_run_id,
                "package_name": run_ctx.package_name,
                "interactive": bool(run_ctx.interactive),
                "tier": self.config.tier,
                "duration_seconds": run_ctx.duration_seconds,
                "scenario_id": run_ctx.scenario_id,
                "device_serial": run_ctx.device_serial,
                "observer_ids": [observer.observer_id for observer in self.observers],
                "sampling_rate_s": self.config.sampling_rate_s,
                "batch_id": getattr(run_ctx, "batch_id", None),
                "run_profile": getattr(run_ctx, "run_profile", None),
                "run_sequence": getattr(run_ctx, "run_sequence", None),
                "interaction_level": getattr(run_ctx, "interaction_level", None),
                "messaging_activity": getattr(run_ctx, "messaging_activity", None),
                "counts_toward_completion": getattr(run_ctx, "counts_toward_completion", None),
            },
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
            plan_identity = plan_payload.get("run_identity") if isinstance(plan_payload, dict) and isinstance(plan_payload.get("run_identity"), dict) else {}
            manifest.target["identity_checked_at_start_utc"] = self._now()
            manifest.target["identity_start"] = {
                "package_name_lc": str(plan_identity.get("package_name_lc") or plan_payload.get("package_name") or "").strip().lower() if isinstance(plan_payload, dict) else None,
                "version_code": str(plan_identity.get("version_code") or plan_payload.get("version_code") or "").strip() if isinstance(plan_payload, dict) else None,
                "base_apk_sha256": plan_identity.get("base_apk_sha256"),
                "artifact_set_hash": plan_identity.get("artifact_set_hash"),
                "signer_set_hash": plan_identity.get("signer_set_hash") or plan_identity.get("signer_digest"),
                "observed_signer_set_hash": (target_snapshot.metadata or {}).get("signer_set_hash"),
                "observed_signer_primary_digest": (target_snapshot.metadata or {}).get("signer_primary_digest"),
                "static_handoff_hash": plan_identity.get("static_handoff_hash"),
                "observed_package_name_lc": str((target_snapshot.metadata or {}).get("package_name") or "").strip().lower(),
                "observed_version_code": str((target_snapshot.metadata or {}).get("version_code") or "").strip() or None,
                "user_id": str((target_snapshot.metadata or {}).get("user_id") or "").strip() or "0",
                "first_install_time": (target_snapshot.metadata or {}).get("first_install_time"),
                "last_update_time": (target_snapshot.metadata or {}).get("last_update_time"),
                "installer_package_name": (target_snapshot.metadata or {}).get("installer_package_name"),
            }
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
        monitor = None
        clock_start = None
        clock_end = None
        if run_ctx.device_serial:
            sampler = TelemetrySampler(
                device_serial=run_ctx.device_serial,
                package_name=run_ctx.package_name,
                sample_rate_s=self.config.sampling_rate_s,
                allow_fallback_iface=self.config.tier != "dataset",
                netstats_debug_dir=run_ctx.notes_dir,
            )
            if self.config.enable_monitor:
                verbose = bool(getattr(self.config, "monitor_verbose", False))
                monitor = RunMonitor(
                    RunMonitorConfig(
                        device_serial=run_ctx.device_serial,
                        run_id=run_ctx.dynamic_run_id,
                        notes_dir=run_ctx.notes_dir,
                        interactive=run_ctx.interactive,
                        verbose=verbose,
                    )
                )
                if run_ctx.interactive:
                    print(
                        status_messages.status(
                            "Run monitor enabled (writing notes/run_monitor.jsonl).",
                            level="info",
                        )
                    )
            clock_start = self._capture_device_clock(run_ctx.device_serial)
        host_start = datetime.now(UTC)
        self._emit_marker(run_ctx, "SCENARIO_START")
        if run_ctx.scenario_hint:
            event_logger.log("scenario_hint", {"hint": run_ctx.scenario_hint})
        event_logger.log("scenario_started", {"scenario_id": run_ctx.scenario_id})
        try:
            if monitor:
                monitor.start()
            scenario_result = scenario_runner.run(
                run_ctx,
                on_start=sampler.start if sampler else None,
                on_end=None,
                on_protocol_event=(lambda event_type, details: event_logger.log(event_type, details)),
            )
        finally:
            if monitor:
                monitor.stop()
        if sampler:
            capture = sampler.stop()
            telemetry_payload = {
                "telemetry_process": capture.process_rows,
                "telemetry_network": capture.network_rows,
                "telemetry_stats": capture.stats,
                "sampling_rate_s": self.config.sampling_rate_s,
            }
            manifest.operator["telemetry_stats"] = capture.stats
            manifest.operator["telemetry_counts"] = {
                "process": len(capture.process_rows),
                "network": len(capture.network_rows),
            }
            manifest.operator["telemetry_schema_version"] = 1
            manifest.operator["sampling_rate_s"] = self.config.sampling_rate_s
            manifest.operator["tier"] = self.config.tier
        if run_ctx.device_serial:
            clock_end = self._capture_device_clock(run_ctx.device_serial)
        host_end = datetime.now(UTC)
        clock_payload = self._format_clock_payload(host_start, host_end, clock_start, clock_end)
        if clock_payload:
            telemetry_payload.update(clock_payload)
            manifest.environment.setdefault("clock", {}).update(clock_payload)
        self._emit_marker(run_ctx, "SCENARIO_END")
        event_logger.log("scenario_ended", {"notes": scenario_result.notes})
        manifest.scenario.update(
            {
                "started_at": scenario_result.started_at.isoformat(),
                "ended_at": scenario_result.ended_at.isoformat(),
                "notes": scenario_result.notes,
                "interaction_level": (
                    "minimal"
                    if getattr(scenario_result, "interaction_level", None) == "idle"
                    else getattr(scenario_result, "interaction_level", None)
                ),
            }
        )
        actual_duration_s = int((scenario_result.ended_at - scenario_result.started_at).total_seconds())
        manifest.operator["actual_duration_s"] = actual_duration_s
        if isinstance(scenario_result.protocol, dict):
            protocol = scenario_result.protocol
            manifest.operator.update(
                {
                    "interaction_protocol_version": int(
                        protocol.get("interaction_protocol_version") or SCRIPT_PROTOCOL_VERSION
                    ),
                    "template_id": protocol.get("template_id"),
                    "template_hash": protocol.get("template_hash"),
                    "template_map_version": protocol.get("template_map_version"),
                    "template_map_hash": protocol.get("template_map_hash"),
                    "baseline_protocol_id": protocol.get("baseline_protocol_id"),
                    "baseline_protocol_version": protocol.get("baseline_protocol_version"),
                    "baseline_protocol_hash": protocol.get("baseline_protocol_hash"),
                    "script_name": protocol.get("script_name"),
                    "scenario_template": protocol.get("scenario_template"),
                    "script_hash": protocol.get("script_hash"),
                    "step_count": protocol.get("step_count_completed"),
                    "step_count_planned": protocol.get("step_count_planned"),
                    "step_count_completed": protocol.get("step_count_completed"),
                    "script_exit_code": protocol.get("script_exit_code"),
                    "script_end_marker": protocol.get("script_end_marker"),
                    "script_timing_within_tolerance": protocol.get("timing_within_tolerance"),
                    "script_target_overrun_s": protocol.get("target_overrun_s"),
                    "script_target_controlled": protocol.get("target_controlled"),
                    "target_duration_s": protocol.get("target_duration_s") or manifest.operator.get("target_duration_s"),
                    "call_type": protocol.get("call_type"),
                    "call_attempted": protocol.get("call_attempted"),
                    "call_connected": protocol.get("call_connected"),
                    "call_connect_latency_s": protocol.get("call_connect_latency_s"),
                    "call_connected_duration_s": protocol.get("call_connected_duration_s"),
                    "call_end_reason": protocol.get("call_end_reason"),
                }
            )
        else:
            profile = str(getattr(run_ctx, "run_profile", "") or "").strip().lower()
            if profile.startswith("baseline"):
                manifest.operator.setdefault("not_applicable", {"script": profile or "baseline"})
        interaction_level = (
            "minimal"
            if getattr(scenario_result, "interaction_level", None) == "idle"
            else getattr(scenario_result, "interaction_level", None)
        )
        # If the scenario runner didn't provide an interaction level, derive a
        # deterministic operator label from the dataset protocol (baseline vs interactive).
        if not interaction_level:
            tier = self.config.tier
            run_profile = getattr(run_ctx, "run_profile", None)
            if tier and str(tier).lower() == "dataset" and run_profile:
                if str(run_profile).lower().startswith("baseline"):
                    interaction_level = "minimal"
                else:
                    interaction_level = "interactive"

        if interaction_level:
            manifest.operator["interaction_level"] = interaction_level
            event_logger.log(
                "operator_interaction_level",
                {"interaction_level": interaction_level},
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
        if target_finalize.metadata:
            manifest.target.update(target_finalize.metadata)
        identity_end_pkg = str((target_finalize.metadata or {}).get("package_name_end") or "").strip().lower()
        identity_end_ver = str((target_finalize.metadata or {}).get("version_code_end") or "").strip() or None
        if identity_end_pkg or identity_end_ver:
            manifest.target["identity_checked_at_end_utc"] = self._now()
            manifest.target["identity_end"] = {
                "observed_package_name_lc": identity_end_pkg or None,
                "observed_version_code": identity_end_ver,
                "observed_signer_set_hash": (target_finalize.metadata or {}).get("signer_set_hash_end"),
                "observed_signer_primary_digest": (target_finalize.metadata or {}).get("signer_primary_digest_end"),
                "user_id": str((target_finalize.metadata or {}).get("user_id_end") or "").strip() or "0",
                "first_install_time": (target_finalize.metadata or {}).get("first_install_time_end"),
                "last_update_time": (target_finalize.metadata or {}).get("last_update_time_end"),
                "installer_package_name": (target_finalize.metadata or {}).get("installer_package_name_end"),
            }
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
        try:
            index_pcap_by_app(manifest, run_dir, event_logger=event_logger)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "PCAP archive index failed",
                extra={"dynamic_run_id": dynamic_run_id, "error": str(exc)},
            )
            event_logger.log("pcap_index_failed", {"error": str(exc)})

        summarizer = DynamicRunSummarizer(writer)
        outputs = summarizer.summarize(manifest)
        report = write_pcap_report(manifest, run_dir, event_logger=event_logger)
        if report:
            outputs.append(report)
        features = write_pcap_features(manifest, run_dir, event_logger=event_logger)
        if features:
            outputs.append(features)
        overlap = write_static_dynamic_overlap(manifest, run_dir, event_logger=event_logger)
        if overlap:
            outputs.append(overlap)
        tier = (manifest.operator or {}).get("tier") if isinstance(manifest.operator, dict) else None
        if not (tier and str(tier).lower() == "dataset"):
            update_dataset_tracker(manifest, run_dir, event_logger=event_logger)

        # Deterministic dataset validity classification (Paper #2) must be written to the manifest.
        if tier and str(tier).lower() == "dataset":
            try:
                entry = {"pcap_size_bytes": next((a.size_bytes for a in manifest.artifacts if a.type == "pcapdroid_capture"), 0)}
                validity = evaluate_dataset_validity(run_dir, manifest, entry, DatasetTrackerConfig())
                # First-class dataset validity (Paper #2). Written only to manifest.dataset.
                if isinstance(validity, dict):
                    current_ds = manifest.dataset if isinstance(manifest.dataset, dict) else {}
                    merged_ds = dict(current_ds)
                    merged_ds.update(validity)
                    merged_ds.setdefault("tier", self.config.tier)
                    manifest.dataset = merged_ds

                    # ML readiness is separate from validity. Tag low-signal runs deterministically
                    # without changing VALID/INVALID semantics (Paper #2 contract).
                    try:
                        from scytaledroid.DynamicAnalysis.pcap.low_signal import (
                            compute_low_signal_for_run,
                        )

                        ls = compute_low_signal_for_run(
                            run_dir,
                            package_name=str((manifest.target or {}).get("package_name") or ""),
                            run_profile=str((manifest.operator or {}).get("run_profile") or ""),
                        )
                        if isinstance(ls, dict):
                            manifest.dataset.update(ls)
                    except Exception:
                        # Best-effort; absence is not a correctness failure.
                        pass

                    # Derive paper-eligibility from finalized in-memory state, then
                    # sync tracker from this final state so countability is not stale.
                    eligibility = derive_paper_eligibility(
                        manifest={
                            "dataset": manifest.dataset,
                            "operator": manifest.operator,
                            "target": manifest.target,
                        },
                        plan=plan_payload if isinstance(plan_payload, dict) else {},
                        min_windows=int(MIN_WINDOWS_PER_RUN),
                        required_capture_policy_version=int(
                            getattr(paper2_config, "PAPER_CONTRACT_VERSION", 1)
                        ),
                    )
                    manifest.dataset["paper_eligible"] = bool(eligibility.paper_eligible)
                    manifest.dataset["paper_exclusion_primary_reason_code"] = eligibility.reason_code
                    manifest.dataset["paper_exclusion_all_reason_codes"] = list(
                        eligibility.all_reason_codes
                    )

                    update_dataset_tracker(manifest, run_dir, event_logger=event_logger)

                    # "countable" is quota-counted by construction. Determine it from the
                    # derived tracker markings (counts_toward_quota) rather than from
                    # operator choice or run order.
                    tracker_row: dict[str, object] | None = None
                    try:
                        tracker = load_dataset_tracker()
                        apps = tracker.get("apps") if isinstance(tracker, dict) else {}
                        pkg = (manifest.target.get("package_name") or "").strip()
                        app_entry = apps.get(pkg) if isinstance(apps, dict) and pkg else None
                        runs = app_entry.get("runs") if isinstance(app_entry, dict) else []
                        if isinstance(runs, list):
                            tracker_row = next(
                                (
                                    r
                                    for r in runs
                                    if isinstance(r, dict) and r.get("run_id") == manifest.dynamic_run_id
                                ),
                                None,
                            )
                    except Exception:
                        tracker_row = None

                    countable = None
                    if isinstance(tracker_row, dict):
                        countable = tracker_row.get("countable")
                        if not isinstance(countable, bool):
                            countable = bool(tracker_row.get("counts_toward_quota"))
                        manifest.dataset["paper_eligible"] = bool(tracker_row.get("paper_eligible"))
                        manifest.dataset["paper_exclusion_primary_reason_code"] = (
                            tracker_row.get("paper_exclusion_primary_reason_code")
                        )
                        all_codes = tracker_row.get("paper_exclusion_all_reason_codes")
                        manifest.dataset["paper_exclusion_all_reason_codes"] = (
                            list(all_codes) if isinstance(all_codes, list) else []
                        )
                    if isinstance(countable, bool):
                        manifest.dataset["countable"] = countable
                    else:
                        manifest.dataset.setdefault("countable", True)

                    verdict_source = tracker_row if isinstance(tracker_row, dict) else {
                        "valid_dataset_run": manifest.dataset.get("valid_dataset_run"),
                        "paper_eligible": manifest.dataset.get("paper_eligible"),
                        "countable": manifest.dataset.get("countable"),
                        "paper_exclusion_all_reason_codes": manifest.dataset.get(
                            "paper_exclusion_all_reason_codes"
                        ),
                    }
                    technical_validity, protocol_compliance, cohort_eligibility = (
                        derive_three_verdicts_for_row(verdict_source)
                    )
                    manifest.dataset["technical_validity"] = technical_validity
                    manifest.dataset["protocol_compliance"] = protocol_compliance
                    manifest.dataset["cohort_eligibility"] = cohort_eligibility
                    manifest.operator["technical_validity"] = technical_validity
                    manifest.operator["protocol_compliance"] = protocol_compliance
                    manifest.operator["cohort_eligibility"] = cohort_eligibility

                ds = manifest.dataset if isinstance(manifest.dataset, dict) else {}
                event_logger.log(
                    "dataset_validity",
                    {
                        "valid": bool(ds.get("valid_dataset_run")),
                        "invalid_reason_code": ds.get("invalid_reason_code"),
                        "min_pcap_bytes": ds.get("min_pcap_bytes"),
                        "sampling_duration_seconds": ds.get("sampling_duration_seconds"),
                        "short_run": ds.get("short_run"),
                        "no_traffic_observed": ds.get("no_traffic_observed"),
                        "countable": bool(ds.get("countable")),
                        "low_signal": bool(ds.get("low_signal")),
                        "technical_validity": ds.get("technical_validity"),
                        "protocol_compliance": ds.get("protocol_compliance"),
                        "cohort_eligibility": ds.get("cohort_eligibility"),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(
                    "Dataset validity computation failed",
                    extra={"dynamic_run_id": dynamic_run_id, "error": str(exc)},
                )
                event_logger.log("dataset_validity_error", {"error": str(exc)})
            # Fail-closed: dataset-tier runs must never leave validity unset.
            if isinstance(manifest.dataset, dict) and manifest.dataset.get("valid_dataset_run") is None:
                manifest.dataset.update(
                    {
                        "valid_dataset_run": False,
                        "invalid_reason_code": "PCAP_PARSE_ERROR",
                        "countable": bool(manifest.dataset.get("countable", True)),
                    }
                )

        # Finalize structured event log *after* all analysis steps that emit events.
        # This prevents SHA mismatches for the run_events artifact.
        event_artifact = event_logger.finalize()
        if event_artifact:
            manifest.add_artifacts([event_artifact])
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
                sha256=None,
                size_bytes=plan_path.stat().st_size,
                produced_by="dynamic_orchestrator",
            )
        profile_key = None
        if plan_payload and isinstance(plan_payload, dict):
            profile_key = (
                plan_payload.get("profile_key")
                or plan_payload.get("profile")
                or plan_payload.get("scope_label")
            )
        static_context = compute_static_context(plan_payload if isinstance(plan_payload, dict) else None)
        static_tags = static_context.get("tags") if isinstance(static_context, dict) else []
        manifest = RunManifest(
            run_manifest_version=1,
            dynamic_run_id=run_ctx.dynamic_run_id,
            created_at=created_at,
            batch_id=getattr(run_ctx, "batch_id", None),
            dataset={
                "tier": self.config.tier,
                "countable": (
                    bool(run_ctx.counts_toward_completion)
                    if getattr(run_ctx, "counts_toward_completion", None) is not None
                    else str(self.config.tier).lower() == "dataset"
                ),
                # Filled deterministically at finalize-time for dataset-tier runs.
                "valid_dataset_run": None,
                "invalid_reason_code": None,
                "min_pcap_bytes": int(getattr(paper2_config, "MIN_PCAP_BYTES", 50000)),
                "short_run": 0,
                "no_traffic_observed": 0,
                "capture_policy_version": int(getattr(paper2_config, "PAPER_CONTRACT_VERSION", 1)),
                # ML-only quality flag (non-invalidating). Filled best-effort at finalize-time.
                "low_signal": None,
                "low_signal_reasons": [],
            },
            qa={},
            target={
                "run_type": "dynamic",
                "package_name": run_ctx.package_name,
                "duration_seconds": run_ctx.duration_seconds,
                "static_run_id": self.config.static_run_id,
                "dep_static_run_id": self.config.static_run_id,
                "harvest_session_id": self.config.harvest_session_id,
                "profile_key": profile_key,
                "run_intent": getattr(run_ctx, "run_profile", None),
                "static_plan_path": plan_artifact.relative_path if plan_artifact else None,
                "static_plan_summary": self._summarize_plan(plan_payload),
                "static_context_tags": static_tags,
                "static_context": static_context,
                "run_identity": (
                    dict(plan_payload.get("run_identity"))
                    if isinstance(plan_payload, dict) and isinstance(plan_payload.get("run_identity"), dict)
                    else None
                ),
                "identity_checked_at_start_utc": None,
                "identity_checked_at_end_utc": None,
                "identity_checked_at_gate_utc": None,
                "identity_start": None,
                "identity_end": None,
                "identity_gate": None,
            },
            environment={
                "device_serial": run_ctx.device_serial,
                "host": platform.node(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                # Frozen execution config (no env reads in execution paths).
                "require_dynamic_schema": bool(getattr(self.config, "require_dynamic_schema", True)),
                "observer_prompts_enabled": bool(getattr(self.config, "observer_prompts_enabled", False)),
                "pcapdroid_api_key_present": bool(getattr(self.config, "pcapdroid_api_key", None)),
                # Host toolchain audit payload for reproducibility. This is not a gate here
                # (dataset-tier gating happens earlier), but recording it avoids "version drift"
                # ambiguity when reviewing frozen evidence packs.
                "host_tools": collect_host_tools(),
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
                "tool_version": app_config.APP_VERSION,
                "tool_semver": app_config.APP_VERSION,
                "capture_policy_version": int(getattr(paper2_config, "PAPER_CONTRACT_VERSION", 1)),
                "paper_contract_version": str(PAPER_MODE_CONTRACT_VERSION),
                "paper_contract_hash": str(paper_contract_hash(build_paper_contract_snapshot())),
                "interaction_protocol_version": int(SCRIPT_PROTOCOL_VERSION),
                "template_id": None,
                "template_hash": None,
                "template_map_version": None,
                "template_map_hash": None,
                "baseline_protocol_id": None,
                "baseline_protocol_version": None,
                "baseline_protocol_hash": None,
                "script_name": None,
                "script_hash": None,
                "step_count": None,
                "step_count_planned": None,
                "step_count_completed": None,
                "script_exit_code": None,
                "script_end_marker": None,
                "script_timing_within_tolerance": None,
                "call_type": None,
                "call_attempted": None,
                "call_connected": None,
                "call_connect_latency_s": None,
                "call_connected_duration_s": None,
                "call_end_reason": None,
                "target_duration_s": int(getattr(app_config, "DYNAMIC_TARGET_DURATION_S", 180)),
                "actual_duration_s": None,
                "tool_git_commit": get_git_commit(),
                "schema_version": db_diagnostics.get_schema_version() or "<unknown>",
                "host_tools": collect_host_tools(),
                # Operator protocol metadata (not used for behavioral modeling).
                "run_intent": getattr(run_ctx, "run_profile", None),
                "run_profile": getattr(run_ctx, "run_profile", None),
                "run_sequence": getattr(run_ctx, "run_sequence", None),
                "messaging_activity": getattr(run_ctx, "messaging_activity", None),
                "counts_toward_completion": getattr(run_ctx, "counts_toward_completion", None),
                # RunContext snapshot: immutable execution context for reproducibility.
                "run_context": {
                    "interactive": bool(run_ctx.interactive),
                    "tier": self.config.tier,
                    "sampling_rate_s": self.config.sampling_rate_s,
                    "min_pcap_bytes": int(getattr(paper2_config, "MIN_PCAP_BYTES", 50000)),
                    "require_dynamic_schema": bool(getattr(self.config, "require_dynamic_schema", True)),
                    "observer_prompts_enabled": bool(getattr(self.config, "observer_prompts_enabled", False)),
                    "pcapdroid_api_key_present": bool(getattr(self.config, "pcapdroid_api_key", None)),
                    "duration_seconds": run_ctx.duration_seconds,
                    "scenario_id": run_ctx.scenario_id,
                    "device_serial": run_ctx.device_serial,
                    "observer_ids": [observer.observer_id for observer in self.observers],
                    "enable_monitor": bool(getattr(self.config, "enable_monitor", False)),
                    "monitor_verbose": bool(getattr(self.config, "monitor_verbose", False)),
                    "batch_id": getattr(run_ctx, "batch_id", None),
                    "run_profile": getattr(run_ctx, "run_profile", None),
                    "run_sequence": getattr(run_ctx, "run_sequence", None),
                    "messaging_activity": getattr(run_ctx, "messaging_activity", None),
                    "counts_toward_completion": getattr(run_ctx, "counts_toward_completion", None),
                    "static_context_tags": static_tags,
                },
            },
        )
        if plan_artifact:
            manifest.add_artifacts([plan_artifact])
        dep_artifact = self._attach_dep_snapshot(run_ctx, writer, manifest)
        if dep_artifact:
            manifest.add_artifacts([dep_artifact])
            manifest.target["dep_snapshot_path"] = dep_artifact.relative_path
        return manifest

    def _attach_dep_snapshot(
        self,
        run_ctx: RunContext,
        writer: EvidencePackWriter,
        manifest: RunManifest,
    ) -> ArtifactRecord | None:
        if not run_ctx.static_run_id:
            return None
        try:
            row = core_q.run_sql(
                """
                SELECT a.package_name, sar.sha256, sar.base_apk_sha256
                FROM static_analysis_runs sar
                JOIN app_versions av ON av.id = sar.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE sar.id=%s
                """,
                (run_ctx.static_run_id,),
                fetch="one",
            )
        except Exception:
            row = None
        package_name = run_ctx.package_name
        if row:
            package_name = row[0] or package_name
        dep_path = Path("evidence") / "static_runs" / str(run_ctx.static_run_id) / "dep.json"
        if not dep_path.exists():
            note = (
                "DEP snapshot missing; expected "
                f"{dep_path} for static_run_id={run_ctx.static_run_id}"
            )
            self.logger.warning(note)
            manifest.notes.append(note)
            return None
        dest_path = writer.run_dir / "artifacts/dep/dep.json"
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dep_path, dest_path)
        return ArtifactRecord(
            relative_path=str(dest_path.relative_to(writer.run_dir)),
            type="dep_snapshot",
            sha256=None,
            size_bytes=dest_path.stat().st_size,
            produced_by="static_analysis",
        )

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
                error_path.write_text(str(exc), encoding="utf-8")
                artifact = ArtifactRecord(
                    relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                    type="observer_error",
                    sha256=None,
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
            error_path.write_text(str(exc), encoding="utf-8")
            artifact = ArtifactRecord(
                relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                type="observer_error",
                sha256=None,
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
                adb_shell.run_shell(
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
        return ArtifactRecord(
            relative_path=str(marker_path.relative_to(run_ctx.run_dir)),
            type="run_markers",
            sha256=None,
            size_bytes=marker_path.stat().st_size,
            produced_by="orchestrator",
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def _capture_device_clock(self, serial: str | None) -> dict[str, object] | None:
        if not serial:
            return None
        try:
            device_epoch = adb_shell.run_shell(serial, ["date", "+%s"]).strip()
            device_dt = datetime.fromtimestamp(float(device_epoch), tz=UTC)
        except Exception:
            device_dt = None
        try:
            uptime_raw = adb_shell.run_shell(serial, ["cat", "/proc/uptime"]).strip().split()[0]
            uptime_ms = int(float(uptime_raw) * 1000)
        except Exception:
            uptime_ms = None
        if device_dt is None and uptime_ms is None:
            return None
        return {"device_time_utc": device_dt, "device_uptime_ms": uptime_ms}

    @staticmethod
    def _format_clock_payload(
        host_start: datetime,
        host_end: datetime,
        clock_start: dict[str, object] | None,
        clock_end: dict[str, object] | None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "host_time_utc_start": host_start.isoformat(),
            "host_time_utc_end": host_end.isoformat(),
        }
        if clock_start:
            if clock_start.get("device_time_utc"):
                payload["device_time_utc_start"] = clock_start["device_time_utc"].isoformat()
            if clock_start.get("device_uptime_ms") is not None:
                payload["device_uptime_ms_start"] = clock_start["device_uptime_ms"]
        if clock_end:
            if clock_end.get("device_time_utc"):
                payload["device_time_utc_end"] = clock_end["device_time_utc"].isoformat()
            if clock_end.get("device_uptime_ms") is not None:
                payload["device_uptime_ms_end"] = clock_end["device_uptime_ms"]
        try:
            if payload.get("device_time_utc_start"):
                device_start = datetime.fromisoformat(str(payload["device_time_utc_start"]))
                payload["drift_ms_start"] = int(
                    (host_start - device_start).total_seconds() * 1000
                )
            if payload.get("device_time_utc_end"):
                device_end = datetime.fromisoformat(str(payload["device_time_utc_end"]))
                payload["drift_ms_end"] = int((host_end - device_end).total_seconds() * 1000)
        except Exception:
            pass
        return payload

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
            if getattr(validation, "is_pass", False):
                print(status_messages.status("Plan validation: PASS (baseline shown above).", level="success"))
            else:
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
        domain_sources = (
            network.get("domain_sources") if isinstance(network.get("domain_sources"), list) else []
        )
        cleartext = network.get("cleartext_domains") if isinstance(network.get("cleartext_domains"), list) else []
        return {
            "declared_permissions_count": len(declared),
            "dangerous_permissions_count": len(dangerous),
            "high_value_permissions_count": len(high_value),
            "network_targets_count": len(domains),
            "network_targets_sample": sorted(domains)[:5],
            "network_targets_all": sorted(domains),
            "domain_sources": domain_sources,
            "cleartext_targets_sample": sorted(cleartext)[:5],
            "risk_flags": risk_flags,
        }

    def _build_permission_trigger_hint(self, plan_payload: dict[str, object] | None) -> str | None:
        if not plan_payload:
            return None
        perms = plan_payload.get("permissions") if isinstance(plan_payload.get("permissions"), dict) else {}
        high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
        if high_value:
            return (
                "Optional capabilities to exercise: Location, Camera, Microphone, Contacts, Notifications/IPC. "
                "Press P to view raw permission names."
            )
        return None


__all__ = ["DynamicRunOrchestrator"]
