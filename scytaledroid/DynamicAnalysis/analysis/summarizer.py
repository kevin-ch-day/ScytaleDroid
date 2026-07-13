"""Post-processing summarizer for dynamic analysis runs."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.run_qualification import qualification_fields_from_dataset
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.security_surface import compute_static_dynamic_cleartext_posture
from scytaledroid.DynamicAnalysis.utils.messaging_activity_labels import messaging_activity_label
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality


class DynamicRunSummarizer:
    def __init__(self, writer: EvidencePackWriter) -> None:
        self.writer = writer

    def summarize(self, manifest: RunManifest) -> list[ArtifactRecord]:
        summary = self._build_summary(manifest)
        summary_path = self.writer.write_json("analysis/summary.json", summary)
        summary_md_path = self.writer.write_text(
            "analysis/summary.md",
            self._render_summary_md(summary),
        )
        return [
            self._artifact_record(
                summary_path,
                "analysis_summary_json",
                "summarizer",
            ),
            self._artifact_record(
                summary_md_path,
                "analysis_summary_md",
                "summarizer",
            ),
        ]

    def _build_summary(self, manifest: RunManifest) -> dict[str, Any]:
        pcap_report = self._load_pcap_report()
        pcap_features = self._load_pcap_features()
        destinations = self._load_destinations(manifest, pcap_report=pcap_report)
        service_context = (
            pcap_report.get("service_context")
            if isinstance(pcap_report.get("service_context"), dict)
            else {}
        )
        service_signals = (
            pcap_report.get("service_signals")
            if isinstance(pcap_report.get("service_signals"), dict)
            else {}
        )
        media_plane = (
            pcap_report.get("media_plane")
            if isinstance(pcap_report.get("media_plane"), dict)
            else {}
        )
        runtime_surfaces = self._load_runtime_surfaces()
        fingerprint_summary = self._fingerprint_summary(pcap_report, pcap_features)
        cleartext_flag = self._detect_cleartext(destinations, pcap_report)
        cleartext_protocol_flag = self._detect_cleartext_protocol(pcap_report)
        security_surface = (
            pcap_report.get("security_surface")
            if isinstance(pcap_report.get("security_surface"), dict)
            else {}
        )
        cleartext_posture = self._load_cleartext_posture(pcap_report)
        notable_logs = self._scan_log_signals(manifest)
        tls_mitm = "true" if "SSLHandshakeException" in notable_logs else "false"
        pcap_meta = self._load_pcap_meta(manifest)
        network_present = self._network_capture_present(manifest, pcap_meta)
        evidence_sizes = self._evidence_sizes(manifest)
        capture_sources, capture_bytes = self._capture_sources(manifest)
        pcap_available = pcap_meta.get("pcap_available")
        pcap_valid_raw = pcap_meta.get("pcap_valid")
        capture_mode = pcap_meta.get("capture_mode")
        pcap_size_bytes = (
            _safe_int(pcap_meta.get("pcap_size_bytes"))
            or _safe_int(pcap_report.get("pcap_size_bytes"))
            or capture_bytes
        )
        static_plan = manifest.target.get("static_plan_summary") if isinstance(manifest.target, dict) else None
        telemetry_stats = None
        telemetry_counts = None
        telemetry_schema_version = None
        if isinstance(manifest.operator, dict):
            telemetry_stats = manifest.operator.get("telemetry_stats")
            telemetry_counts = manifest.operator.get("telemetry_counts")
            telemetry_schema_version = manifest.operator.get("telemetry_schema_version")
        tier = None
        if isinstance(manifest.operator, dict):
            tier = manifest.operator.get("tier")
        stored_quality = None
        if isinstance(telemetry_stats, dict):
            stored_quality = telemetry_stats.get("network_signal_quality")
        netstats_rows = int((telemetry_stats or {}).get("netstats_rows") or 0) if telemetry_stats else 0
        netstats_missing = int((telemetry_stats or {}).get("netstats_missing_rows") or 0) if telemetry_stats else 0
        netstats_in = (telemetry_stats or {}).get("netstats_bytes_in_total") if telemetry_stats else None
        netstats_out = (telemetry_stats or {}).get("netstats_bytes_out_total") if telemetry_stats else None
        dataset = manifest.dataset if isinstance(manifest.dataset, dict) else {}
        operator = manifest.operator if isinstance(manifest.operator, dict) else {}
        pcap_size_bytes = _safe_int(dataset.get("pcap_size_bytes")) or pcap_size_bytes
        if pcap_available is None and dataset.get("pcap_available") is not None:
            pcap_available = bool(dataset.get("pcap_available"))
        pcap_failure_detail = self._pcap_failure_detail(
            dataset=dataset,
            pcap_meta=pcap_meta,
            pcap_size_bytes=pcap_size_bytes,
        )
        pcap_valid = self._effective_pcap_valid(
            dataset=dataset,
            pcap_available=pcap_available,
            pcap_size_bytes=pcap_size_bytes,
            pcap_valid_raw=pcap_valid_raw,
            pcap_failure_detail=pcap_failure_detail,
        )
        invalid_reason = str(dataset.get("invalid_reason_code") or "").strip() or None
        if not invalid_reason and dataset.get("valid_dataset_run") is True and dataset.get("countable") is False:
            invalid_reason = str(dataset.get("paper_exclusion_primary_reason_code") or "").strip() or None
        network_signal_quality = evaluate_network_signal_quality(
            netstats_rows=netstats_rows,
            netstats_missing_rows=netstats_missing,
            sum_bytes_in=_safe_int(netstats_in),
            sum_bytes_out=_safe_int(netstats_out),
            pcap_present=pcap_valid is True,
            pcap_bytes=_safe_int(pcap_size_bytes),
        )
        telemetry_quality = self._telemetry_quality(telemetry_stats)
        if isinstance(telemetry_stats, dict):
            netstats_available = telemetry_stats.get("netstats_available")
            if netstats_available is not None:
                telemetry_quality["netstats_available"] = bool(netstats_available)
        if telemetry_quality.get("netstats_available") is False:
            telemetry_quality["netstats_warning"] = "netstats_unavailable"
        netstats_missing_rows = int((telemetry_stats or {}).get("netstats_missing_rows") or 0) if telemetry_stats else 0
        if netstats_missing_rows:
            telemetry_quality["netstats_warning"] = "netstats_missing"
        if network_signal_quality == "netstats_zero_bytes":
            telemetry_quality["netstats_warning"] = "netstats_zero_bytes"
        countability_reason = self._countability_reason(
            dataset=dataset,
            run_profile=operator.get("run_profile"),
            invalid_reason=invalid_reason,
        )
        countability_label = self._countability_label(
            dataset=dataset,
            run_profile=operator.get("run_profile"),
            invalid_reason=invalid_reason,
        )
        qualification = qualification_fields_from_dataset(dataset)
        dataset_verdict = (
            "VALID"
            if dataset.get("valid_dataset_run") is True
            else "INVALID"
            if dataset.get("valid_dataset_run") is False
            else None
        )
        target = manifest.target if isinstance(manifest.target, dict) else {}
        top_dns = pcap_report.get("top_dns") if isinstance(pcap_report.get("top_dns"), list) else []
        top_sni = pcap_report.get("top_sni") if isinstance(pcap_report.get("top_sni"), list) else []
        top_alpn = fingerprint_summary.get("top_alpn") if isinstance(fingerprint_summary.get("top_alpn"), list) else []
        service_family_names = self._service_family_names(service_context)
        quota_window_metrics = (
            pcap_features.get("window_metrics")
            if isinstance(pcap_features.get("window_metrics"), dict)
            else {}
        )
        startup_profile = (
            pcap_features.get("startup_profile", {}).get("summary")
            if isinstance(pcap_features.get("startup_profile"), dict)
            and isinstance(pcap_features.get("startup_profile", {}).get("summary"), dict)
            else {}
        )
        interaction_level = operator.get("interaction_level")
        interaction_mode = self._interaction_mode(
            run_profile=operator.get("run_profile"),
            interaction_level=interaction_level,
        )
        call_metadata = self._call_metadata(operator=operator, media_plane=media_plane)
        return {
            "dynamic_run_id": manifest.dynamic_run_id,
            "status": manifest.status,
            "tier": tier,
            "run_profile": operator.get("run_profile"),
            "interaction_level": interaction_level,
            "interaction_mode": interaction_mode,
            "messaging_activity": operator.get("messaging_activity"),
            "call_type": call_metadata.get("call_type"),
            "call_attempted": call_metadata.get("call_attempted"),
            "call_connected": call_metadata.get("call_connected"),
            "call_connected_duration_s": call_metadata.get("call_connected_duration_s"),
            "call_outcome_reason": call_metadata.get("call_outcome_reason"),
            "call_outcome_flag": call_metadata.get("call_outcome_flag"),
            "call_primary_outcome_reason": call_metadata.get("call_primary_outcome_reason"),
            "call_attempt_count": call_metadata.get("call_attempt_count"),
            "call_connected_count": call_metadata.get("call_connected_count"),
            "call_not_connected_count": call_metadata.get("call_not_connected_count"),
            "call_connected_short_count": call_metadata.get("call_connected_short_count"),
            "call_canceled_count": call_metadata.get("call_canceled_count"),
            "call_outcome_summary": call_metadata.get("call_outcome_summary"),
            "call_outcome_events": call_metadata.get("call_outcome_events"),
            "call_activity_inferred_from_foreground": call_metadata.get(
                "call_activity_inferred_from_foreground"
            ),
            "call_activity_original_tag": call_metadata.get("call_activity_original_tag"),
            "call_activity_foreground_component": call_metadata.get(
                "call_activity_foreground_component"
            ),
            "package_name": target.get("package_name"),
            "version_code": target.get("version_code"),
            "version_name": target.get("version_name"),
            "dataset_verdict": dataset_verdict,
            "countable": dataset.get("countable"),
            "counts_toward_quota": dataset.get("countable"),
            "countability_reason": countability_reason,
            "exploratory_class": dataset.get("exploratory_class"),
            "cohort_eligibility": dataset.get("cohort_eligibility"),
            "pcap_bytes": pcap_size_bytes,
            "pcap_failure_detail": pcap_failure_detail,
            "capture_duration_s": dataset.get("actual_sampling_seconds"),
            "capinfos_capture_duration_s": pcap_report.get("capture_duration_s"),
            "pcap_valid": pcap_valid,
            "domain_count": len(destinations),
            "domains_count": len(destinations),
            "dns_count": _safe_int(pcap_report.get("dns_unique_count")) or len(top_dns),
            "sni_count": _safe_int(pcap_report.get("sni_unique_count")) or len(top_sni),
            "service_families_observed": ", ".join(service_family_names) if service_family_names else None,
            "unique_service_families": len(service_family_names),
            "tls_client_hello_count": _safe_int(fingerprint_summary.get("client_hello_count")),
            "tls_server_hello_count": _safe_int(fingerprint_summary.get("server_hello_count")),
            "unique_ja3_count": _safe_int(fingerprint_summary.get("unique_ja3_count")),
            "unique_ja3s_count": _safe_int(fingerprint_summary.get("unique_ja3s_count")),
            "unique_ja4_count": _safe_int(fingerprint_summary.get("unique_ja4_count")),
            "top_alpn": top_alpn,
            "top_ja3": fingerprint_summary.get("top_ja3") if isinstance(fingerprint_summary.get("top_ja3"), list) else [],
            "top_ja3s": fingerprint_summary.get("top_ja3s") if isinstance(fingerprint_summary.get("top_ja3s"), list) else [],
            "top_ja4": fingerprint_summary.get("top_ja4") if isinstance(fingerprint_summary.get("top_ja4"), list) else [],
            "top_dns": top_dns,
            "top_sni": top_sni,
            "quota_detail": {
                "countable": dataset.get("countable"),
                "countability_label": countability_label,
                "cohort_eligibility": dataset.get("cohort_eligibility"),
                "invalid_reason_code": invalid_reason,
                "pcap_failure_detail": pcap_failure_detail,
                "exploratory_class": dataset.get("exploratory_class"),
                "baseline_not_idle": dataset.get("baseline_not_idle"),
                "baseline_not_idle_reasons": dataset.get("baseline_not_idle_reasons") or [],
            },
            "evidence_qualification": qualification,
            "verdicts": {
                "technical": dataset_verdict,
                "protocol": "COMPLIANT" if dataset_verdict == "VALID" else ("NON_COMPLIANT" if dataset_verdict == "INVALID" else None),
                "cohort": dataset.get("cohort_eligibility"),
            },
            "dataset": dataset,
            "target": target,
            "environment": manifest.environment,
            "scenario": manifest.scenario,
            "observers": [asdict(observer) for observer in manifest.observers],
            "destinations_observed": destinations,
            "indicators": {
                "top_dns": top_dns,
                "top_sni": top_sni,
                "top_alpn": top_alpn,
                "runtime_surfaces": runtime_surfaces,
                "service_context": service_context,
                "service_signals": service_signals,
                "media_plane": media_plane,
                "tls_fingerprints": fingerprint_summary,
                "security_surface": {
                    "status": security_surface.get("status"),
                    "finding_count": security_surface.get("finding_count"),
                    "risk_flags": security_surface.get("risk_flags") or [],
                    "findings": (security_surface.get("findings") or [])[:10],
                    "cleartext": (
                        security_surface.get("cleartext")
                        if isinstance(security_surface.get("cleartext"), dict)
                        else {}
                    ),
                },
                "cleartext_posture": cleartext_posture,
            },
            "telemetry": {
                "schema_version": telemetry_schema_version,
                "counts": telemetry_counts,
                "stats": telemetry_stats,
                "quality": telemetry_quality,
                "network_signal_quality": network_signal_quality,
                "network_signal_quality_stored": stored_quality,
                "network_signal_quality_computed": network_signal_quality,
                "network_quality_mismatch": bool(
                    stored_quality
                    and isinstance(stored_quality, str)
                    and network_signal_quality
                    and stored_quality != network_signal_quality
                ),
            },
            "flags": {
                "network_capture_present": network_present,
                "cleartext_http_detected": cleartext_flag,
                "cleartext_protocol_detected": cleartext_protocol_flag,
                "tls_mitm_suspected": tls_mitm,
                "notable_log_signals": notable_logs,
                "static_watchlist_used": bool(static_plan),
                "capture_sources": capture_sources,
                "security_finding_count": security_surface.get("finding_count"),
                "security_risk_flags": security_surface.get("risk_flags") or [],
                "cleartext_mismatch_class": cleartext_posture.get("mismatch_class"),
            },
            "static_watchlist": static_plan,
            "capture": {
                "sources": capture_sources,
                "total_bytes": capture_bytes,
                "pcap_available": pcap_available,
                "pcap_size_bytes": pcap_size_bytes,
                "pcap_valid": pcap_valid,
                "capture_mode": capture_mode,
                "network_signal_quality": network_signal_quality,
                "evidence_sizes": evidence_sizes,
                "quota_window_metrics": quota_window_metrics,
                "startup_profile": startup_profile,
            },
            "evidence": [
                {
                    "relative_path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "type": artifact.type,
                    "size_bytes": artifact.size_bytes,
                    "produced_by": artifact.produced_by,
                }
                for artifact in manifest.artifacts
            ],
        }

    def _render_summary_md(self, summary: dict[str, Any]) -> str:
        destinations = summary.get("destinations_observed", [])
        destinations_text = ", ".join(destinations) if destinations else "none recorded"
        telemetry = summary.get("telemetry", {}) or {}
        quality = telemetry.get("quality", {}) or {}
        environment = summary.get("environment", {}) or {}
        capture = summary.get("capture", {}) or {}
        capture_sources = capture.get("sources") or []
        capture_sources_text = ", ".join(capture_sources) if capture_sources else "none"
        capture_bytes = capture.get("total_bytes")
        capture_bytes_text = f"{capture_bytes} bytes" if isinstance(capture_bytes, int) else "unknown"
        capture_mode = capture.get("capture_mode") or "unknown"
        pcap_valid = capture.get("pcap_valid")
        pcap_valid_text = self._bool_text(pcap_valid)
        target = summary.get("target", {}) or {}
        quota_detail = summary.get("quota_detail", {}) or {}
        indicators = summary.get("indicators", {}) or {}
        cleartext_http_text = self._bool_text(summary.get("flags", {}).get("cleartext_http_detected"))
        cleartext_protocol_text = self._bool_text(summary.get("flags", {}).get("cleartext_protocol_detected"))
        network_capture_text = self._bool_text(summary.get("flags", {}).get("network_capture_present"))
        static_watchlist_text = self._bool_text(summary.get("flags", {}).get("static_watchlist_used"))
        invalid_reason_text = self._display_text(quota_detail.get("invalid_reason_code"))
        top_dns = indicators.get("top_dns") or []
        top_sni = indicators.get("top_sni") or []
        top_dns_text = self._top_indicator_text(top_dns)
        top_sni_text = self._top_indicator_text(top_sni)
        messaging_activity_text = messaging_activity_label(summary.get("messaging_activity"))
        call_type_text = self._display_text(summary.get("call_type"))
        call_attempted_text = self._bool_text(summary.get("call_attempted"))
        call_connected_text = self._bool_text(summary.get("call_connected"))
        call_outcome_text = self._display_text(summary.get("call_outcome_reason"))
        call_attempt_count = _safe_int(summary.get("call_attempt_count"))
        call_connected_count = _safe_int(summary.get("call_connected_count"))
        call_not_connected_count = _safe_int(summary.get("call_not_connected_count"))
        call_canceled_count = _safe_int(summary.get("call_canceled_count"))
        call_outcome_summary_text = self._display_text(summary.get("call_outcome_summary"))
        call_inferred_text = self._bool_text(summary.get("call_activity_inferred_from_foreground"))
        security = indicators.get("security_surface") or {}
        security_findings = security.get("findings") or []
        security_risk_flags = security.get("risk_flags") or []
        cleartext_surface = security.get("cleartext") or {}
        security_findings_text = self._security_findings_text(security_findings)
        security_risk_flags_text = ", ".join(security_risk_flags) if security_risk_flags else "none"
        cleartext_posture = indicators.get("cleartext_posture") or {}
        cleartext_mismatch_text = self._display_text(cleartext_posture.get("mismatch_summary"))
        runtime_surface_lines = self._runtime_surface_lines(indicators.get("runtime_surfaces"))
        quota_window_lines = self._quota_window_lines(capture.get("quota_window_metrics"))
        startup_profile_lines = self._startup_profile_lines(capture.get("startup_profile"))
        lines = [
            "# Dynamic Run Summary",
            "",
            f"- Run ID: {summary['dynamic_run_id']}",
            f"- Status: {summary['status']}",
            f"- Tier: {summary.get('tier', 'unknown')}.",
            f"- Scenario: {summary['scenario'].get('id', 'unknown')}",
            f"- Package: {target.get('package_name', 'unknown')}.",
            f"- Run profile: {summary.get('run_profile', 'unknown')}.",
            f"- Device: {environment.get('device_model', 'unknown')} / {environment.get('android_version', 'unknown')}.",
            f"- Security patch: {environment.get('security_patch_level', 'unknown')}.",
            f"- Play Services: {environment.get('play_services_version', 'unknown')}.",
            "",
            "## Observations",
            f"- Destinations observed: {destinations_text}.",
            f"- Cleartext HTTP detected: {cleartext_http_text}.",
            f"- Non-HTTP cleartext protocol metadata detected: {cleartext_protocol_text}.",
            f"- Network capture present: {network_capture_text}.",
            f"- Network capture sources: {capture_sources_text} ({capture_bytes_text}).",
            f"- Capture mode: {capture_mode}.",
            f"- PCAP valid: {pcap_valid_text}.",
            f"- Dataset verdict: {summary.get('dataset_verdict', 'unknown')}.",
            f"- Counts toward quota: {quota_detail.get('countability_label') or 'UNKNOWN'}.",
            f"- Cohort eligibility: {quota_detail.get('cohort_eligibility')}.",
            f"- Invalid reason: {invalid_reason_text}.",
            f"- Static watchlist used: {static_watchlist_text}.",
            f"- TLS MITM suspected: {self._bool_text(summary['flags'].get('tls_mitm_suspected'))}.",
            f"- Top DNS: {top_dns_text}.",
            f"- Top SNI: {top_sni_text}.",
        ]
        if str(summary.get("messaging_activity") or "").strip():
            lines.insert(8, f"- Messaging activity: {messaging_activity_text}.")
        if any(
            summary.get(field) is not None
            for field in ("call_type", "call_attempted", "call_connected", "call_outcome_reason")
        ):
            insert_at = 9 if str(summary.get("messaging_activity") or "").strip() else 8
            call_lines = [
                f"- Call type: {call_type_text}.",
                f"- Call attempted: {call_attempted_text}.",
                f"- Call connected: {call_connected_text}.",
                f"- Call outcome: {call_outcome_text}.",
            ]
            if call_attempt_count is not None:
                call_lines.append(f"- Call attempts observed by operator: {call_attempt_count}.")
            if call_connected_count is not None:
                call_lines.append(f"- Operator connected attempts: {call_connected_count}.")
            if call_not_connected_count is not None:
                call_lines.append(f"- Operator no-connect/ringing attempts: {call_not_connected_count}.")
            if call_canceled_count is not None:
                call_lines.append(f"- Operator canceled attempts: {call_canceled_count}.")
            if summary.get("call_outcome_summary"):
                call_lines.append(f"- Call outcome summary: {call_outcome_summary_text}.")
            if summary.get("call_activity_inferred_from_foreground") is not None:
                call_lines.append(f"- Call tag inferred from foreground: {call_inferred_text}.")
            if summary.get("call_activity_original_tag"):
                call_lines.append(
                    f"- Original messaging tag: {messaging_activity_label(summary.get('call_activity_original_tag'))}."
                )
            lines[insert_at:insert_at] = call_lines
        if quota_window_lines:
            lines.extend(["", "## Quota windows", *quota_window_lines])
        if startup_profile_lines:
            lines.extend(["", "## Startup profile", *startup_profile_lines])
        if runtime_surface_lines:
            lines.extend(["", "## Runtime surfaces", *runtime_surface_lines])
        lines.extend(
            [
                "",
                "## Security (metadata)",
                f"- Security surface status: {security.get('status') or 'unknown'}.",
                f"- Cleartext visibility: {cleartext_surface.get('visibility_class') or 'unknown'}.",
                f"- Security findings: {security.get('finding_count') if security.get('finding_count') is not None else 'unknown'}.",
                f"- Risk flags: {security_risk_flags_text}.",
                f"- Notable findings: {security_findings_text}.",
                f"- Static↔dynamic cleartext: {cleartext_mismatch_text}.",
                "",
                "## Telemetry",
                f"- Schema version: {summary.get('telemetry', {}).get('schema_version')}.",
                f"- Counts: {summary.get('telemetry', {}).get('counts')}.",
                f"- Stats: {summary.get('telemetry', {}).get('stats')}.",
                f"- Quality: {quality}.",
                f"- Network signal quality: {telemetry.get('network_signal_quality')}.",
                "",
                "## Evidence",
            ]
        )
        for item in summary.get("evidence", []):
            lines.append(f"- {item['relative_path']} ({item['sha256']})")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _bool_text(value: object) -> str:
        if value is True or str(value).strip().lower() == "true":
            return "yes"
        if value is False or str(value).strip().lower() == "false":
            return "no"
        return "unknown"

    @staticmethod
    def _display_text(value: object) -> str:
        text = str(value or "").strip()
        return text or "—"

    def _countability_label(
        self,
        *,
        dataset: dict[str, Any],
        run_profile: object,
        invalid_reason: str | None,
    ) -> str:
        if dataset.get("valid_dataset_run") is False:
            return f"NO ({str(invalid_reason or 'INVALID').strip() or 'INVALID'})"
        if dataset.get("countable") is True:
            return f"YES ({str(run_profile or 'dataset').strip() or 'dataset'})"
        profile_lc = str(run_profile or "").strip().lower()
        exclusion_reason = str(dataset.get("paper_exclusion_primary_reason_code") or "").strip().upper()
        cohort_eligibility = str(dataset.get("cohort_eligibility") or "").strip().upper()
        if dataset.get("low_signal") is True and profile_lc == "baseline_idle":
            return "NO (LOW_SIGNAL_IDLE)"
        if exclusion_reason == "EXCLUDED_MANUAL_NON_COHORT":
            return "NO (manual exploratory)"
        if cohort_eligibility == "EXTRA":
            return "NO (extra run)"
        if dataset.get("countable") is False:
            return "NO (extra run)"
        return "UNKNOWN"

    def _countability_reason(
        self,
        *,
        dataset: dict[str, Any],
        run_profile: object,
        invalid_reason: str | None,
    ) -> str | None:
        if dataset.get("valid_dataset_run") is False:
            return str(invalid_reason or "INVALID").strip() or "INVALID"
        if dataset.get("countable") is True:
            return None
        profile_lc = str(run_profile or "").strip().lower()
        exclusion_reason = str(dataset.get("paper_exclusion_primary_reason_code") or "").strip().upper()
        cohort_eligibility = str(dataset.get("cohort_eligibility") or "").strip().upper()
        if dataset.get("low_signal") is True and profile_lc == "baseline_idle":
            return "LOW_SIGNAL_IDLE"
        if exclusion_reason == "EXCLUDED_MANUAL_NON_COHORT":
            return exclusion_reason
        if cohort_eligibility == "EXTRA":
            return "EXTRA_RUN"
        if dataset.get("countable") is False:
            return exclusion_reason or "EXTRA_RUN"
        return invalid_reason

    @staticmethod
    def _interaction_mode(*, run_profile: object, interaction_level: object) -> str:
        profile = str(run_profile or "").strip().lower()
        level = str(interaction_level or "").strip().lower()
        if profile.startswith("baseline"):
            return "baseline"
        if "script" in profile:
            return "scripted"
        if "manual" in profile:
            return "manual"
        if level:
            return level
        if profile.startswith("interaction") or profile.startswith("interactive"):
            return "interactive"
        return "unknown"

    @staticmethod
    def _call_metadata(*, operator: dict[str, Any], media_plane: dict[str, Any]) -> dict[str, Any]:
        activity = str(operator.get("messaging_activity") or "").strip().lower()
        call_type = operator.get("call_type")
        if call_type in (None, "") and activity in {"voice_call", "video_call"}:
            call_type = "video" if activity == "video_call" else "voice"

        summary = media_plane.get("summary") if isinstance(media_plane.get("summary"), dict) else {}
        media_observed = bool(
            summary.get("rtc_call_observed")
            or summary.get("relay_media_likely")
            or _safe_int(summary.get("rtc_sustained_session_count"))
        )

        call_attempted = operator.get("call_attempted")
        if call_attempted is None and activity in {"voice_call", "video_call"}:
            call_attempted = True

        call_connected = operator.get("call_connected")
        if call_connected is None and media_observed:
            call_connected = True

        duration_s = operator.get("call_connected_duration_s")
        if duration_s is None and call_connected is True:
            inferred_duration = _safe_float(summary.get("rtc_max_session_duration_s"))
            if inferred_duration is not None and inferred_duration > 0:
                duration_s = inferred_duration

        outcome_reason = operator.get("call_outcome_reason")
        if not outcome_reason and media_observed:
            outcome_reason = "CALL_MEDIA_OBSERVED"

        call_attempt_count = _safe_int(operator.get("call_attempt_count"))
        call_connected_count = _safe_int(operator.get("call_connected_count"))
        call_not_connected_count = _safe_int(operator.get("call_not_connected_count"))
        call_connected_short_count = _safe_int(operator.get("call_connected_short_count"))
        call_canceled_count = _safe_int(operator.get("call_canceled_count"))
        if call_attempt_count is None and call_attempted is True:
            call_attempt_count = 1
        if call_connected_count is None:
            call_connected_count = (
                1
                if call_connected is True
                or outcome_reason in {"CALL_CONNECTED_OK", "CALL_CONNECTED_SHORT", "CALL_MEDIA_OBSERVED"}
                else 0
                if call_attempt_count is not None
                else None
            )
        if call_not_connected_count is None:
            call_not_connected_count = (
                1
                if outcome_reason == "CALL_NOT_CONNECTED"
                else 0
                if call_attempt_count is not None
                else None
            )
        if call_canceled_count is None:
            call_canceled_count = (
                1
                if outcome_reason == "CALL_CANCELED"
                else 0
                if call_attempt_count is not None
                else None
            )
        if call_connected_short_count is None:
            call_connected_short_count = (
                1
                if outcome_reason == "CALL_CONNECTED_SHORT"
                else 0
                if call_attempt_count is not None
                else None
            )
        call_outcome_summary = operator.get("call_outcome_summary")
        if not call_outcome_summary and call_attempt_count is not None:
            call_outcome_summary = _format_call_outcome_summary(
                attempt_count=call_attempt_count,
                connected_count=call_connected_count,
                not_connected_count=call_not_connected_count,
                canceled_count=call_canceled_count,
                connected_short_count=call_connected_short_count,
            )

        return {
            "call_type": call_type,
            "call_attempted": call_attempted,
            "call_connected": call_connected,
            "call_connected_duration_s": duration_s,
            "call_outcome_reason": outcome_reason,
            "call_outcome_flag": operator.get("call_outcome_flag"),
            "call_primary_outcome_reason": operator.get("call_primary_outcome_reason") or outcome_reason,
            "call_attempt_count": call_attempt_count,
            "call_connected_count": call_connected_count,
            "call_not_connected_count": call_not_connected_count,
            "call_connected_short_count": call_connected_short_count,
            "call_canceled_count": call_canceled_count,
            "call_outcome_summary": call_outcome_summary,
            "call_outcome_events": operator.get("call_outcome_events"),
            "call_activity_inferred_from_foreground": operator.get(
                "call_activity_inferred_from_foreground"
            ),
            "call_activity_original_tag": operator.get("call_activity_original_tag"),
            "call_activity_foreground_component": operator.get("call_activity_foreground_component"),
        }

    def _pcap_failure_detail(
        self,
        *,
        dataset: dict[str, Any],
        pcap_meta: dict[str, Any],
        pcap_size_bytes: int,
    ) -> str | None:
        raw = str(dataset.get("pcap_failure_detail") or "").strip()
        if dataset.get("valid_dataset_run") is True and not str(dataset.get("invalid_reason_code") or "").strip():
            return raw or None
        pcap_valid = pcap_meta.get("pcap_valid")
        size = int(pcap_size_bytes or 0)
        min_pcap_bytes = _safe_int(pcap_meta.get("min_pcap_bytes")) or _safe_int(dataset.get("min_pcap_bytes"))
        observed_too_small = (
            pcap_valid is False and size > 0 and min_pcap_bytes > 0 and size < min_pcap_bytes
        )
        if observed_too_small:
            return "PCAP_TOO_SMALL"
        if raw:
            return raw
        return None

    def _effective_pcap_valid(
        self,
        *,
        dataset: dict[str, Any],
        pcap_available: object,
        pcap_size_bytes: int,
        pcap_valid_raw: object,
        pcap_failure_detail: str | None,
    ) -> object:
        if pcap_valid_raw is False:
            if (
                dataset.get("valid_dataset_run") is True
                and not str(dataset.get("invalid_reason_code") or "").strip()
                and not pcap_failure_detail
                and bool(pcap_available)
                and int(pcap_size_bytes or 0) > 0
            ):
                return True
        return pcap_valid_raw

    def _artifact_record(self, path: Path, artifact_type: str, produced_by: str) -> ArtifactRecord:
        sha256 = self.writer.hash_file(path)
        return ArtifactRecord(
            relative_path=str(path.relative_to(self.writer.run_dir)),
            type=artifact_type,
            sha256=sha256,
            size_bytes=path.stat().st_size,
            produced_by=produced_by,
            origin="host",
            pull_status="n/a",
        )

    def _load_destinations(self, manifest: RunManifest, pcap_report: dict[str, Any] | None = None) -> list[str]:
        for artifact in manifest.artifacts:
            if artifact.type != "network_flow_summary":
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                payload = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            destinations = payload.get("destinations", [])
            if isinstance(destinations, list):
                return [str(item) for item in destinations]
        report = pcap_report if isinstance(pcap_report, dict) else self._load_pcap_report()
        return self._destinations_from_pcap_report(report)

    def _load_pcap_report(self) -> dict[str, Any]:
        report_path = self.writer.run_dir / "analysis" / "pcap_report.json"
        if not report_path.exists():
            return {}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _load_pcap_features(self) -> dict[str, Any]:
        features_path = self.writer.run_dir / "analysis" / "pcap_features.json"
        if not features_path.exists():
            return {}
        try:
            payload = json.loads(features_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _load_cleartext_posture(self, pcap_report: dict[str, Any]) -> dict[str, Any]:
        plan_path = self.writer.run_dir / "inputs" / "static_dynamic_plan.json"
        if not plan_path.exists():
            return {}
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(plan, dict):
            return {}
        return compute_static_dynamic_cleartext_posture(plan, pcap_report)

    def _fingerprint_summary(self, report: dict[str, Any], features: dict[str, Any]) -> dict[str, Any]:
        report_tls = report.get("tls_fingerprints")
        if isinstance(report_tls, dict):
            report_summary = report_tls.get("summary")
            if isinstance(report_summary, dict):
                return report_summary
        feature_fingerprints = features.get("fingerprints")
        if isinstance(feature_fingerprints, dict):
            feature_summary = feature_fingerprints.get("summary")
            if isinstance(feature_summary, dict):
                return feature_summary
        return {}

    @staticmethod
    def _service_family_names(service_context: dict[str, Any]) -> list[str]:
        if not isinstance(service_context, dict):
            return []
        names = {
            str(service.get("service_category") or "").strip()
            for service in (service_context.get("services") or [])
            if isinstance(service, dict) and str(service.get("service_category") or "").strip()
        }
        return sorted(names)

    def _top_indicator_text(self, items: list[dict[str, Any]]) -> str:
        out: list[str] = []
        for item in items[:3]:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            count = item.get("count")
            if not value:
                continue
            out.append(f"{value} ({count})" if count is not None else value)
        return ", ".join(out) if out else "none"

    def _quota_window_lines(self, payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        lines: list[str] = []
        for label in ("180s", "240s"):
            window = payload.get(label)
            if not isinstance(window, dict):
                continue
            lines.append(
                f"- {label}: {self._display_metric(window.get('total_bytes'))} bytes, "
                f"avg {self._display_metric(window.get('avg_bytes_per_sec'), precision=1)} B/s, "
                f"p95 {self._display_metric(window.get('bytes_per_second_p95'), precision=1)} B/s, "
                f"{self._display_metric(window.get('total_packets'))} packets, "
                f"active {self._display_metric(window.get('active_second_count'))}s."
            )
        return lines

    def _startup_profile_lines(self, payload: object) -> list[str]:
        if not isinstance(payload, dict) or not payload:
            return []
        lines: list[str] = []
        window_s = payload.get("window_s")
        startup_total_bytes = payload.get("startup_total_bytes")
        startup_byte_share = payload.get("startup_byte_share")
        post_start_median_bytes_per_min = payload.get("post_start_median_bytes_per_min")
        post_start_mean_bytes_per_min = payload.get("post_start_mean_bytes_per_min")
        startup_dominant = payload.get("startup_dominant")
        if window_s is not None and startup_total_bytes is not None:
            share_text = (
                f"{float(startup_byte_share) * 100.0:.1f}%"
                if isinstance(startup_byte_share, (int, float))
                else "unknown"
            )
            lines.append(
                f"- First {self._display_metric(window_s)}s: "
                f"{self._display_metric(startup_total_bytes)} bytes ({share_text} of observed bytes)."
            )
        if post_start_median_bytes_per_min is not None or post_start_mean_bytes_per_min is not None:
            lines.append(
                f"- Post-start tail: median {self._display_metric(post_start_median_bytes_per_min, precision=1)} B/min, "
                f"mean {self._display_metric(post_start_mean_bytes_per_min, precision=1)} B/min."
            )
        if startup_dominant is not None:
            lines.append(f"- Startup dominant: {'yes' if bool(startup_dominant) else 'no'}.")
        return lines

    def _runtime_surface_lines(self, payload: object) -> list[str]:
        if not isinstance(payload, dict) or not payload:
            return []
        lines: list[str] = []
        labels = payload.get("labels")
        if isinstance(labels, list) and labels:
            rendered = [str(item).strip() for item in labels if str(item).strip()]
            if rendered:
                lines.append(f"- Observed surfaces: {', '.join(rendered)}.")
        primary_label = str(payload.get("primary_label") or "").strip()
        primary_detail = str(payload.get("primary_detail") or "").strip()
        if primary_label:
            primary_text = primary_label
            if primary_detail:
                primary_text += f" ({primary_detail})"
            lines.append(f"- Primary surface: {primary_text}.")
        transitions = payload.get("transitions")
        if isinstance(transitions, list) and transitions:
            rendered_steps: list[str] = []
            for row in transitions[:5]:
                if not isinstance(row, dict):
                    continue
                label = str(row.get("surface_label") or "").strip()
                if not label:
                    continue
                at = self._display_metric(row.get("elapsed_s"))
                detail = str(row.get("surface_detail") or "").strip()
                text = f"{at}s {label}"
                if detail:
                    text += f" ({detail})"
                rendered_steps.append(text)
            if rendered_steps:
                lines.append(f"- Surface sequence: {' -> '.join(rendered_steps)}.")
        return lines

    @staticmethod
    def _display_metric(value: object, *, precision: int = 0) -> str:
        if value is None:
            return "unknown"
        if isinstance(value, bool):
            return "1" if value else "0"
        try:
            if precision <= 0:
                return str(int(round(float(value))))
            return f"{float(value):.{precision}f}"
        except (TypeError, ValueError):
            return str(value)

    def _detect_cleartext(self, destinations: list[str], pcap_report: dict[str, Any] | None = None) -> str:
        from_surface = self._cleartext_from_security_surface(pcap_report or {})
        if from_surface is not None:
            return from_surface
        if not destinations:
            return "unknown"
        has_port_hint = False
        for entry in destinations:
            if ":" in entry or entry.rsplit(".", 1)[-1].isdigit():
                has_port_hint = True
            if entry.endswith(".80") or entry.endswith(":80"):
                return "true"
        return "false" if has_port_hint else "unknown"

    @staticmethod
    def _cleartext_from_security_surface(report: dict[str, Any]) -> str | None:
        surface = report.get("security_surface")
        if not isinstance(surface, dict) or surface.get("status") != "ok":
            return None
        cleartext = surface.get("cleartext")
        if not isinstance(cleartext, dict):
            return None
        if cleartext.get("http_observed"):
            return "true"
        if (
            cleartext.get("cleartext_protocol_observed")
            or _safe_int(cleartext.get("plaintext_protocol_frames"))
            or _safe_int(cleartext.get("decoded_stream_count"))
        ):
            return "false"
        visibility = str(cleartext.get("visibility_class") or "").strip()
        if visibility == "encrypted_or_opaque_dominant":
            return "false"
        return None

    def _detect_cleartext_protocol(self, report: dict[str, Any]) -> str:
        surface = report.get("security_surface") if isinstance(report, dict) else None
        if not isinstance(surface, dict) or surface.get("status") != "ok":
            return "unknown"
        cleartext = surface.get("cleartext")
        if not isinstance(cleartext, dict):
            return "unknown"
        observed = bool(
            cleartext.get("cleartext_protocol_observed")
            or _safe_int(cleartext.get("plaintext_protocol_frames"))
            or _safe_int(cleartext.get("decoded_stream_count"))
        )
        return "true" if observed else "false"

    @staticmethod
    def _security_findings_text(findings: list[dict[str, Any]]) -> str:
        out: list[str] = []
        for item in findings[:5]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip()
            severity = str(item.get("severity") or "").strip()
            if not title:
                continue
            out.append(f"{title} [{severity}]" if severity else title)
        return "; ".join(out) if out else "none"

    def _destinations_from_pcap_report(self, report: dict[str, Any]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []

        def _append(value: object) -> None:
            text = str(value or "").strip()
            if not text or text in seen:
                return
            seen.add(text)
            ordered.append(text)

        for key in ("top_dns", "top_sni"):
            items = report.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                _append(item.get("value"))

        service_context = report.get("service_context")
        if isinstance(service_context, dict):
            for service in service_context.get("services") or []:
                if not isinstance(service, dict):
                    continue
                for domain in service.get("domains") or []:
                    if not isinstance(domain, dict):
                        continue
                    _append(domain.get("domain"))
            for unresolved in service_context.get("unresolved_domains") or []:
                if isinstance(unresolved, dict):
                    _append(unresolved.get("domain"))
                else:
                    _append(unresolved)

        return ordered

    def _evidence_sizes(self, manifest: RunManifest) -> dict[str, int]:
        sizes: dict[str, int] = {}
        for artifact in manifest.artifacts:
            if artifact.size_bytes is None:
                continue
            sizes[artifact.type] = sizes.get(artifact.type, 0) + int(artifact.size_bytes)
        return sizes

    def _capture_sources(self, manifest: RunManifest) -> tuple[list[str], int | None]:
        sources: list[str] = []
        total_bytes: int = 0
        found_size = False
        for artifact in manifest.artifacts:
            if artifact.type != "pcapdroid_capture":
                continue
            sources.append("pcapdroid")
            if artifact.size_bytes is not None:
                total_bytes += int(artifact.size_bytes)
                found_size = True
        unique_sources = sorted(set(sources))
        if not unique_sources:
            return [], None
        return unique_sources, total_bytes if found_size else None

    def _telemetry_quality(self, stats: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(stats, dict):
            return {}
        expected = stats.get("expected_samples")
        captured = stats.get("captured_samples")
        ratio = None
        try:
            if expected and int(expected) > 0:
                ratio = round(float(captured or 0) / float(expected), 4)
        except Exception:
            ratio = None
        return {
            "capture_ratio": ratio,
            "sampling_duration_seconds": stats.get("sampling_duration_seconds"),
            "max_gap_s": stats.get("sample_max_gap_s"),
            "avg_delta_s": stats.get("sample_avg_delta_s"),
        }

    def _scan_log_signals(self, manifest: RunManifest) -> list[str]:
        signals: list[str] = []
        for artifact in manifest.artifacts:
            if artifact.type != "system_log_capture":
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                content = path.read_text(errors="ignore")
            except OSError:
                continue
            if "SSLHandshakeException" in content:
                signals.append("SSLHandshakeException")
            if "Cleartext" in content:
                signals.append("CleartextTraffic")
        return sorted(set(signals))

    def _load_runtime_surfaces(self) -> dict[str, Any]:
        events_path = self.writer.run_dir / "notes" / "run_events.jsonl"
        if not events_path.exists():
            return {}
        transitions: list[dict[str, Any]] = []
        try:
            for raw_line in events_path.read_text(encoding="utf-8").splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get("event_type") != "FOREGROUND_SURFACE_CHANGE":
                    continue
                details = payload.get("details")
                if not isinstance(details, dict):
                    continue
                label = str(details.get("surface_label") or "").strip()
                if not label:
                    continue
                transitions.append(
                    {
                        "elapsed_s": _safe_int(details.get("elapsed_s")),
                        "surface_label": label,
                        "surface_detail": str(details.get("surface_detail") or "").strip() or None,
                        "foreground_component": str(details.get("foreground_component") or "").strip() or None,
                    }
                )
        except OSError:
            return {}
        if not transitions:
            return {}
        counts: dict[str, int] = {}
        first_details: dict[str, str] = {}
        for row in transitions:
            label = str(row.get("surface_label") or "").strip()
            counts[label] = counts.get(label, 0) + 1
            detail = str(row.get("surface_detail") or "").strip()
            if detail and label not in first_details:
                first_details[label] = detail
        primary_label = max(
            counts.items(),
            key=lambda item: (
                item[1],
                -min(
                    int(t.get("elapsed_s") or 0)
                    for t in transitions
                    if str(t.get("surface_label") or "").strip() == item[0]
                ),
            ),
        )[0]
        return {
            "transition_count": len(transitions),
            "labels": sorted(counts.keys()),
            "counts": counts,
            "primary_label": primary_label,
            "primary_detail": first_details.get(primary_label),
            "transitions": transitions[:12],
        }

    def _network_capture_present(self, manifest: RunManifest, pcap_meta: dict[str, Any]) -> str:
        capture_types = {"pcapdroid_capture"}
        meta_size = _safe_int(pcap_meta.get("pcap_size_bytes")) or 0
        if pcap_meta.get("pcap_available") and meta_size > 0:
            return "true"
        for artifact in manifest.artifacts:
            if artifact.type not in capture_types:
                continue
            if artifact.size_bytes is not None:
                if artifact.size_bytes > 0:
                    return "true"
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                if path.exists() and path.stat().st_size > 0:
                    return "true"
            except OSError:
                continue
        return "false"

    def _load_pcap_meta(self, manifest: RunManifest) -> dict[str, Any]:
        meta_path = None
        pcap_artifact_present = False
        for artifact in manifest.artifacts:
            if artifact.type == "pcapdroid_capture":
                pcap_artifact_present = True
            if artifact.type == "pcapdroid_capture_meta":
                meta_path = self.writer.run_dir / artifact.relative_path
        if not meta_path or not meta_path.exists():
            return {"pcap_available": pcap_artifact_present}
        try:
            payload = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            return {"pcap_available": pcap_artifact_present}
        meta: dict[str, Any] = {}
        for key in ("pcap_size_bytes", "pcap_valid", "min_pcap_bytes", "capture_mode"):
            if key in payload:
                meta[key] = payload.get(key)
        resolved_name = payload.get("resolved_pcap_name") or payload.get("pcap_name")
        candidate_exists = False
        candidate_size = None
        if isinstance(resolved_name, str) and resolved_name.strip():
            candidate = self.writer.run_dir / "artifacts" / "pcapdroid_capture" / resolved_name
            try:
                if candidate.exists():
                    candidate_exists = True
                    candidate_size = int(candidate.stat().st_size)
            except OSError:
                candidate_exists = False
                candidate_size = None
        elif not pcap_artifact_present:
            for candidate in (self.writer.run_dir / "artifacts" / "pcapdroid_capture").glob("*.pcap*"):
                if not candidate.is_file():
                    continue
                try:
                    candidate_exists = True
                    candidate_size = int(candidate.stat().st_size)
                    break
                except OSError:
                    continue
        if meta.get("pcap_size_bytes") in (None, 0) and candidate_size is not None:
            meta["pcap_size_bytes"] = candidate_size
        meta["pcap_available"] = bool(pcap_artifact_present or candidate_exists)
        return meta


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_float(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _format_call_outcome_summary(
    *,
    attempt_count: int | None,
    connected_count: int | None,
    not_connected_count: int | None,
    canceled_count: int | None,
    connected_short_count: int | None,
) -> str:
    parts = [
        f"attempts={int(attempt_count or 0)}",
        f"connected={int(connected_count or 0)}",
        f"not_connected={int(not_connected_count or 0)}",
        f"canceled={int(canceled_count or 0)}",
    ]
    if connected_short_count:
        parts.append(f"connected_short={int(connected_short_count)}")
    return ";".join(parts)


__all__ = ["DynamicRunSummarizer"]
