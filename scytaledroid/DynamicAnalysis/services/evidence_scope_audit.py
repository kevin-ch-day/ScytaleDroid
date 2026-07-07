"""Read-only evidence-scope audit for dynamic PCAP captures."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCOPE_CLEAN = "SCOPE_CLEAN"
SCOPE_MINOR_OVERHEAD = "SCOPE_MINOR_OVERHEAD"
SCOPE_REVIEW = "SCOPE_REVIEW"
SCOPE_CONTAMINATED_FULL_PCAP = "SCOPE_CONTAMINATED_FULL_PCAP"

CLEAN_DURATION_DELTA_S = 60.0
MINOR_DURATION_DELTA_S = 120.0
CLEAN_RATIO_LOW = 0.80
CLEAN_RATIO_HIGH = 1.25
MINOR_RATIO_LOW = 0.50
MINOR_RATIO_HIGH = 2.00
CONTAMINATED_DURATION_S = 120.0
CONTAMINATED_BYTE_SHARE = 0.25
CONTAMINATED_PACKET_SHARE = 0.25


@dataclass(frozen=True)
class ScopeClassification:
    scope_classification: str
    reasons: tuple[str, ...]
    missing_metrics: tuple[str, ...]


@dataclass
class EvidenceScopeMetrics:
    dynamic_run_id: str
    package_name: str | None = None
    app_label: str | None = None
    version_code: str | None = None
    static_run_id: str | None = None
    run_profile: str | None = None
    cohort_eligibility: str | None = None
    countable: bool | None = None
    valid_dataset_run: bool | None = None
    paper_eligible: bool | None = None
    target_duration_s: float | None = None
    scenario_elapsed_s: float | None = None
    telemetry_sampling_window_s: float | None = None
    capinfos_capture_duration_s: float | None = None
    packet_count: int | None = None
    pcap_file_bytes: int | None = None
    pcap_data_bytes: int | None = None
    netstats_total_bytes: int | None = None
    pcap_to_netstats_ratio: float | None = None
    duration_delta_s: float | None = None
    overhead_outside_sampling_s: float | None = None
    pre_scenario_duration_s: float | None = None
    post_scenario_duration_s: float | None = None
    pre_scenario_bytes: int | None = None
    scenario_window_bytes: int | None = None
    post_scenario_bytes: int | None = None
    pre_scenario_packet_count: int | None = None
    scenario_packet_count: int | None = None
    post_scenario_packet_count: int | None = None
    observer_start_ts: str | None = None
    scenario_start_ts: str | None = None
    scenario_end_ts: str | None = None
    observer_stop_ts: str | None = None
    pcap_first_packet_ts: str | None = None
    pcap_last_packet_ts: str | None = None
    pcap_path: str | None = None


@dataclass(frozen=True)
class EvidenceScopeRow:
    dynamic_run_id: str
    package_name: str | None
    app_label: str | None
    version_code: str | None
    static_run_id: str | None
    run_profile: str | None
    cohort_eligibility: str | None
    countable: bool | None
    valid_dataset_run: bool | None
    paper_eligible: bool | None
    target_duration_s: float | None
    scenario_elapsed_s: float | None
    telemetry_sampling_window_s: float | None
    capinfos_capture_duration_s: float | None
    packet_count: int | None
    pcap_file_bytes: int | None
    pcap_data_bytes: int | None
    netstats_total_bytes: int | None
    pcap_to_netstats_ratio: float | None
    duration_delta_s: float | None
    overhead_outside_sampling_s: float | None
    pre_scenario_duration_s: float | None
    post_scenario_duration_s: float | None
    pre_scenario_bytes: int | None
    scenario_window_bytes: int | None
    post_scenario_bytes: int | None
    pre_scenario_packet_count: int | None
    scenario_packet_count: int | None
    post_scenario_packet_count: int | None
    pre_scenario_byte_share: float | None
    post_scenario_byte_share: float | None
    pre_scenario_packet_share: float | None
    post_scenario_packet_share: float | None
    observer_start_ts: str | None
    scenario_start_ts: str | None
    scenario_end_ts: str | None
    observer_stop_ts: str | None
    pcap_first_packet_ts: str | None
    pcap_last_packet_ts: str | None
    pcap_path: str | None
    scope_classification: str
    scope_reasons: str
    missing_metrics: str


@dataclass
class EvidenceScopeAudit:
    generated_at: str
    evidence_root: str
    runs_scanned: int
    rows: list[EvidenceScopeRow]
    classification_counts: dict[str, int]
    missing_metric_counts: dict[str, int]
    top_duration_mismatch: list[dict[str, Any]]
    top_ratio_outliers: list[dict[str, Any]]
    top_pre_scenario_byte_share: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "evidence_root": self.evidence_root,
            "runs_scanned": self.runs_scanned,
            "classification_counts": self.classification_counts,
            "missing_metric_counts": self.missing_metric_counts,
            "top_duration_mismatch": self.top_duration_mismatch,
            "top_ratio_outliers": self.top_ratio_outliers,
            "top_pre_scenario_byte_share": self.top_pre_scenario_byte_share,
            "rows": [asdict(row) for row in self.rows],
        }


def classify_scope(metrics: EvidenceScopeMetrics) -> ScopeClassification:
    reasons: list[str] = []
    missing: list[str] = []

    if metrics.capinfos_capture_duration_s is None:
        missing.append("capinfos_capture_duration_s")
    if metrics.telemetry_sampling_window_s is None and metrics.scenario_elapsed_s is None:
        missing.append("scenario_or_telemetry_duration")
    if metrics.netstats_total_bytes is None or metrics.netstats_total_bytes <= 0:
        missing.append("netstats_total_bytes")
    if metrics.pcap_data_bytes is None and metrics.pcap_file_bytes is None:
        missing.append("pcap_bytes")

    pre_byte_share = _share(metrics.pre_scenario_bytes, metrics.pcap_data_bytes or metrics.pcap_file_bytes)
    post_byte_share = _share(metrics.post_scenario_bytes, metrics.pcap_data_bytes or metrics.pcap_file_bytes)
    pre_packet_share = _share(metrics.pre_scenario_packet_count, metrics.packet_count)
    post_packet_share = _share(metrics.post_scenario_packet_count, metrics.packet_count)

    if _contaminated_slice(metrics.pre_scenario_duration_s, pre_byte_share, pre_packet_share):
        reasons.append(f"pre-scenario slice substantial ({_fmt_share(pre_byte_share)} bytes)")
    if _contaminated_slice(metrics.post_scenario_duration_s, post_byte_share, post_packet_share):
        reasons.append(f"post-scenario slice substantial ({_fmt_share(post_byte_share)} bytes)")
    if reasons:
        return ScopeClassification(SCOPE_CONTAMINATED_FULL_PCAP, tuple(reasons), tuple(missing))

    duration_delta = metrics.duration_delta_s
    if duration_delta is None:
        duration_delta = _duration_delta(metrics.capinfos_capture_duration_s, _best_window(metrics))
    if duration_delta is None:
        reasons.append("missing duration comparison")
    elif duration_delta > MINOR_DURATION_DELTA_S:
        reasons.append(f"duration delta {duration_delta:.1f}s > {MINOR_DURATION_DELTA_S:.0f}s")
    elif duration_delta > CLEAN_DURATION_DELTA_S:
        reasons.append(f"duration delta {duration_delta:.1f}s > {CLEAN_DURATION_DELTA_S:.0f}s")

    ratio = metrics.pcap_to_netstats_ratio
    if ratio is None and metrics.netstats_total_bytes and metrics.netstats_total_bytes > 0:
        pcap_bytes = metrics.pcap_data_bytes or metrics.pcap_file_bytes
        if pcap_bytes is not None:
            ratio = pcap_bytes / metrics.netstats_total_bytes
    if ratio is None:
        if "netstats_total_bytes" not in missing:
            missing.append("pcap_to_netstats_ratio")
    elif ratio < MINOR_RATIO_LOW or ratio > MINOR_RATIO_HIGH:
        reasons.append(f"pcap/netstats ratio {ratio:.2f} outside {MINOR_RATIO_LOW:.2f}-{MINOR_RATIO_HIGH:.2f}")
    elif ratio < CLEAN_RATIO_LOW or ratio > CLEAN_RATIO_HIGH:
        reasons.append(f"pcap/netstats ratio {ratio:.2f} outside {CLEAN_RATIO_LOW:.2f}-{CLEAN_RATIO_HIGH:.2f}")

    if any(">" in reason or "outside 0.50-2.00" in reason for reason in reasons):
        return ScopeClassification(SCOPE_REVIEW, tuple(reasons), tuple(missing))
    if reasons:
        return ScopeClassification(SCOPE_MINOR_OVERHEAD, tuple(reasons), tuple(missing))
    return ScopeClassification(SCOPE_CLEAN, tuple(), tuple(missing))


def build_evidence_scope_audit(
    evidence_root: Path,
    *,
    packages: set[str] | None = None,
    run_ids: set[str] | None = None,
    include_invalid: bool = False,
    segment_probe: bool = True,
    max_segment_probes: int = 25,
    top_n: int = 10,
) -> EvidenceScopeAudit:
    rows: list[EvidenceScopeRow] = []
    runs_scanned = 0
    segment_probes = 0
    package_filter = {pkg.strip().lower() for pkg in packages or set() if pkg.strip()}
    run_id_filter = {run_id.strip().lower() for run_id in run_ids or set() if run_id.strip()}

    if evidence_root.exists():
        for run_dir in sorted((p for p in evidence_root.iterdir() if p.is_dir()), key=lambda p: p.name):
            manifest = _read_json(run_dir / "run_manifest.json")
            if not manifest:
                continue
            metrics = metrics_from_run_dir(run_dir, manifest=manifest)
            if run_id_filter and metrics.dynamic_run_id.lower() not in run_id_filter:
                continue
            if package_filter and (metrics.package_name or "").lower() not in package_filter:
                continue
            if not include_invalid and metrics.valid_dataset_run is False:
                continue
            runs_scanned += 1
            preliminary = classify_scope(metrics)
            if (
                segment_probe
                and segment_probes < max_segment_probes
                and metrics.pcap_path
                and _should_probe_segments(metrics, preliminary.scope_classification)
            ):
                _populate_segment_metrics(metrics)
                segment_probes += 1
            rows.append(row_from_metrics(metrics, classify_scope(metrics)))

    class_counts = Counter(row.scope_classification for row in rows)
    missing_counts: Counter[str] = Counter()
    for row in rows:
        for metric in [part for part in row.missing_metrics.split(";") if part]:
            missing_counts[metric] += 1

    return EvidenceScopeAudit(
        generated_at=datetime.now(UTC).isoformat(),
        evidence_root=str(evidence_root.resolve()),
        runs_scanned=runs_scanned,
        rows=rows,
        classification_counts={key: class_counts.get(key, 0) for key in _classification_order()},
        missing_metric_counts=dict(sorted(missing_counts.items())),
        top_duration_mismatch=_top_rows(rows, "duration_delta_s", top_n),
        top_ratio_outliers=_top_ratio_rows(rows, top_n),
        top_pre_scenario_byte_share=_top_rows(rows, "pre_scenario_byte_share", top_n),
    )


def metrics_from_run_dir(run_dir: Path, *, manifest: dict[str, Any] | None = None) -> EvidenceScopeMetrics:
    manifest = manifest or _read_json(run_dir / "run_manifest.json") or {}
    target = _dict_value(manifest, "target")
    dataset = _dict_value(manifest, "dataset")
    operator = _dict_value(manifest, "operator")
    telemetry = _dict_value(operator, "telemetry_stats")
    scenario = _dict_value(manifest, "scenario")
    identity = _dict_value(target, "run_identity")
    run_context = _dict_value(operator, "run_context")

    report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
    capinfos = _dict_value(_dict_value(report, "capinfos"), "parsed")

    package_name = _string_or_none(target.get("package_name") or identity.get("package_name_lc"))
    app_label = _string_or_none(target.get("display_name") or target.get("app_label") or package_name)
    run_id = _string_or_none(manifest.get("dynamic_run_id")) or run_dir.name
    scenario_start = _timestamp_or_none(scenario.get("started_at"))
    scenario_end = _timestamp_or_none(scenario.get("ended_at"))
    observer_start, observer_stop = _observer_bounds(run_dir)
    if scenario_start is None:
        scenario_start = _event_timestamp(run_dir, "TARGET_FOREGROUND_READY") or _event_timestamp(run_dir, "scenario_started")
    if scenario_end is None:
        scenario_end = _event_timestamp(run_dir, "scenario_ended")

    scenario_elapsed = _elapsed_seconds(scenario_start, scenario_end)
    telemetry_window = _safe_float(telemetry.get("sampling_duration_seconds") or dataset.get("sampling_duration_seconds"))
    cap_duration = _safe_float(capinfos.get("capture_duration_s") or dataset.get("actual_sampling_seconds"))
    pcap_data_bytes = _safe_int(capinfos.get("data_size_bytes"))
    pcap_file_bytes = _safe_int(capinfos.get("file_size_bytes") or dataset.get("pcap_size_bytes"))
    packet_count = _safe_int(capinfos.get("packet_count"))
    netstats_total = _netstats_total_bytes(telemetry, dataset)
    pcap_bytes_for_ratio = pcap_data_bytes or pcap_file_bytes
    ratio = pcap_bytes_for_ratio / netstats_total if pcap_bytes_for_ratio and netstats_total and netstats_total > 0 else None
    best_window = telemetry_window if telemetry_window is not None else scenario_elapsed

    pre_duration = _elapsed_seconds(observer_start, scenario_start)
    if pre_duration is not None and pre_duration < 0:
        pre_duration = None
    post_duration = None
    if cap_duration is not None and scenario_elapsed is not None:
        post_duration = max(cap_duration - max(pre_duration or 0.0, 0.0) - scenario_elapsed, 0.0)
    elif observer_stop is not None and scenario_end is not None:
        post_duration = _elapsed_seconds(scenario_end, observer_stop)

    return EvidenceScopeMetrics(
        dynamic_run_id=run_id,
        package_name=package_name,
        app_label=app_label,
        version_code=_string_or_none(target.get("version_code") or identity.get("version_code")),
        static_run_id=_string_or_none(target.get("static_run_id") or identity.get("static_run_id")),
        run_profile=_string_or_none(operator.get("run_profile") or run_context.get("run_profile")),
        cohort_eligibility=_string_or_none(dataset.get("cohort_eligibility") or operator.get("cohort_eligibility")),
        countable=_bool_or_none(dataset.get("countable") if "countable" in dataset else operator.get("counts_toward_completion")),
        valid_dataset_run=_bool_or_none(dataset.get("valid_dataset_run")),
        paper_eligible=_bool_or_none(dataset.get("paper_eligible")),
        target_duration_s=_safe_float(operator.get("target_duration_s") or target.get("duration_seconds")),
        scenario_elapsed_s=scenario_elapsed,
        telemetry_sampling_window_s=telemetry_window,
        capinfos_capture_duration_s=cap_duration,
        packet_count=packet_count,
        pcap_file_bytes=pcap_file_bytes,
        pcap_data_bytes=pcap_data_bytes,
        netstats_total_bytes=netstats_total,
        pcap_to_netstats_ratio=ratio,
        duration_delta_s=_duration_delta(cap_duration, best_window),
        overhead_outside_sampling_s=(cap_duration - telemetry_window) if cap_duration is not None and telemetry_window is not None else None,
        pre_scenario_duration_s=pre_duration,
        post_scenario_duration_s=post_duration,
        observer_start_ts=_iso_or_none(observer_start),
        scenario_start_ts=_iso_or_none(scenario_start),
        scenario_end_ts=_iso_or_none(scenario_end),
        observer_stop_ts=_iso_or_none(observer_stop),
        pcap_first_packet_ts=_string_or_none(capinfos.get("first_packet_time")),
        pcap_last_packet_ts=_string_or_none(capinfos.get("last_packet_time")),
        pcap_path=_pcap_path(run_dir),
    )


def row_from_metrics(metrics: EvidenceScopeMetrics, classification: ScopeClassification) -> EvidenceScopeRow:
    pre_byte_share = _share(metrics.pre_scenario_bytes, metrics.pcap_data_bytes or metrics.pcap_file_bytes)
    post_byte_share = _share(metrics.post_scenario_bytes, metrics.pcap_data_bytes or metrics.pcap_file_bytes)
    pre_packet_share = _share(metrics.pre_scenario_packet_count, metrics.packet_count)
    post_packet_share = _share(metrics.post_scenario_packet_count, metrics.packet_count)
    return EvidenceScopeRow(
        dynamic_run_id=metrics.dynamic_run_id,
        package_name=metrics.package_name,
        app_label=metrics.app_label,
        version_code=metrics.version_code,
        static_run_id=metrics.static_run_id,
        run_profile=metrics.run_profile,
        cohort_eligibility=metrics.cohort_eligibility,
        countable=metrics.countable,
        valid_dataset_run=metrics.valid_dataset_run,
        paper_eligible=metrics.paper_eligible,
        target_duration_s=_round_float(metrics.target_duration_s),
        scenario_elapsed_s=_round_float(metrics.scenario_elapsed_s),
        telemetry_sampling_window_s=_round_float(metrics.telemetry_sampling_window_s),
        capinfos_capture_duration_s=_round_float(metrics.capinfos_capture_duration_s),
        packet_count=metrics.packet_count,
        pcap_file_bytes=metrics.pcap_file_bytes,
        pcap_data_bytes=metrics.pcap_data_bytes,
        netstats_total_bytes=metrics.netstats_total_bytes,
        pcap_to_netstats_ratio=_round_float(metrics.pcap_to_netstats_ratio),
        duration_delta_s=_round_float(metrics.duration_delta_s),
        overhead_outside_sampling_s=_round_float(metrics.overhead_outside_sampling_s),
        pre_scenario_duration_s=_round_float(metrics.pre_scenario_duration_s),
        post_scenario_duration_s=_round_float(metrics.post_scenario_duration_s),
        pre_scenario_bytes=metrics.pre_scenario_bytes,
        scenario_window_bytes=metrics.scenario_window_bytes,
        post_scenario_bytes=metrics.post_scenario_bytes,
        pre_scenario_packet_count=metrics.pre_scenario_packet_count,
        scenario_packet_count=metrics.scenario_packet_count,
        post_scenario_packet_count=metrics.post_scenario_packet_count,
        pre_scenario_byte_share=_round_float(pre_byte_share),
        post_scenario_byte_share=_round_float(post_byte_share),
        pre_scenario_packet_share=_round_float(pre_packet_share),
        post_scenario_packet_share=_round_float(post_packet_share),
        observer_start_ts=metrics.observer_start_ts,
        scenario_start_ts=metrics.scenario_start_ts,
        scenario_end_ts=metrics.scenario_end_ts,
        observer_stop_ts=metrics.observer_stop_ts,
        pcap_first_packet_ts=metrics.pcap_first_packet_ts,
        pcap_last_packet_ts=metrics.pcap_last_packet_ts,
        pcap_path=metrics.pcap_path,
        scope_classification=classification.scope_classification,
        scope_reasons=";".join(classification.reasons),
        missing_metrics=";".join(classification.missing_metrics),
    )


def _populate_segment_metrics(metrics: EvidenceScopeMetrics) -> None:
    if not metrics.pcap_path or metrics.pre_scenario_duration_s is None or metrics.scenario_elapsed_s is None:
        return
    pcap_path = Path(metrics.pcap_path)
    if not pcap_path.exists():
        return
    pre_end = max(metrics.pre_scenario_duration_s, 0.0)
    scenario_end = pre_end + max(metrics.scenario_elapsed_s, 0.0)
    cap_duration = metrics.capinfos_capture_duration_s or scenario_end
    segments = (
        ("pre", f"frame.time_relative < {pre_end:.6f}") if pre_end > 0.0 else None,
        ("scenario", f"frame.time_relative >= {pre_end:.6f} && frame.time_relative <= {min(scenario_end, cap_duration):.6f}"),
        ("post", f"frame.time_relative > {scenario_end:.6f}") if scenario_end < cap_duration else None,
    )
    for segment in segments:
        if segment is None:
            continue
        name, display_filter = segment
        probe = _tshark_len_sum(pcap_path, display_filter)
        if probe is None:
            continue
        packets, bytes_total = probe
        if name == "pre":
            metrics.pre_scenario_packet_count = packets
            metrics.pre_scenario_bytes = bytes_total
        elif name == "scenario":
            metrics.scenario_packet_count = packets
            metrics.scenario_window_bytes = bytes_total
        elif name == "post":
            metrics.post_scenario_packet_count = packets
            metrics.post_scenario_bytes = bytes_total


def _tshark_len_sum(pcap_path: Path, display_filter: str) -> tuple[int, int] | None:
    try:
        proc = subprocess.run(
            ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-e", "frame.len"],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    packets = 0
    bytes_total = 0
    for line in proc.stdout.splitlines():
        value = _safe_int(line.strip())
        if value is None:
            continue
        packets += 1
        bytes_total += value
    return packets, bytes_total


def _should_probe_segments(metrics: EvidenceScopeMetrics, classification: str) -> bool:
    if classification in {SCOPE_REVIEW, SCOPE_MINOR_OVERHEAD}:
        return True
    return (metrics.pre_scenario_duration_s or 0.0) > CLEAN_DURATION_DELTA_S or (metrics.post_scenario_duration_s or 0.0) > CLEAN_DURATION_DELTA_S


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_events(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "notes" / "run_events.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _observer_bounds(run_dir: Path) -> tuple[datetime | None, datetime | None]:
    start: datetime | None = None
    stop: datetime | None = None
    for event in _read_events(run_dir):
        event_type = event.get("event_type") or event.get("event")
        details = _dict_value(event, "details")
        if details.get("observer_id") != "pcapdroid_capture":
            continue
        ts = _timestamp_or_none(event.get("timestamp"))
        if event_type == "observer_started" and start is None:
            start = ts
        elif event_type == "observer_stopped":
            stop = ts
    return start, stop


def _event_timestamp(run_dir: Path, event_type: str) -> datetime | None:
    for event in _read_events(run_dir):
        if (event.get("event_type") or event.get("event")) == event_type:
            return _timestamp_or_none(event.get("timestamp"))
    return None


def _pcap_path(run_dir: Path) -> str | None:
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    if not capture_dir.exists():
        return None
    pcaps = sorted(capture_dir.glob("*.pcap"))
    return str(pcaps[0].resolve()) if pcaps else None


def _timestamp_or_none(value: Any) -> datetime | None:
    text = _string_or_none(value)
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _elapsed_seconds(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return (end - start).total_seconds()


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _dict_value(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}


def _netstats_total_bytes(telemetry: dict[str, Any], dataset: dict[str, Any]) -> int | None:
    inbound = _safe_int(telemetry.get("netstats_bytes_in_total"))
    outbound = _safe_int(telemetry.get("netstats_bytes_out_total"))
    if inbound is not None or outbound is not None:
        return (inbound or 0) + (outbound or 0)
    return _safe_int(dataset.get("netstats_observed_bytes"))


def _best_window(metrics: EvidenceScopeMetrics) -> float | None:
    return metrics.telemetry_sampling_window_s if metrics.telemetry_sampling_window_s is not None else metrics.scenario_elapsed_s


def _duration_delta(pcap_duration: float | None, target_duration: float | None) -> float | None:
    if pcap_duration is None or target_duration is None:
        return None
    return abs(pcap_duration - target_duration)


def _share(value: int | None, total: int | None) -> float | None:
    if value is None or total is None or total <= 0:
        return None
    return value / total


def _contaminated_slice(duration_s: float | None, byte_share: float | None, packet_share: float | None) -> bool:
    if duration_s is None or duration_s < CONTAMINATED_DURATION_S:
        return False
    if byte_share is not None and byte_share >= CONTAMINATED_BYTE_SHARE:
        return True
    return packet_share is not None and packet_share >= CONTAMINATED_PACKET_SHARE


def _fmt_share(value: float | None) -> str:
    return "unknown" if value is None else f"{value:.1%}"


def _iso_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _round_float(value: float | None) -> float | None:
    return round(value, 6) if isinstance(value, float) else value


def _classification_order() -> tuple[str, ...]:
    return (SCOPE_CLEAN, SCOPE_MINOR_OVERHEAD, SCOPE_REVIEW, SCOPE_CONTAMINATED_FULL_PCAP)


def _top_rows(rows: list[EvidenceScopeRow], field: str, top_n: int) -> list[dict[str, Any]]:
    ranked = sorted(
        (row for row in rows if getattr(row, field) is not None),
        key=lambda row: getattr(row, field) or 0,
        reverse=True,
    )
    return [_top_projection(row, field) for row in ranked[:top_n]]


def _top_ratio_rows(rows: list[EvidenceScopeRow], top_n: int) -> list[dict[str, Any]]:
    def distance(row: EvidenceScopeRow) -> float:
        ratio = row.pcap_to_netstats_ratio or 1.0
        if ratio > 1.0:
            return ratio
        return 1.0 / ratio if ratio > 0 else float("inf")

    ranked = sorted(
        (row for row in rows if row.pcap_to_netstats_ratio is not None),
        key=distance,
        reverse=True,
    )
    return [_top_projection(row, "pcap_to_netstats_ratio") for row in ranked[:top_n]]


def _top_projection(row: EvidenceScopeRow, field: str) -> dict[str, Any]:
    return {
        "dynamic_run_id": row.dynamic_run_id,
        "package_name": row.package_name,
        "app_label": row.app_label,
        "scope_classification": row.scope_classification,
        field: getattr(row, field),
    }
