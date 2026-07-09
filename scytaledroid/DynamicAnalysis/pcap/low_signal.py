"""Low-signal tagging for dynamic runs (Paper #2).

Contract (PM-locked):
- Validity (VALID/INVALID) is decided by QA rules and is independent of "signal quality".
- low_signal is a non-invalidating flag used to make ML preflight deterministic and auditable.

This module computes a low_signal decision from evidence-pack artifacts only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import MESSAGING_PACKAGES
from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package

_CHAT_LIKE_BASELINE_PACKAGES = {
    "com.snapchat.android",
}
_RELAXED_IDLE_MIN_BYTES = 500_000  # 500KB
_CONNECTED_BASELINE_MIN_PACKETS = 100
_CONNECTED_BASELINE_MIN_DOMAINS = 1
_RICH_IDLE_CATEGORY_NAMES = {"social_feed", "news_reader"}
_RICH_IDLE_MIN_DURATION_S = 180.0
_RICH_IDLE_MIN_PACKETS = 250
_RICH_IDLE_MIN_DOMAINS = 3
_RICH_IDLE_MIN_SERVICES = 2
_RICH_IDLE_MIN_JA4 = 2
_RICH_IDLE_MIN_TLS_HELLOS = 4


@dataclass(frozen=True)
class LowSignalConfig:
    """Deterministic thresholds for low-signal tagging.

    These defaults are intentionally conservative. The goal is to highlight runs
    that are "valid but likely uninformative for ML training" (e.g., extremely
    short capture span, near-empty PCAP, tiny packet counts).
    """

    min_capture_duration_s: float = 30.0
    min_data_size_bytes: int = 1_000_000  # ~1MB
    min_packet_count: int = 1_000
    min_unique_domains_topn: int = 3


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def compute_low_signal_from_evidence_pack(run_dir: Path, *, cfg: LowSignalConfig | None = None) -> dict[str, Any] | None:
    """Compute low_signal from pcap_features.json (preferred).

    Returns a dict that is safe to embed into run_manifest.json under dataset.
    If inputs are missing/unparseable, returns None.
    """

    config = cfg or LowSignalConfig()
    effective = _effective_low_signal_config(
        config,
        package_name=None,
        run_profile=None,
    )
    features_path = run_dir / "analysis" / "pcap_features.json"
    pf = _read_json(features_path)
    if not isinstance(pf, dict):
        return None

    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}

    capture_duration_s = metrics.get("capture_duration_s")
    data_size_bytes = metrics.get("data_size_bytes")
    packet_count = metrics.get("packet_count")
    unique_domains_topn = proxies.get("unique_domains_topn")

    reasons: list[str] = []

    try:
        dur = float(capture_duration_s) if capture_duration_s is not None else None
    except Exception:
        dur = None
    if dur is not None and dur < float(effective.min_capture_duration_s):
        reasons.append("PCAP_CAPTURE_TOO_SHORT")

    try:
        size_b = int(data_size_bytes) if data_size_bytes is not None else None
    except Exception:
        size_b = None
    if size_b is not None and size_b < int(effective.min_data_size_bytes):
        reasons.append("PCAP_BYTES_LOW")

    try:
        pkts = int(packet_count) if packet_count is not None else None
    except Exception:
        pkts = None
    if pkts is not None and pkts < int(effective.min_packet_count):
        reasons.append("PCAP_PACKETS_LOW")

    try:
        doms = int(unique_domains_topn) if unique_domains_topn is not None else None
    except Exception:
        doms = None
    if doms is not None and doms < int(effective.min_unique_domains_topn):
        reasons.append("DOMAINS_LOW")

    return {
        "low_signal": bool(reasons),
        "low_signal_reasons": reasons,
        "low_signal_thresholds": {
            "min_capture_duration_s": float(effective.min_capture_duration_s),
            "min_data_size_bytes": int(effective.min_data_size_bytes),
            "min_packet_count": int(effective.min_packet_count),
            "min_unique_domains_topn": int(effective.min_unique_domains_topn),
        },
    }


def compute_low_signal_for_run(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
    cfg: LowSignalConfig | None = None,
) -> dict[str, Any] | None:
    """Compute low-signal with package/profile-aware thresholds."""
    config = cfg or LowSignalConfig()
    effective = _effective_low_signal_config(
        config,
        package_name=package_name,
        run_profile=run_profile,
    )
    decision = compute_low_signal_from_evidence_pack(run_dir, cfg=effective)
    if not isinstance(decision, dict):
        return decision

    reasons = list(decision.get("low_signal_reasons") or [])
    if "DOMAINS_LOW" in reasons and _should_suppress_domains_low_for_messaging_call(
        run_dir,
        package_name=package_name,
        run_profile=run_profile,
    ):
        reasons = [reason for reason in reasons if reason != "DOMAINS_LOW"]
        decision["low_signal_reasons"] = reasons
        decision["low_signal"] = bool(reasons)
    if _should_suppress_low_signal_for_connected_baseline(
        run_dir,
        package_name=package_name,
        run_profile=run_profile,
        reasons=reasons,
        cfg=effective,
    ):
        reasons = []
        decision["low_signal_reasons"] = reasons
        decision["low_signal"] = False
    elif _should_suppress_low_signal_for_rich_idle_baseline(
        run_dir,
        package_name=package_name,
        run_profile=run_profile,
        reasons=reasons,
        cfg=effective,
    ):
        reasons = []
        decision["low_signal_reasons"] = reasons
        decision["low_signal"] = False
    elif _should_suppress_bytes_low_for_idle_baseline(
        run_dir,
        run_profile=run_profile,
        reasons=reasons,
        cfg=effective,
    ):
        reasons = [reason for reason in reasons if reason != "PCAP_BYTES_LOW"]
        decision["low_signal_reasons"] = reasons
        decision["low_signal"] = bool(reasons)
    elif _should_suppress_low_signal_for_messaging_interaction(
        run_dir,
        package_name=package_name,
        run_profile=run_profile,
        reasons=reasons,
        cfg=effective,
    ):
        reasons = []
        decision["low_signal_reasons"] = reasons
        decision["low_signal"] = False
    return decision


def _should_suppress_low_signal_for_messaging_interaction(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
    reasons: list[str],
    cfg: LowSignalConfig,
) -> bool:
    """Messaging interaction runs can be legitimately quiet; keep them valid with warnings only."""
    profile = str(run_profile or "").strip().lower()
    if not profile.startswith("interaction"):
        return False
    if not _is_chat_like_package(package_name):
        return False
    if not reasons:
        return False
    allowed_quiet_reasons = {"PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"}
    if any(reason not in allowed_quiet_reasons for reason in reasons):
        return False

    metrics = _baseline_evidence_metrics(run_dir)
    return (
        metrics["pcap_quality_ok"]
        and metrics["duration_s"] >= float(cfg.min_capture_duration_s)
        and metrics["packet_count"] > 0
        and metrics["has_evidence"]
    )


def _should_suppress_low_signal_for_connected_baseline(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
    reasons: list[str],
    cfg: LowSignalConfig,
) -> bool:
    """Treat quiet connected-idle messaging baselines as sufficient when corroborated."""
    profile = str(run_profile or "").strip().lower()
    if profile != "baseline_connected":
        return False
    if not _is_chat_like_package(package_name):
        return False
    if not reasons:
        return False
    allowed_quiet_reasons = {"PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"}
    if any(reason not in allowed_quiet_reasons for reason in reasons):
        return False

    metrics = _baseline_evidence_metrics(run_dir)
    return (
        metrics["pcap_quality_ok"]
        and metrics["duration_s"] >= float(cfg.min_capture_duration_s)
        and metrics["packet_count"] >= _CONNECTED_BASELINE_MIN_PACKETS
        and metrics["domain_count"] >= _CONNECTED_BASELINE_MIN_DOMAINS
        and metrics["has_evidence"]
    )


def _should_suppress_bytes_low_for_idle_baseline(
    run_dir: Path,
    *,
    run_profile: str | None,
    reasons: list[str],
    cfg: LowSignalConfig,
) -> bool:
    """Do not penalize intentionally quiet idle baselines for bytes alone.

    Baseline-idle protocol asks the operator to keep the app mostly idle. If the
    capture is long enough and has enough packet/domain evidence, low byte volume
    by itself is not evidence that the baseline is uninformative.
    """
    profile = str(run_profile or "").strip().lower()
    if profile != "baseline_idle":
        return False
    if reasons != ["PCAP_BYTES_LOW"]:
        return False

    metrics = _baseline_evidence_metrics(run_dir)
    return (
        metrics["pcap_quality_ok"]
        and metrics["duration_s"] >= float(cfg.min_capture_duration_s)
        and metrics["packet_count"] >= int(cfg.min_packet_count)
        and metrics["domain_count"] >= int(cfg.min_unique_domains_topn)
        and metrics["has_evidence"]
    )


def _should_suppress_low_signal_for_rich_idle_baseline(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
    reasons: list[str],
    cfg: LowSignalConfig,
) -> bool:
    """Allow long, structurally rich feed/news idle baselines to count.

    Some social/news apps keep background-refresh, analytics, and handshake-heavy
    traffic low in byte volume while still providing reproducible runtime
    evidence. For these categories, sustained duration plus corroborating
    domain/service/TLS evidence is stronger than raw byte volume alone.
    """
    profile = str(run_profile or "").strip().lower()
    if profile != "baseline_idle":
        return False
    if not _is_rich_idle_category_package(package_name):
        return False
    if not reasons:
        return False
    allowed_quiet_reasons = {"PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"}
    if any(reason not in allowed_quiet_reasons for reason in reasons):
        return False

    metrics = _baseline_evidence_metrics(run_dir)
    if not metrics["pcap_quality_ok"]:
        return False
    if metrics["duration_s"] < max(float(cfg.min_capture_duration_s), _RICH_IDLE_MIN_DURATION_S):
        return False
    if metrics["packet_count"] < _RICH_IDLE_MIN_PACKETS:
        return False
    if not metrics["has_evidence"]:
        return False

    corroboration_hits = 0
    if metrics["domain_count"] >= _RICH_IDLE_MIN_DOMAINS:
        corroboration_hits += 1
    if metrics["service_count"] >= _RICH_IDLE_MIN_SERVICES:
        corroboration_hits += 1
    if metrics["ja4_count"] >= _RICH_IDLE_MIN_JA4:
        corroboration_hits += 1
    if metrics["tls_hello_count"] >= _RICH_IDLE_MIN_TLS_HELLOS:
        corroboration_hits += 1
    return corroboration_hits >= 2


def _baseline_evidence_metrics(run_dir: Path) -> dict[str, Any]:
    pf = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
    report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}
    quality = pf.get("quality") if isinstance(pf.get("quality"), dict) else {}
    capinfos = report.get("capinfos") if isinstance(report.get("capinfos"), dict) else {}
    capinfos_parsed = capinfos.get("parsed") if isinstance(capinfos.get("parsed"), dict) else {}

    pcap_quality_ok = True
    if quality.get("pcap_valid") is False:
        pcap_quality_ok = False
    report_status = str(quality.get("report_status") or report.get("report_status") or "").strip().lower()
    if report_status and report_status != "ok":
        pcap_quality_ok = False

    duration_s = _safe_float(
        metrics.get("capture_duration_s"),
        fallback=report.get("capture_duration_s") or capinfos_parsed.get("capture_duration_s"),
    )
    packet_count = _safe_int(
        metrics.get("packet_count"),
        fallback=report.get("packet_count") or capinfos_parsed.get("packet_count"),
    )
    domain_count = _safe_int(
        proxies.get("unique_domains_topn"),
        fallback=report.get("service_domain_unique_count")
        or report.get("service_domain_count")
        or _count_top_domains(report),
    )
    service_count = _service_count(pf, report)
    ja4_count = _safe_int(
        proxies.get("unique_ja4_count"),
        fallback=_nested_int(pf, ("fingerprints", "summary", "unique_ja4_count"))
        or _nested_int(report, ("tls_fingerprints", "unique_ja4_count")),
    )
    tls_hello_count = _safe_int(
        proxies.get("tls_client_hello_count"),
        fallback=_nested_int(report, ("tls_fingerprints", "client_hello_count")),
    )

    has_evidence = bool(domain_count > 0 or service_count > 0 or ja4_count > 0 or tls_hello_count > 0)
    return {
        "pcap_quality_ok": pcap_quality_ok,
        "duration_s": duration_s,
        "packet_count": packet_count,
        "domain_count": domain_count,
        "service_count": service_count,
        "ja4_count": ja4_count,
        "tls_hello_count": tls_hello_count,
        "has_evidence": has_evidence,
    }


def _safe_float(value: Any, *, fallback: Any = None) -> float:
    for candidate in (value, fallback):
        try:
            if candidate is not None and candidate != "":
                return float(candidate)
        except Exception:
            continue
    return 0.0


def _safe_int(value: Any, *, fallback: Any = None) -> int:
    for candidate in (value, fallback):
        try:
            if candidate is not None and candidate != "":
                return int(candidate)
        except Exception:
            continue
    return 0


def _nested_int(mapping: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    try:
        return int(current) if current not in (None, "") else None
    except Exception:
        return None


def _count_top_domains(report: dict[str, Any]) -> int:
    domains: set[str] = set()
    for key in ("top_sni_server_names", "top_dns_qnames", "service_domains"):
        value = report.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, dict):
                text = str(item.get("value") or item.get("domain") or item.get("name") or "").strip()
            else:
                text = str(item or "").strip()
            if text:
                domains.add(text.lower())
    return len(domains)


def _service_count(pf: dict[str, Any], report: dict[str, Any]) -> int:
    for source in (pf, report):
        service_context = source.get("service_context") if isinstance(source.get("service_context"), dict) else {}
        summary = service_context.get("summary") if isinstance(service_context.get("summary"), dict) else service_context
        for key in ("service_count", "matched_service_count"):
            count = _safe_int(summary.get(key)) if isinstance(summary, dict) else 0
            if count:
                return count
        services = summary.get("services") if isinstance(summary, dict) else None
        if isinstance(services, list) and services:
            return len(services)
    return 0


def _should_suppress_domains_low_for_messaging_call(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
) -> bool:
    pkg = str(package_name or "").strip().lower()
    profile = str(run_profile or "").strip().lower()
    if not profile.startswith("interaction"):
        return False

    messaging_pkgs = {p.lower() for p in MESSAGING_PACKAGES}
    category = category_for_package(pkg) if pkg else None
    if not (pkg in messaging_pkgs or category == "messaging"):
        return False

    manifest = _read_json(run_dir / "run_manifest.json") or {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    activity = str(operator.get("messaging_activity") or "").strip().lower()
    if activity not in {"voice_call", "video_call"}:
        return False

    pf = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
    report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}

    if _has_messaging_call_media_plane_evidence(pf, report):
        return True

    try:
        packet_count = int(metrics.get("packet_count") or 0)
    except Exception:
        packet_count = 0
    try:
        duration_s = float(metrics.get("capture_duration_s") or 0.0)
    except Exception:
        duration_s = 0.0
    try:
        udp_ratio = float(proxies.get("udp_ratio") or 0.0)
    except Exception:
        udp_ratio = 0.0
    try:
        unique_dst_ip_count = int(proxies.get("unique_dst_ip_count") or 0)
    except Exception:
        unique_dst_ip_count = 0

    return (
        packet_count >= 3000
        and duration_s >= 120.0
        and udp_ratio >= 0.75
        and unique_dst_ip_count >= 3
    )


def _has_messaging_call_media_plane_evidence(pf: dict[str, Any], report: dict[str, Any]) -> bool:
    """Return true when media-plane evidence proves a call despite sparse DNS/SNI."""

    summaries: list[dict[str, Any]] = []
    for source in (pf, report):
        media_plane = source.get("media_plane") if isinstance(source.get("media_plane"), dict) else {}
        summary = media_plane.get("summary") if isinstance(media_plane.get("summary"), dict) else {}
        if isinstance(summary, dict) and summary:
            summaries.append(summary)

    for summary in summaries:
        if not (
            bool(summary.get("rtc_call_observed"))
            or bool(summary.get("relay_media_likely"))
            or _safe_int(summary.get("rtc_sustained_session_count")) > 0
        ):
            continue
        if (
            _safe_int(summary.get("rtc_total_packets")) >= 500
            or _safe_int(summary.get("rtc_total_bytes")) >= 500_000
            or _safe_float(summary.get("rtc_max_session_duration_s")) >= 60.0
            or _safe_int(summary.get("stun_frame_count")) >= 500
        ):
            return True
    return False


def _effective_low_signal_config(
    config: LowSignalConfig,
    *,
    package_name: str | None,
    run_profile: str | None,
) -> LowSignalConfig:
    pkg = str(package_name or "").strip().lower()
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline") and _is_chat_like_package(pkg):
        # Messaging/chat idle can be comparatively quiet; relax byte threshold only.
        return LowSignalConfig(
            min_capture_duration_s=float(config.min_capture_duration_s),
            min_data_size_bytes=min(int(config.min_data_size_bytes), int(_RELAXED_IDLE_MIN_BYTES)),
            min_packet_count=int(config.min_packet_count),
            min_unique_domains_topn=int(config.min_unique_domains_topn),
        )
    if profile.startswith("interaction") and _is_chat_like_package(pkg):
        # Interaction on messaging apps: relax byte/packet/domain floors when capture is structurally valid.
        return LowSignalConfig(
            min_capture_duration_s=float(config.min_capture_duration_s),
            min_data_size_bytes=min(int(config.min_data_size_bytes), int(_RELAXED_IDLE_MIN_BYTES)),
            min_packet_count=min(int(config.min_packet_count), 250),
            min_unique_domains_topn=min(int(config.min_unique_domains_topn), 1),
        )
    return config


def _is_chat_like_package(package_name: str | None) -> bool:
    pkg = str(package_name or "").strip().lower()
    if not pkg:
        return False
    messaging_pkgs = {p.lower() for p in MESSAGING_PACKAGES}
    category = category_for_package(pkg)
    return pkg in _CHAT_LIKE_BASELINE_PACKAGES or pkg in messaging_pkgs or category == "messaging"


def _is_rich_idle_category_package(package_name: str | None) -> bool:
    pkg = str(package_name or "").strip().lower()
    if not pkg:
        return False
    return category_for_package(pkg) in _RICH_IDLE_CATEGORY_NAMES


__all__ = [
    "LowSignalConfig",
    "compute_low_signal_from_evidence_pack",
    "compute_low_signal_for_run",
]
