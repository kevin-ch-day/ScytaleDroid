"""Derived PCAP indexing for dynamic runs."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest

_SCENARIO_SAFE = re.compile(r"[^a-z0-9_-]+")
_PACKAGE_DIR_SAFE = re.compile(r"[^A-Za-z0-9._]+")


@dataclass(frozen=True)
class PcapIndexConfig:
    min_bytes: int = 30 * 1024
    max_scenario_len: int = 48


def index_pcap_by_app(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: PcapIndexConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> Path | None:
    cfg = config or PcapIndexConfig()
    tier = None
    if isinstance(manifest.operator, dict):
        tier = manifest.operator.get("tier")
    if tier and str(tier).lower() != "dataset":
        _log(event_logger, "pcap_index_skip_tier", {"tier": tier})
        return None
    pcap_artifact = _find_pcap_artifact(manifest)
    if not pcap_artifact:
        _log(event_logger, "pcap_index_skip_missing", {"reason": "pcap_artifact_missing"})
        return None
    rel_path = pcap_artifact.relative_path
    if not rel_path:
        _log(event_logger, "pcap_index_skip_missing", {"reason": "pcap_relative_path_missing"})
        return None
    run_root = run_dir.expanduser().resolve()
    src_path = (run_dir / rel_path).resolve()
    if not src_path.is_relative_to(run_root):
        _log(
            event_logger,
            "pcap_index_skip_missing",
            {"reason": "pcap_path_unconfined", "path": str(src_path)},
        )
        return None
    if not src_path.is_file():
        _log(
            event_logger,
            "pcap_index_skip_missing",
            {"reason": "pcap_file_missing", "path": str(src_path)},
        )
        return None
    size_bytes = pcap_artifact.size_bytes or src_path.stat().st_size
    if size_bytes < cfg.min_bytes:
        _log(
            event_logger,
            "pcap_index_skip_invalid",
            {"reason": "pcap_too_small", "size_bytes": size_bytes},
        )
        return None
    package = _safe_package_dir_name(manifest.target.get("package_name") or "_unknown")
    scenario_id = manifest.scenario.get("id") or "scenario"
    scenario_slug = _slugify(str(scenario_id), cfg.max_scenario_len)
    capture_scope = _capture_scope(manifest, run_dir) or "app_only"
    timestamp = _format_timestamp(manifest.scenario.get("started_at") or manifest.started_at)
    run_short = _slugify(str(manifest.dynamic_run_id or "run"), 12)
    filename = f"{timestamp}__{scenario_slug}__pcap-{capture_scope}__run-{run_short}.pcap"
    by_app_root = (Path(app_config.DATA_DIR) / "archive" / "pcap" / "by_app").resolve()
    dest_dir = by_app_root / package
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = (dest_dir / filename).resolve()
    except OSError:
        _log(event_logger, "pcap_index_skip_invalid", {"reason": "pcap_dest_unusable"})
        return None
    if not dest_path.is_relative_to(by_app_root):
        _log(event_logger, "pcap_index_skip_invalid", {"reason": "pcap_dest_unconfined"})
        return None
    final_path = _copy_atomic(src_path, dest_path, size_bytes)
    _log(
        event_logger,
        "pcap_index_written",
        {
            "source": str(src_path.relative_to(run_root)),
            "destination": str(final_path),
            "size_bytes": size_bytes,
        },
    )
    return final_path


def _find_pcap_artifact(manifest: RunManifest):
    for artifact in manifest.artifacts:
        if artifact.type == "pcapdroid_capture":
            return artifact
    return None


def _capture_scope(manifest: RunManifest, run_dir: Path) -> str | None:
    for artifact in manifest.artifacts:
        if artifact.type != "pcapdroid_capture_meta":
            continue
        if not artifact.relative_path:
            continue
        meta_path = run_dir / artifact.relative_path
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        capture_mode = payload.get("capture_mode")
        if isinstance(capture_mode, str) and capture_mode:
            return _slugify(capture_mode, 16)
    return None


def _safe_package_dir_name(package: str) -> str:
    raw = str(package or "").strip() or "_unknown"
    if raw in {".", ".."} or "/" in raw or "\\" in raw or "\x00" in raw or ".." in raw:
        slug = _PACKAGE_DIR_SAFE.sub("_", raw).replace("..", "_").strip("._")
        return slug[:191] or "_unknown"
    return raw[:191]


def _slugify(value: str, max_len: int) -> str:
    lowered = value.strip().lower()
    lowered = _SCENARIO_SAFE.sub("_", lowered)
    lowered = lowered.strip("_")
    if not lowered:
        lowered = "scenario"
    if len(lowered) > max_len:
        lowered = lowered[:max_len].rstrip("_")
    return lowered


def _format_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(UTC).strftime("%Y%m%d_%H%M%SZ")
    try:
        raw = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(UTC).strftime("%Y%m%d_%H%M%SZ")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y%m%d_%H%M%SZ")


def _copy_atomic(src: Path, dest: Path, size_bytes: int) -> Path:
    if dest.exists():
        if dest.stat().st_size == size_bytes:
            return dest
        dest = _dedupe_path(dest)
    tmp_path = dest.with_suffix(dest.suffix + ".tmp")
    shutil.copy2(src, tmp_path)
    if tmp_path.stat().st_size != size_bytes:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError("pcap index copy size mismatch")
    tmp_path.replace(dest)
    return dest


def _dedupe_path(dest: Path) -> Path:
    stem = dest.stem
    suffix = dest.suffix
    for idx in range(2, 10):
        candidate = dest.with_name(f"{stem}__dup{idx}{suffix}")
        if not candidate.exists():
            return candidate
    return dest.with_name(f"{stem}__dup{int(datetime.now(UTC).timestamp())}{suffix}")


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, object]) -> None:
    if not event_logger:
        return
    event_logger.log(event, payload)


__all__ = ["PcapIndexConfig", "index_pcap_by_app"]
