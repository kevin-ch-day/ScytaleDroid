"""PCAPdroid VPN-based network capture observer (non-root)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle, ObserverResult

PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_COMPONENT = "com.emanuelef.remote_capture/.activities.CaptureCtrl"
PCAPDROID_DOWNLOAD_DIR = "/sdcard/Download/PCAPdroid"
MIN_PCAP_BYTES = int(getattr(app_config, "DYNAMIC_MIN_PCAP_BYTES", 100000))
CAPTURE_MODE = "app_only"
FINALIZE_MIN_WAIT_S = 5.0
FINALIZE_MAX_WAIT_S = 12.0
FINALIZE_STABLE_POLLS = 2


def _effective_min_pcap_bytes(run_ctx: RunContext) -> int:
    """Return observer-side PCAP floor aligned with run mode.

    Dataset/freeze runs should use the freeze contract floor; other modes keep the
    operational fallback from app config.
    """
    profile = str(getattr(run_ctx, "run_profile", "") or "").strip().lower()
    if profile.startswith("baseline_") or profile.startswith("interaction_"):
        return int(getattr(profile_config, "MIN_PCAP_BYTES", MIN_PCAP_BYTES))
    return int(MIN_PCAP_BYTES)


class PcapdroidCaptureObserver(Observer):
    observer_id = "pcapdroid_capture"
    observer_name = "PCAPdroid VPN Capture"

    def __init__(self, *, api_key: str | None = None) -> None:
        # Read secrets at config build time only. Never read env vars in start/stop.
        self._api_key = api_key

    def start(self, run_ctx: RunContext) -> ObserverHandle:
        if not adb_client.is_available():
            raise RuntimeError("adb binary not available on PATH")
        if not run_ctx.device_serial:
            raise RuntimeError("device serial required for PCAPdroid capture")
        if not _pcapdroid_installed(run_ctx.device_serial):
            raise RuntimeError("PCAPdroid not installed on device")

        capture_dir = run_ctx.run_dir / f"artifacts/{self.observer_id}"
        capture_dir.mkdir(parents=True, exist_ok=True)
        meta_path = capture_dir / "pcapdroid_capture_meta.json"

        pcap_name = f"scytaledroid_{run_ctx.dynamic_run_id}.pcap"
        device_path = f"{PCAPDROID_DOWNLOAD_DIR}/{pcap_name}"
        api_key = self._api_key
        capture_start = time.time()

        start_args = [
            "am",
            "start",
            "-e",
            "action",
            "start",
            "-e",
            "pcap_dump_mode",
            "pcap_file",
            "-e",
            "pcap_name",
            pcap_name,
            "-e",
            "app_filter",
            run_ctx.package_name,
            "-n",
            PCAPDROID_COMPONENT,
        ]
        if api_key:
            start_args = start_args[:-2] + ["-e", "api_key", api_key] + start_args[-2:]

        adb_shell.run_shell(run_ctx.device_serial, start_args)
        status_ok, status_error = _pcapdroid_status_ok(run_ctx.device_serial, api_key)
        newest_hint = _peek_latest_pcapdroid(run_ctx.device_serial, min_epoch=capture_start)
        start_probe = _poll_latest_pcapdroid(
            run_ctx.device_serial,
            min_epoch=capture_start,
            timeout_s=2.0,
        )
        if status_ok is None and start_probe.get("latest_path"):
            status_ok = True
        if status_ok is False:
            raise RuntimeError(status_error or "PCAPdroid capture did not start")
        meta_path.write_text(
            json.dumps(
                {
                    "pcap_name": pcap_name,
                    "device_path": device_path,
                    "app_filter": run_ctx.package_name,
                    "capture_mode": CAPTURE_MODE,
                    "pcapdroid_package": PCAPDROID_PACKAGE,
                    "api_key_present": bool(api_key),
                    "capture_start_epoch": capture_start,
                    "status_check": {
                        "ok": status_ok,
                        "error": status_error,
                    },
                    "start_hint": newest_hint,
                    "start_probe": start_probe,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return ObserverHandle(
            observer_id=self.observer_id,
            payload={
                "pcap_name": pcap_name,
                "device_path": device_path,
                "meta_path": meta_path,
                "capture_start_epoch": capture_start,
                "api_key_present": bool(api_key),
            },
        )

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        if handle is None or handle.payload is None:
            raise RuntimeError("PCAPdroid capture handle missing")
        payload = handle.payload
        pcap_name: str = payload["pcap_name"]
        device_path: str = payload["device_path"]
        meta_path: Path = payload["meta_path"]
        capture_start_epoch = payload.get("capture_start_epoch")
        api_key = self._api_key

        stop_args = [
            "am",
            "start",
            "-e",
            "action",
            "stop",
            "-n",
            PCAPDROID_COMPONENT,
        ]
        if api_key:
            stop_args = stop_args[:-2] + ["-e", "api_key", api_key] + stop_args[-2:]
        adb_shell.run_shell(run_ctx.device_serial, stop_args)

        artifacts: list[ArtifactRecord] = []
        status = "success"
        error = None
        min_pcap_bytes = _effective_min_pcap_bytes(run_ctx)

        local_path = meta_path.parent / pcap_name
        try:
            if capture_start_epoch is not None:
                _wait_for_finalized_pcap(
                    run_ctx.device_serial,
                    device_path,
                    min_epoch=capture_start_epoch,
                )
            resolved_path = _wait_for_capture_path(
                run_ctx.device_serial,
                device_path,
                min_epoch=capture_start_epoch,
            )
            resolved_from_fallback = False
            if resolved_path:
                if resolved_path != device_path:
                    resolved_from_fallback = True
                device_path = resolved_path
                resolved_name = Path(resolved_path).name
                local_path = meta_path.parent / resolved_name
                if meta_path.exists():
                    try:
                        meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                    except Exception:
                        meta_payload = {}
                    meta_payload["resolved_device_path"] = resolved_path
                    meta_payload["resolved_pcap_name"] = resolved_name
                    meta_payload["resolved_from_fallback"] = resolved_from_fallback
                    meta_path.write_text(
                        json.dumps(meta_payload, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )
                _pull_with_retries(
                    run_ctx.device_serial,
                    device_path,
                    local_path,
                    min_bytes=min_pcap_bytes,
                )
            if not local_path.exists():
                fallback_path = _latest_pcapdroid_capture(
                    run_ctx.device_serial,
                    min_epoch=capture_start_epoch,
                )
                if fallback_path and fallback_path != device_path:
                    resolved_from_fallback = True
                    device_path = fallback_path
                    resolved_name = Path(fallback_path).name
                    local_path = meta_path.parent / resolved_name
                    _pull_with_retries(
                        run_ctx.device_serial,
                        device_path,
                        local_path,
                        min_bytes=min_pcap_bytes,
                    )
                    if meta_path.exists():
                        try:
                            meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                        except Exception:
                            meta_payload = {}
                        meta_payload["resolved_device_path"] = fallback_path
                        meta_payload["resolved_pcap_name"] = resolved_name
                        meta_payload["resolved_from_fallback"] = True
                        meta_path.write_text(
                            json.dumps(meta_payload, indent=2, sort_keys=True),
                            encoding="utf-8",
                        )
            mismatch_warning = None
            if local_path.exists():
                file_size = local_path.stat().st_size
                if file_size < min_pcap_bytes:
                    error = (
                        f"PCAPdroid capture file empty/too small "
                        f"({file_size}B < {min_pcap_bytes}B)."
                    )
                    status = "failed"
                    if meta_path.exists():
                        try:
                            meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                        except Exception:
                            meta_payload = {}
                        meta_payload["pcap_size_bytes"] = file_size
                        meta_payload["pcap_valid"] = False
                        meta_payload["min_pcap_bytes"] = min_pcap_bytes
                        meta_path.write_text(
                            json.dumps(meta_payload, indent=2, sort_keys=True),
                            encoding="utf-8",
                        )
                else:
                    resolved_name = local_path.name
                    if run_ctx.dynamic_run_id not in resolved_name:
                        mismatch_warning = (
                            "PCAPdroid capture filename mismatch (fallback file does not match run id)."
                        )
                    digest = _sha256_stream(local_path)
                    artifacts.append(
                        ArtifactRecord(
                            relative_path=str(local_path.relative_to(run_ctx.run_dir)),
                            type="pcapdroid_capture",
                            sha256=digest,
                            size_bytes=local_path.stat().st_size,
                            produced_by=self.observer_id,
                            origin="device",
                            device_path=device_path,
                            pull_status="pulled",
                        )
                    )
                    if meta_path.exists():
                        try:
                            meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                        except Exception:
                            meta_payload = {}
                        meta_payload["pcap_size_bytes"] = file_size
                        meta_payload["pcap_valid"] = True
                        meta_payload["min_pcap_bytes"] = min_pcap_bytes
                        meta_path.write_text(
                            json.dumps(meta_payload, indent=2, sort_keys=True),
                            encoding="utf-8",
                        )
            else:
                status = "failed"
                error = "PCAPdroid capture file missing after pull."
                if meta_path.exists():
                    try:
                        meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                    except Exception:
                        meta_payload = {}
                    meta_payload["pcap_size_bytes"] = 0
                    meta_payload["pcap_valid"] = False
                    meta_payload["min_pcap_bytes"] = min_pcap_bytes
                    meta_path.write_text(
                        json.dumps(meta_payload, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )
        except Exception as exc:
            status = "failed"
            error = f"PCAPdroid capture failed: {exc}"

        if mismatch_warning and status == "success":
            error = mismatch_warning
            if meta_path.exists():
                try:
                    meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta_payload = {}
                meta_payload["mismatch_warning"] = mismatch_warning
                meta_path.write_text(
                    json.dumps(meta_payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )

        # pcapdroid_capture_meta.json is not treated as an immutable artifact (it may be
        # enriched later by post-processing). Do not include sha256 to avoid integrity
        # failures "by construction". Freeze immutability relies on dataset-level
        # checksums, not these best-effort hashes.
        if meta_path.exists():
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(meta_path.relative_to(run_ctx.run_dir)),
                    type="pcapdroid_capture_meta",
                    sha256=None,
                    size_bytes=meta_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )

        if status == "failed":
            error_path = meta_path.parent / "observer_error.txt"
            error_path.write_text(error or "", encoding="utf-8")
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                    type="observer_error",
                    sha256=None,
                    size_bytes=error_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )
        elif error:
            error_path = meta_path.parent / "observer_error.txt"
            error_path.write_text(error or "", encoding="utf-8")
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                    type="observer_error",
                    sha256=None,
                    size_bytes=error_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )

        return ObserverResult(
            observer_id=self.observer_id,
            status=status,
            error=error,
            artifacts=artifacts,
        )


def _pcapdroid_installed(device_serial: str) -> bool:
    try:
        output = adb_shell.run_shell(device_serial, ["pm", "path", PCAPDROID_PACKAGE])
    except Exception:
        return False
    return "package:" in output


def _sha256_stream(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pcapdroid_status_ok(device_serial: str, api_key: str | None) -> tuple[bool | None, str | None]:
    status_args = [
        "am",
        "start",
        "-e",
        "action",
        "get_status",
        "-n",
        PCAPDROID_COMPONENT,
    ]
    if api_key:
        status_args = status_args[:-2] + ["-e", "api_key", api_key] + status_args[-2:]
    try:
        output = adb_shell.run_shell(device_serial, status_args)
    except Exception as exc:
        return None, f"PCAPdroid status check failed: {exc}"
    lowered = output.lower()
    if "running=true" in lowered:
        return True, None
    if "running=false" in lowered:
        return False, "PCAPdroid reported running=false"
    return None, "PCAPdroid status unavailable"


def _device_file_exists(device_serial: str, path: str) -> bool:
    try:
        completed = adb_shell.run_shell_command(device_serial, ["ls", "-l", path])
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    stderr = (completed.stderr or "").lower()
    if "no such file" in stderr:
        return False
    return True


def _device_file_size(device_serial: str, path: str) -> int | None:
    try:
        output = adb_shell.run_shell(device_serial, ["stat", "-c", "%s", path]).strip()
        return int(output)
    except Exception:
        return None


def _pull_with_retries(
    device_serial: str,
    device_path: str,
    local_path: Path,
    *,
    retries: int = 3,
    delay_s: float = 0.5,
    min_bytes: int | None = None,
) -> bool:
    for _ in range(max(retries, 1)):
        if not _device_file_exists(device_serial, device_path):
            time.sleep(delay_s)
            continue
        device_size = _device_file_size(device_serial, device_path)
        adb_client.run_adb_command(
            ["-s", device_serial, "pull", device_path, str(local_path)],
        )
        if local_path.exists():
            local_size = local_path.stat().st_size
            if device_size is not None and local_size < device_size:
                time.sleep(delay_s)
                continue
            if min_bytes is not None and device_size is not None:
                if device_size >= min_bytes and local_size < min_bytes:
                    time.sleep(delay_s)
                    continue
            return True
        time.sleep(delay_s)
    return False


def _latest_pcapdroid_capture(device_serial: str, *, min_epoch: float | None = None) -> str | None:
    try:
        output = adb_shell.run_shell(
            device_serial,
            [
                "sh",
                "-c",
                (
                    f"ls -t {PCAPDROID_DOWNLOAD_DIR}/*.pcap* "
                    f"{PCAPDROID_DOWNLOAD_DIR}/.trashed-*.pcap* 2>/dev/null | head -n 1"
                ),
            ],
        ).strip()
    except Exception:
        return None
    if not output.startswith(PCAPDROID_DOWNLOAD_DIR):
        return None
    if min_epoch is None:
        return output
    try:
        stat_out = adb_shell.run_shell(device_serial, ["stat", "-c", "%Y", output]).strip()
        mtime = float(stat_out)
        if mtime + 2 < float(min_epoch):
            return None
    except Exception:
        return None
    return output


def _peek_latest_pcapdroid(device_serial: str, *, min_epoch: float | None = None) -> dict[str, object]:
    path = _latest_pcapdroid_capture(device_serial, min_epoch=min_epoch)
    if not path:
        return {"latest_path": None, "latest_mtime": None}
    mtime = None
    try:
        stat_out = adb_shell.run_shell(device_serial, ["stat", "-c", "%Y", path]).strip()
        mtime = float(stat_out)
    except Exception:
        mtime = None
    return {"latest_path": path, "latest_mtime": mtime}


def _poll_latest_pcapdroid(
    device_serial: str, *, min_epoch: float | None = None, timeout_s: float = 2.0
) -> dict[str, object]:
    deadline = time.time() + max(timeout_s, 0.1)
    last = {"latest_path": None, "latest_mtime": None}
    while time.time() < deadline:
        last = _peek_latest_pcapdroid(device_serial, min_epoch=min_epoch)
        if last.get("latest_path"):
            return last
        time.sleep(0.2)
    return last


def _wait_for_capture_path(
    device_serial: str,
    expected_path: str,
    *,
    min_epoch: float | None = None,
    timeout_s: float = 6.0,
    poll_s: float = 0.5,
) -> str | None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _device_file_exists(device_serial, expected_path):
            return expected_path
        fallback = _latest_pcapdroid_capture(device_serial, min_epoch=min_epoch)
        if fallback:
            return fallback
        time.sleep(poll_s)
    return None


def _wait_for_finalized_pcap(
    device_serial: str,
    expected_path: str,
    *,
    min_epoch: float | None = None,
) -> None:
    """Wait for a PCAP to appear and stabilize in size before pulling."""

    time.sleep(max(FINALIZE_MIN_WAIT_S, 0.0))
    deadline = time.time() + max(FINALIZE_MAX_WAIT_S, 0.1)
    stable_hits = 0
    last_size = None

    while time.time() < deadline:
        path = expected_path
        if not _device_file_exists(device_serial, path):
            fallback = _latest_pcapdroid_capture(device_serial, min_epoch=min_epoch)
            if fallback:
                path = fallback
            else:
                time.sleep(0.5)
                continue

        size = _device_file_size(device_serial, path)
        if size is None:
            time.sleep(0.5)
            continue
        if last_size is not None and size == last_size:
            stable_hits += 1
        else:
            stable_hits = 0
        last_size = size
        if stable_hits >= FINALIZE_STABLE_POLLS:
            return
        time.sleep(0.5)


__all__ = ["PcapdroidCaptureObserver", "PCAPDROID_PACKAGE"]
