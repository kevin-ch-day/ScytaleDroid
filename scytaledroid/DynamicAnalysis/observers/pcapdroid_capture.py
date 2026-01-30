"""PCAPdroid VPN-based network capture observer (non-root)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from scytaledroid.DeviceAnalysis import adb_client, adb_shell
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle, ObserverResult

PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_COMPONENT = "com.emanuelef.remote_capture/.activities.CaptureCtrl"
PCAPDROID_DOWNLOAD_DIR = "/sdcard/Download/PCAPdroid"


class PcapdroidCaptureObserver(Observer):
    observer_id = "pcapdroid_capture"
    observer_name = "PCAPdroid VPN Capture"

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
        api_key = os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY")

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
        meta_path.write_text(
            json.dumps(
                {
                    "pcap_name": pcap_name,
                    "device_path": device_path,
                    "app_filter": run_ctx.package_name,
                    "pcapdroid_package": PCAPDROID_PACKAGE,
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
            },
        )

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        if handle is None or handle.payload is None:
            raise RuntimeError("PCAPdroid capture handle missing")
        payload = handle.payload
        pcap_name: str = payload["pcap_name"]
        device_path: str = payload["device_path"]
        meta_path: Path = payload["meta_path"]
        api_key = os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY")

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

        if meta_path.exists():
            digest = hashlib.sha256(meta_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(meta_path.relative_to(run_ctx.run_dir)),
                    type="pcapdroid_capture_meta",
                    sha256=digest,
                    size_bytes=meta_path.stat().st_size,
                    produced_by=self.observer_id,
                )
            )

        local_path = meta_path.parent / pcap_name
        try:
            if _device_file_exists(run_ctx.device_serial, device_path):
                adb_client.run_adb_command(
                    ["-s", run_ctx.device_serial, "pull", device_path, str(local_path)],
                )
            else:
                fallback_path = _latest_pcapdroid_capture(run_ctx.device_serial)
                if fallback_path:
                    device_path = fallback_path
                    local_path = meta_path.parent / Path(fallback_path).name
                    adb_client.run_adb_command(
                        ["-s", run_ctx.device_serial, "pull", device_path, str(local_path)],
                    )
            if local_path.exists():
                digest = hashlib.sha256(local_path.read_bytes()).hexdigest()
                artifacts.append(
                    ArtifactRecord(
                        relative_path=str(local_path.relative_to(run_ctx.run_dir)),
                        type="pcapdroid_capture",
                        sha256=digest,
                        size_bytes=local_path.stat().st_size,
                        produced_by=self.observer_id,
                    )
                )
            else:
                status = "failed"
                error = "PCAPdroid capture file missing after pull."
        except Exception as exc:
            status = "failed"
            error = f"PCAPdroid capture failed: {exc}"

        if status == "failed":
            error_path = meta_path.parent / "observer_error.txt"
            error_path.write_text(error or "", encoding="utf-8")
            digest = hashlib.sha256(error_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                    type="observer_error",
                    sha256=digest,
                    size_bytes=error_path.stat().st_size,
                    produced_by=self.observer_id,
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


def _device_file_exists(device_serial: str, path: str) -> bool:
    try:
        adb_shell.run_shell(device_serial, ["ls", "-l", path])
    except Exception:
        return False
    return True


def _latest_pcapdroid_capture(device_serial: str) -> str | None:
    try:
        output = adb_shell.run_shell(
            device_serial,
            ["sh", "-c", f"ls -t {PCAPDROID_DOWNLOAD_DIR}/*.pcap* 2>/dev/null | head -n 1"],
        ).strip()
    except Exception:
        return None
    return output if output.startswith(PCAPDROID_DOWNLOAD_DIR) else None


__all__ = ["PcapdroidCaptureObserver", "PCAPDROID_PACKAGE"]
