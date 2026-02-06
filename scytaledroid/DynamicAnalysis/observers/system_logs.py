"""Placeholder system log observer."""

from __future__ import annotations

import hashlib
import subprocess

from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle, ObserverResult


class SystemLogObserver(Observer):
    observer_id = "system_log_capture"
    observer_name = "System Logs"

    def start(self, run_ctx: RunContext) -> ObserverHandle:
        if not adb_client.is_available():
            raise RuntimeError("adb binary not available on PATH")
        if not run_ctx.device_serial:
            raise RuntimeError("device serial required for logcat capture")
        if run_ctx.clear_logcat:
            try:
                adb_client.run_adb_command(
                    ["-s", run_ctx.device_serial, "logcat", "-c"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except Exception:
                pass
        relative_path = f"artifacts/{self.observer_id}/logcat.txt"
        path = run_ctx.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("w", encoding="utf-8")
        process = adb_client.run_adb_popen(
            ["-s", run_ctx.device_serial, "logcat", "-v", "threadtime"],
            stdout=handle,
            stderr=subprocess.PIPE,
            text=True,
        )
        return ObserverHandle(observer_id=self.observer_id, payload=(process, handle, relative_path))

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        if handle is None or handle.payload is None:
            raise RuntimeError("logcat handle missing")
        process, file_handle, relative_path = handle.payload
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        file_handle.flush()
        file_handle.close()
        path = run_ctx.run_dir / relative_path
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        artifact = ArtifactRecord(
            relative_path=relative_path,
            type="system_log_capture",
            sha256=digest,
            size_bytes=path.stat().st_size,
            produced_by=self.observer_id,
            origin="host",
            pull_status="n/a",
        )
        return ObserverResult(
            observer_id=self.observer_id,
            status="success",
            error=None,
            artifacts=[artifact],
        )


__all__ = ["SystemLogObserver"]
