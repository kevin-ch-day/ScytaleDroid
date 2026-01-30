"""Network capture observer using adb tcpdump when available."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from scytaledroid.DeviceAnalysis import adb_client, adb_shell

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle, ObserverResult


class NetworkCaptureObserver(Observer):
    observer_id = "network_capture"
    observer_name = "Network Capture"

    def start(self, run_ctx: RunContext) -> ObserverHandle:
        if not run_ctx.device_serial:
            raise RuntimeError("device serial required for network capture")
        tcpdump_path = adb_shell.run_shell(
            run_ctx.device_serial,
            ["which", "tcpdump"],
        ).strip()
        if not tcpdump_path:
            return ObserverHandle(
                observer_id=self.observer_id,
                payload={"skipped": True, "reason": "tcpdump not available on device"},
            )
        device_path = "/sdcard/scytaledroid_dynamic_capture.pcapng"
        process = adb_client.run_adb_popen(
            [
                "-s",
                run_ctx.device_serial,
                "shell",
                "tcpdump",
                "-i",
                "any",
                "-p",
                "-s",
                "0",
                "-w",
                device_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return ObserverHandle(
            observer_id=self.observer_id,
            payload={
                "process": process,
                "device_path": device_path,
            },
        )

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        if handle is None or handle.payload is None:
            raise RuntimeError("network capture handle missing")
        payload = handle.payload
        process = payload["process"]
        device_path = payload["device_path"]
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        relative_path = f"artifacts/{self.observer_id}/capture.pcapng"
        path = run_ctx.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        pull = adb_client.run_adb_command(
            ["-s", run_ctx.device_serial or "", "pull", device_path, str(path)],
            capture_output=True,
            text=True,
        )
        artifacts: list[ArtifactRecord] = []
        if pull.returncode != 0 or not path.exists():
            error_path = run_ctx.run_dir / f"artifacts/{self.observer_id}/observer_error.txt"
            error_path.write_text(pull.stderr or "Failed to pull capture file.")
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
                status="failed",
                error=pull.stderr or "Failed to pull capture file.",
                artifacts=artifacts,
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        artifacts.append(
            ArtifactRecord(
                relative_path=relative_path,
                type="network_capture",
                sha256=digest,
                size_bytes=path.stat().st_size,
                produced_by=self.observer_id,
            )
        )
        flow_summary_path = self._write_flow_summary(path, run_ctx)
        if flow_summary_path:
            summary_digest = hashlib.sha256(flow_summary_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(flow_summary_path.relative_to(run_ctx.run_dir)),
                    type="network_flow_summary",
                    sha256=summary_digest,
                    size_bytes=flow_summary_path.stat().st_size,
                    produced_by=self.observer_id,
                )
            )
        return ObserverResult(
            observer_id=self.observer_id,
            status="success",
            error=None,
            artifacts=artifacts,
        )

    def _write_flow_summary(self, capture_path: Path, run_ctx: RunContext) -> Path | None:
        tcpdump_bin = shutil.which("tcpdump")
        summary_path = run_ctx.run_dir / f"artifacts/{self.observer_id}/flow_summary.json"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        if tcpdump_bin is None:
            summary_path.write_text(
                '{"destinations": [], "notes": "tcpdump not available on host"}\n'
            )
            return summary_path
        result = subprocess.run(
            [tcpdump_bin, "-nn", "-r", str(capture_path)],
            capture_output=True,
            text=True,
        )
        destinations: set[str] = set()
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if " > " not in line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                src = parts[2]
                dst = parts[4].rstrip(":")
                destinations.add(src)
                destinations.add(dst)
        summary = {
            "destinations": sorted(destinations),
            "notes": "parsed via tcpdump -nn -r" if destinations else "no destinations parsed",
        }
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        return summary_path


__all__ = ["NetworkCaptureObserver"]
