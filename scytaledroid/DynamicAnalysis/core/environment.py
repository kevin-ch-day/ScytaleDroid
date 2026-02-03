"""Environment management for dynamic analysis runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DeviceAnalysis import adb_devices, adb_shell
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass(frozen=True)
class EnvironmentSnapshot:
    metadata: dict[str, Any]
    artifacts: list[ArtifactRecord]


class EnvironmentManager:
    def prepare(self, run_ctx: RunContext) -> EnvironmentSnapshot:
        artifacts: list[ArtifactRecord] = []
        metadata: dict[str, Any] = {}
        if run_ctx.device_serial:
            metadata.update(adb_devices.get_basic_properties(run_ctx.device_serial))
            metadata["device_serial"] = run_ctx.device_serial
            metadata["build_fingerprint"] = metadata.get("build_fingerprint")
            play_services = adb_devices.get_play_services_version(run_ctx.device_serial)
            if play_services:
                metadata["play_services_version"] = play_services
        device_info_path = self._write_json(
            run_ctx,
            "artifacts/environment/device_info.json",
            metadata,
        )
        artifacts.append(self._artifact_record(run_ctx, device_info_path, "device_info"))
        if run_ctx.device_serial:
            self._clear_app_data(run_ctx)
            permissions_before = self._capture_permissions(run_ctx, "permissions_before.txt")
            artifacts.append(
                self._artifact_record(run_ctx, permissions_before, "permissions_snapshot")
            )
        return EnvironmentSnapshot(metadata=metadata, artifacts=artifacts)

    def finalize(self, run_ctx: RunContext) -> EnvironmentSnapshot:
        artifacts: list[ArtifactRecord] = []
        metadata: dict[str, Any] = {}
        if run_ctx.device_serial:
            permissions_after = self._capture_permissions(run_ctx, "permissions_after.txt")
            artifacts.append(
                self._artifact_record(run_ctx, permissions_after, "permissions_snapshot")
            )
        return EnvironmentSnapshot(metadata=metadata, artifacts=artifacts)

    def _clear_app_data(self, run_ctx: RunContext) -> None:
        adb_shell.run_shell(run_ctx.device_serial or "", ["pm", "clear", run_ctx.package_name])

    def _capture_permissions(self, run_ctx: RunContext, filename: str) -> Path:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["dumpsys", "package", run_ctx.package_name],
        )
        path = run_ctx.run_dir / f"artifacts/environment/{filename}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output)
        return path

    def _write_json(self, run_ctx: RunContext, relative_path: str, payload: dict[str, Any]) -> Path:
        path = run_ctx.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        return path

    def _artifact_record(self, run_ctx: RunContext, path: Path, artifact_type: str) -> ArtifactRecord:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return ArtifactRecord(
            relative_path=str(path.relative_to(run_ctx.run_dir)),
            type=artifact_type,
            sha256=digest,
            size_bytes=path.stat().st_size,
            produced_by="environment_manager",
        )


__all__ = ["EnvironmentManager", "EnvironmentSnapshot"]
