"""Target management helpers for dynamic analysis runs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
from typing import Any

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass(frozen=True)
class TargetSnapshot:
    metadata: dict[str, Any]
    artifacts: list[ArtifactRecord]


class TargetManager:
    def prepare(self, run_ctx: RunContext) -> TargetSnapshot:
        if not run_ctx.device_serial:
            return TargetSnapshot(metadata={}, artifacts=[])
        artifacts: list[ArtifactRecord] = []
        metadata: dict[str, Any] = {}
        package_info, package_artifact = self._capture_package_info(run_ctx)
        metadata.update(package_info)
        artifacts.append(package_artifact)
        launch_output = self._launch_app(run_ctx)
        if launch_output:
            artifacts.append(
                self._artifact_record(
                    run_ctx,
                    launch_output,
                    "target_launch_output",
                )
            )
        return TargetSnapshot(metadata=metadata, artifacts=artifacts)

    def finalize(self, run_ctx: RunContext) -> TargetSnapshot:
        if not run_ctx.device_serial:
            return TargetSnapshot(metadata={}, artifacts=[])
        artifacts: list[ArtifactRecord] = []
        stop_output = self._force_stop_app(run_ctx)
        if stop_output:
            artifacts.append(
                self._artifact_record(
                    run_ctx,
                    stop_output,
                    "target_stop_output",
                )
            )
        return TargetSnapshot(metadata={}, artifacts=artifacts)

    def _capture_package_info(self, run_ctx: RunContext) -> tuple[dict[str, Any], ArtifactRecord]:
        package_dump = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["dumpsys", "package", run_ctx.package_name],
        )
        path = run_ctx.run_dir / "artifacts/target/package_info.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(package_dump)
        version_name = self._extract_value(package_dump, r"versionName=(\S+)")
        version_code = self._extract_value(package_dump, r"versionCode=(\d+)")
        package_paths = self._read_package_paths(run_ctx)
        metadata = {
            "package_name": run_ctx.package_name,
            "version_name": version_name,
            "version_code": version_code,
            "apk_paths": package_paths,
            "package_info_artifact": str(path.relative_to(run_ctx.run_dir)),
        }
        artifact = self._artifact_record(run_ctx, path, "target_package_info")
        return metadata, artifact

    def _read_package_paths(self, run_ctx: RunContext) -> list[str]:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["pm", "path", run_ctx.package_name],
        )
        paths: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            paths.append(line.replace("package:", "", 1))
        return paths

    def _launch_app(self, run_ctx: RunContext) -> Path | None:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            [
                "monkey",
                "-p",
                run_ctx.package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
        )
        path = run_ctx.run_dir / "artifacts/target/launch_output.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output)
        return path

    def _force_stop_app(self, run_ctx: RunContext) -> Path | None:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["am", "force-stop", run_ctx.package_name],
        )
        path = run_ctx.run_dir / "artifacts/target/stop_output.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output)
        return path

    def _artifact_record(self, run_ctx: RunContext, path: Path, artifact_type: str) -> ArtifactRecord:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return ArtifactRecord(
            relative_path=str(path.relative_to(run_ctx.run_dir)),
            type=artifact_type,
            sha256=digest,
            size_bytes=path.stat().st_size,
            produced_by="target_manager",
        )

    def _extract_value(self, text: str, pattern: str) -> str | None:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
        return None


__all__ = ["TargetManager", "TargetSnapshot"]
