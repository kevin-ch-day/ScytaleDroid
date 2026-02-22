"""Target management helpers for dynamic analysis runs.

Hash posture: per-artifact sha256 values are best-effort audit aids. Most target/env
artifacts are not treated as immutable inputs to Phase E; freeze checksums are the
immutability anchor.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
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
        metadata: dict[str, Any] = {}
        package_info, package_artifact = self._capture_package_info(run_ctx)
        metadata.update(
            {
                "package_name_end": package_info.get("package_name"),
                "version_name_end": package_info.get("version_name"),
                "version_code_end": package_info.get("version_code"),
                "user_id_end": package_info.get("user_id"),
                "first_install_time_end": package_info.get("first_install_time"),
                "last_update_time_end": package_info.get("last_update_time"),
                "installer_package_name_end": package_info.get("installer_package_name"),
                "signer_primary_digest_end": package_info.get("signer_primary_digest"),
                "signer_set_hash_end": package_info.get("signer_set_hash"),
                "apk_paths_end": package_info.get("apk_paths"),
                "package_info_end_artifact": package_info.get("package_info_artifact"),
            }
        )
        artifacts.append(
            ArtifactRecord(
                relative_path=package_artifact.relative_path,
                type="target_package_info_end",
                sha256=package_artifact.sha256,
                size_bytes=package_artifact.size_bytes,
                produced_by=package_artifact.produced_by,
                origin=package_artifact.origin,
                device_path=package_artifact.device_path,
                pull_status=package_artifact.pull_status,
            )
        )
        stop_output = self._force_stop_app(run_ctx)
        if stop_output:
            artifacts.append(
                self._artifact_record(
                    run_ctx,
                    stop_output,
                    "target_stop_output",
                )
            )
        return TargetSnapshot(metadata=metadata, artifacts=artifacts)

    def _capture_package_info(self, run_ctx: RunContext) -> tuple[dict[str, Any], ArtifactRecord]:
        package_dump = self._read_package_dump(run_ctx)
        path = run_ctx.run_dir / "artifacts/target/package_info.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(package_dump, encoding="utf-8")
        version_name = self._extract_value(package_dump, r"versionName=(\S+)")
        version_code = self._extract_value(package_dump, r"versionCode=(\d+)")
        user_id = self._extract_value(package_dump, r"userId=(\d+)")
        first_install_time = self._extract_value(package_dump, r"firstInstallTime=(.+)")
        last_update_time = self._extract_value(package_dump, r"lastUpdateTime=(.+)")
        installer_package_name = self._extract_value(package_dump, r"installerPackageName=(\S+)")
        signer_digests = self._extract_signer_digests(package_dump)
        package_paths = self._read_package_paths(run_ctx)
        metadata = {
            "package_name": run_ctx.package_name,
            "version_name": version_name,
            "version_code": version_code,
            "user_id": user_id or "0",
            "first_install_time": first_install_time,
            "last_update_time": last_update_time,
            "installer_package_name": installer_package_name,
            "apk_paths": package_paths,
            "signer_primary_digest": signer_digests[0] if signer_digests else None,
            "signer_set_hash": self._compute_signer_set_hash(signer_digests),
            "package_info_artifact": str(path.relative_to(run_ctx.run_dir)),
        }
        artifact = self._artifact_record(run_ctx, path, "target_package_info")
        return metadata, artifact

    def _read_package_dump(self, run_ctx: RunContext) -> str:
        serial = run_ctx.device_serial or ""
        package = run_ctx.package_name
        # Paper contract: identity checks are pinned to user 0.
        output = adb_shell.run_shell(serial, ["dumpsys", "package", "--user", "0", package])
        if output and "Unknown option" not in output and "Bad argument" not in output:
            return output
        return adb_shell.run_shell(serial, ["dumpsys", "package", package])

    def _read_package_paths(self, run_ctx: RunContext) -> list[str]:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["pm", "path", "--user", "0", run_ctx.package_name],
        )
        if output and ("Error:" in output or "Unknown option" in output):
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
        path.write_text(output, encoding="utf-8")
        return path

    def _force_stop_app(self, run_ctx: RunContext) -> Path | None:
        output = adb_shell.run_shell(
            run_ctx.device_serial or "",
            ["am", "force-stop", run_ctx.package_name],
        )
        path = run_ctx.run_dir / "artifacts/target/stop_output.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        return path

    def _artifact_record(self, run_ctx: RunContext, path: Path, artifact_type: str) -> ArtifactRecord:
        return ArtifactRecord(
            relative_path=str(path.relative_to(run_ctx.run_dir)),
            type=artifact_type,
            sha256=None,
            size_bytes=path.stat().st_size,
            produced_by="target_manager",
            origin="host",
            pull_status="n/a",
        )

    def _extract_value(self, text: str, pattern: str) -> str | None:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
        return None

    def _extract_signer_digests(self, package_dump: str) -> list[str]:
        digests: list[str] = []
        for line in package_dump.splitlines():
            low = line.lower()
            if ("sha-256" not in low) and ("sha256" not in low) and ("sign" not in low):
                continue
            for match in re.finditer(r"([0-9A-Fa-f:]{64,95})", line):
                raw = match.group(1).replace(":", "").strip().lower()
                if len(raw) == 64 and all(ch in "0123456789abcdef" for ch in raw):
                    digests.append(raw)
        return sorted(set(digests))

    def _compute_signer_set_hash(self, digests: list[str]) -> str | None:
        if not digests:
            return None
        payload = "|".join(sorted(digests)).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


__all__ = ["TargetManager", "TargetSnapshot"]
