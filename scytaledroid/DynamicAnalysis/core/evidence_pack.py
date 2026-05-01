"""Evidence pack helpers for dynamic analysis."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config

from .manifest import RunManifest, manifest_to_dict


class EvidencePackWriter:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.artifacts_dir = run_dir / "artifacts"
        self.analysis_dir = run_dir / "analysis"
        self.notes_dir = run_dir / "notes"

    def ensure_layout(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.notes_dir.mkdir(parents=True, exist_ok=True)

    def write_manifest(self, manifest: RunManifest, *, allow_overwrite: bool = False) -> Path:
        manifest_path = self.run_dir / "run_manifest.json"
        if manifest_path.exists() and not allow_overwrite:
            raise RuntimeError(f"Refusing to overwrite sealed manifest: {manifest_path}")
        if not manifest.sealed_at:
            # Sealing moment: the final manifest write.
            # Use the same UTC ISO format used elsewhere in manifests.
            from datetime import UTC, datetime

            manifest.sealed_at = datetime.now(UTC).isoformat()
        if not manifest.sealed_by:
            manifest.sealed_by = f"{app_config.APP_NAME} {app_config.APP_VERSION}"
        payload = manifest_to_dict(manifest)
        # Write atomically: temp + replace. Use a per-process temp name to avoid
        # rare collisions if a run directory is ever touched concurrently.
        temp_path = self.run_dir / f"run_manifest.json.tmp.{os.getpid()}"
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(manifest_path)
        return manifest_path

    def hash_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def write_text(self, relative_path: str, content: str) -> Path:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, relative_path: str, payload: dict[str, Any]) -> Path:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path


__all__ = ["EvidencePackWriter"]
