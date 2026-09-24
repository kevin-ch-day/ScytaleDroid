"""Evidence pack helpers for dynamic analysis."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_contained_path
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from .manifest import RunManifest, manifest_to_dict


class EvidencePackWriter:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir.resolve(strict=False)
        self.artifacts_dir = self.run_dir / "artifacts"
        self.analysis_dir = self.run_dir / "analysis"
        self.notes_dir = self.run_dir / "notes"

    def ensure_layout(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for directory in ("artifacts", "analysis", "notes"):
            self._output_path(directory).mkdir(parents=True, exist_ok=True)

    def write_manifest(self, manifest: RunManifest) -> Path:
        manifest_path = self.run_dir / "run_manifest.json"
        if manifest_path.exists():
            raise RuntimeError(f"Refusing to overwrite sealed manifest: {manifest_path}")
        if not manifest.sealed_at:
            # Sealing moment: the final manifest write.
            # Use the same UTC ISO format used elsewhere in manifests.
            from datetime import UTC, datetime

            manifest.sealed_at = datetime.now(UTC).isoformat()
        if not manifest.sealed_by:
            manifest.sealed_by = f"{app_config.APP_NAME} {app_config.APP_VERSION}"
        from .sealing_v2 import seal_inventory

        manifest.evidence_integrity = seal_inventory(self.run_dir, manifest)
        payload = manifest_to_dict(manifest)
        # Publish through a same-directory hard link. Unlike ``replace()``, the
        # link fails atomically if another writer seals this run after the
        # existence check above; an immutable manifest is never overwritten.
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=self.run_dir,
                prefix=".run_manifest.json.tmp.",
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp_path, manifest_path)
            except FileExistsError as exc:
                raise RuntimeError(
                    f"Refusing to overwrite sealed manifest: {manifest_path}"
                ) from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    # The immutable target, once linked, remains authoritative.
                    # A stale hidden temp file is cleanup debt, not a failed seal.
                    pass
        return manifest_path

    def is_v2_sealed(self) -> bool:
        path = self.run_dir / "run_manifest.json"
        if not path.exists():
            return False
        try:
            return (
                json.loads(path.read_text()).get("evidence_integrity", {}).get("contract")
                == "evidence_sealing_v2"
            )
        except (OSError, ValueError, AttributeError, TypeError):
            return True  # An unreadable existing manifest must not authorize writes.

    def derived_writer(self) -> EvidencePackWriter:
        """Preserve legacy locations; V2 operational derivatives live outside the seal."""
        if not self.is_v2_sealed():
            return self
        return EvidencePackWriter(self.run_dir.parent / (self.run_dir.name + ".postseal"))

    def hash_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _output_path(self, relative_path: str) -> Path:
        if relative_path != "notes/.scytaledroid_in_progress" and self.is_v2_sealed():
            raise RuntimeError("Sealed evidence pack; write a separate versioned sidecar")
        path = resolve_contained_path(self.run_dir, relative_path)
        if path is None or path == self.run_dir.resolve(strict=False):
            raise ValueError(
                f"Evidence artifact path must remain inside run directory: {relative_path!r}"
            )
        return path

    def write_text(self, relative_path: str, content: str) -> Path:
        path = self._output_path(relative_path)
        atomic_write_text(path, content)
        return path

    def write_json(self, relative_path: str, payload: dict[str, Any]) -> Path:
        path = self._output_path(relative_path)
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return path


__all__ = ["EvidencePackWriter"]
