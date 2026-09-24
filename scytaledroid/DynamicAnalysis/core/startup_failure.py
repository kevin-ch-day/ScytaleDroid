"""Fail-closed local provenance when dynamic initialization cannot finish."""

from __future__ import annotations

import os
import traceback
from datetime import UTC, datetime
from pathlib import Path

from ..utils.path_utils import artifact_relative_path
from .evidence_pack import EvidencePackWriter
from .manifest import ArtifactRecord, RunManifest
from .session import DynamicSessionConfig


def seal_startup_failure(
    config: DynamicSessionConfig,
    run_id: str,
    run_dir: Path,
    writer: EvidencePackWriter | None,
    error: Exception,
) -> tuple[RunManifest, Path, dict[str, object]]:
    """Preserve a failed local manifest if writable, without DB or device work.

    No installed-build completion identity is asserted: capture never began.
    If sealing fails, retain/mark the incomplete workspace for recovery discovery.
    """
    now = datetime.now(UTC).isoformat()
    detail = {
        "stage": "Evidence workspace initialization",
        "capture_started": False,
        "database_persisted": False,
        "database_attempted": False,
        "error": f"{type(error).__name__}: {error}",
        "diagnostic_evidence": "See application debug log; workspace unavailable",
        "recovery": "Failed; workspace unavailable",
    }
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id=run_id,
        created_at=now,
        ended_at=now,
        status="failed",
        batch_id=config.batch_id,
        target={"package_name": config.package_name, "static_run_id": config.static_run_id},
        dataset={
            "tier": config.tier,
            "countable": False,
            "valid_dataset_run": False,
            "invalid_reason_code": "STARTUP_ERROR",
        },
        qa={
            "startup_failure": {
                "stage": detail["stage"],
                "capture_started": False,
                "error_type": type(error).__name__,
            }
        },
        operator={
            "tier": config.tier,
            "run_profile": config.run_profile,
            "counts_toward_completion": False,
        },
        notes=[str(detail["error"])],
    )
    if writer is None:
        return manifest, run_dir, detail
    run_dir = writer.run_dir
    try:
        trace = writer.write_text("notes/startup_error.txt", traceback.format_exc())
        manifest.add_artifacts(
            [
                ArtifactRecord(
                    relative_path=artifact_relative_path(run_dir, trace),
                    type="startup_error",
                    produced_by="dynamic_orchestrator",
                    size_bytes=trace.stat().st_size,
                )
            ]
        )
        detail["diagnostic_evidence"] = "Preserved (startup_error.txt and application log)"
    except Exception:
        pass
    sealed = False
    try:
        manifest.finalize()
        writer.write_manifest(manifest)
        sealed = True
        detail["diagnostic_evidence"] = "Preserved (sealed FAILED manifest; application debug log)"
        detail["recovery"] = "Not required; failed startup sealed"
    except Exception:
        # A live CLI PID must not hide a failed-to-seal startup from recovery.
        try:
            writer.write_json(
                "notes/.scytaledroid_in_progress",
                {
                    "dynamic_run_id": run_id,
                    "host_pid": os.getpid(),
                    "started_at_utc": now,
                    "state": "startup_failed",
                },
            )
            detail["recovery"] = "Available for incomplete-pack review; sealing failed"
        except Exception:
            detail["recovery"] = "Failed; inspect application debug log and workspace"
    if sealed:
        try:
            marker = writer._output_path("notes/.scytaledroid_in_progress")
            marker.unlink(missing_ok=True)
        except Exception:
            pass
    return manifest, run_dir, detail
