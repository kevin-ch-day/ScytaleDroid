"""Optional process-pool workers for static ``analyze_apk`` (persistence stays on the main thread)."""

from __future__ import annotations

import os
import pickle
import time
from collections.abc import Mapping
from pathlib import Path

from ..core.models import RunParameters


def effective_parallel_artifact_worker_count(
    *,
    resolved_worker_budget: int | None,
    artifact_count: int,
    hard_cap: int = 8,
) -> int:
    """Return max concurrent analyze workers for one package (1 = disable parallelism)."""

    raw = os.environ.get("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", "1").strip()
    try:
        want = int(raw)
    except ValueError:
        want = 1
    want = max(1, want)
    if isinstance(resolved_worker_budget, int) and resolved_worker_budget >= 1:
        want = min(want, resolved_worker_budget)
    return max(1, min(want, max(0, artifact_count), hard_cap))


def build_parallel_analyze_blob(
    artifact: object,
    params: RunParameters,
    base_dir: Path,
    *,
    extra_metadata: Mapping[str, object] | None,
) -> bytes:
    """Pickle job payload for :func:`parallel_static_analyze_worker`."""

    from .scan_report import build_analysis_config, build_scan_report_metadata_payload

    md = build_scan_report_metadata_payload(artifact, params, extra_metadata=extra_metadata)
    cfg = build_analysis_config(params)
    return pickle.dumps(
        {
            "path": str(Path(getattr(artifact, "path")).resolve()),
            "base_dir": str(Path(base_dir).resolve()),
            "metadata": dict(md),
            "config": cfg,
        },
        protocol=pickle.HIGHEST_PROTOCOL,
    )


def parallel_static_analyze_worker(blob: bytes) -> bytes:
    """Child entrypoint: run ``analyze_apk`` only; return pickled result dict."""

    from scytaledroid.StaticAnalysis.core.errors import StaticAnalysisError
    from scytaledroid.StaticAnalysis.core.pipeline import analyze_apk

    p = pickle.loads(blob)
    path = Path(p["path"])
    base_dir = Path(p["base_dir"])
    meta = dict(p["metadata"])
    cfg = p["config"]
    t0 = time.monotonic()
    try:
        report = analyze_apk(
            path,
            metadata=meta,
            storage_root=base_dir,
            config=cfg,
            stage_observer=None,
        )
    except StaticAnalysisError as exc:
        return pickle.dumps(
            {
                "ok": False,
                "error": str(exc),
                "analyze_wall_s": time.monotonic() - t0,
            },
            protocol=pickle.HIGHEST_PROTOCOL,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return pickle.dumps(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "analyze_wall_s": time.monotonic() - t0,
            },
            protocol=pickle.HIGHEST_PROTOCOL,
        )
    return pickle.dumps(
        {
            "ok": True,
            "report": report,
            "analyze_wall_s": time.monotonic() - t0,
        },
        protocol=pickle.HIGHEST_PROTOCOL,
    )


__all__ = [
    "build_parallel_analyze_blob",
    "effective_parallel_artifact_worker_count",
    "parallel_static_analyze_worker",
]
