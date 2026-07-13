"""Shared runtime-ML readiness and status helpers."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import (
    dataset_level_table_names,
    dataset_tables_dir,
    output_locked_runtime_bundle_artifacts_manifest_path,
    output_publication_qa_dir,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
    default_freeze_manifest_path,
    paper_artifacts_path,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import (
    get_sampling_duration_seconds,
    load_run_inputs,
)
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    active_dataset_freeze_path,
    active_dataset_plan_path,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    FreezeConfig,
    build_dataset_freeze_manifest,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root


def runtime_ml_status_snapshot() -> dict[str, object]:
    """Return the current locked-runtime-ML readiness snapshot."""

    freeze_path = display_freeze_anchor_path()
    artifacts_path = paper_artifacts_path(freeze_path)
    qa_path = output_publication_qa_dir() / "ml_audit_report_v1.json"
    bundle_manifest = output_locked_runtime_bundle_artifacts_manifest_path()
    evidence_root = dynamic_evidence_root()
    plan_path = active_dataset_plan_path()
    dataset_tables = dataset_tables_dir()
    required_tables = dataset_level_table_names()
    existing_tables, stale_tables = dataset_table_counts(
        dataset_tables=dataset_tables,
        required_tables=required_tables,
        anchor_path=freeze_path,
    )
    freeze_status = freeze_build_status(freeze_path=freeze_path, plan_path=plan_path, evidence_root=evidence_root)
    duration_status = duration_tier_status(freeze_path=freeze_path, evidence_root=evidence_root)
    return {
        "freeze_path": freeze_path,
        "artifacts_path": artifacts_path,
        "evidence_root": evidence_root,
        "plan_path": plan_path,
        "dataset_tables": dataset_tables,
        "required_tables": len(required_tables),
        "existing_tables": existing_tables,
        "stale_tables": stale_tables,
        "lockfile_state": current_file_state(artifacts_path, anchor_path=freeze_path),
        "qa_status": qa_status_label(qa_path, anchor_path=freeze_path),
        "bundle_status": bundle_status_label(bundle_manifest, anchor_path=freeze_path, artifacts_path=artifacts_path),
        "freeze_status": freeze_status,
        "duration_status": duration_status,
    }


def display_freeze_anchor_path() -> Path:
    """Return the active locked dataset anchor path shown to operators."""

    resolved = default_freeze_manifest_path()
    if resolved.exists():
        return resolved
    return active_dataset_freeze_path()


def current_file_state(path: Path, *, anchor_path: Path) -> str:
    """Classify a derived file relative to the current dataset anchor."""

    if not path.exists():
        return "missing"
    if not anchor_path.exists():
        return "ready"
    try:
        if path.stat().st_mtime + 0.001 < anchor_path.stat().st_mtime:
            return "stale"
    except OSError:
        return "unknown"
    return "ready"


def dataset_table_counts(
    *,
    dataset_tables: Path,
    required_tables: tuple[str, ...],
    anchor_path: Path,
) -> tuple[int, int]:
    """Return current and stale dataset-level ML table counts."""

    current = 0
    stale = 0
    for name in required_tables:
        state = current_file_state(dataset_tables / name, anchor_path=anchor_path)
        if state == "ready":
            current += 1
        elif state == "stale":
            stale += 1
    return current, stale


def table_state_label(existing_tables: int, required_tables: int, stale_tables: int) -> str:
    if stale_tables:
        return f"{existing_tables}/{required_tables} current · {stale_tables} stale"
    return f"{existing_tables}/{required_tables} ready"


def qa_status_label(path: Path, *, anchor_path: Path) -> str:
    """Return a compact QA status suitable for operator menus."""

    state = current_file_state(path, anchor_path=anchor_path)
    if state == "missing":
        return "missing"
    if state == "stale":
        return "stale - rerun QA audit"
    if state != "ready":
        return state
    payload = read_json(path) or {}
    readiness = payload.get("readiness") if isinstance(payload.get("readiness"), dict) else {}
    errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
    warnings = payload.get("warnings") if isinstance(payload.get("warnings"), list) else []
    status = str(readiness.get("status") or "").strip()
    if errors or status == "BLOCKED":
        return f"blocked - {len(errors)} error(s)"
    primary = str(readiness.get("primary_model_calibration") or "").strip()
    secondary = str(readiness.get("secondary_model_calibration") or "").strip()
    if status == "OK_WITH_SECONDARY_CAVEATS" or secondary == "WARN":
        return f"ready - primary OK · secondary caveats ({len(warnings)} warning(s))"
    if status == "OK" or primary == "OK":
        return "ready"
    return f"ready - {len(warnings)} warning(s)"


def bundle_status_label(path: Path, *, anchor_path: Path, artifacts_path: Path) -> str:
    """Return a compact locked bundle status suitable for operator menus."""

    if not path.exists():
        return "missing"
    for dependency in (anchor_path, artifacts_path):
        if dependency.exists():
            try:
                if path.stat().st_mtime + 0.001 < dependency.stat().st_mtime:
                    return "stale - regenerate locked dataset bundle"
            except OSError:
                return "unknown"
    payload = read_json(path) or {}
    files = payload.get("files") if isinstance(payload.get("files"), dict) else {}
    table_count = len([key for key in files if str(key).startswith("table_") and str(key).endswith("_csv")])
    figure_count = len([key for key in files if str(key).startswith("fig_") and str(key).endswith("_png")])
    return f"ready - {table_count} table CSV(s) · {figure_count} figure PNG(s)"


def freeze_status_summary(status: str) -> str:
    """Shorten detailed freeze-builder status for menus."""

    raw = str(status or "").strip()
    if not raw:
        return "unknown"
    lower = raw.lower()
    if lower.startswith("ready"):
        return raw
    if "freeze_insufficient_eligible_runs" in lower:
        count = extract_app_count(raw)
        suffix = f" for {count} app(s)" if count is not None else ""
        return f"blocked - insufficient eligible runs{suffix}"
    if "dataset plan missing" in lower:
        return "blocked - dataset plan missing"
    if "evidence root missing" in lower:
        return "blocked - evidence root missing"
    if "extra=" in lower or "missing=" in lower:
        return raw
    if lower.startswith("blocked -"):
        first = raw.split(";", 1)[0]
        first = first.split(":", 1)[0] if len(first) > 96 else first
        return first
    return raw


def freeze_status_details(status: str) -> list[str]:
    """Return detailed operator lines for a blocked locked dataset."""

    raw = str(status or "").strip()
    if not raw:
        return []
    lower = raw.lower()
    if not lower.startswith("blocked"):
        return []
    if "freeze_insufficient_eligible_runs" not in lower:
        return [raw]
    detail = raw.split(":", 2)
    if len(detail) < 3:
        return [raw]
    app_chunks = [chunk.strip() for chunk in detail[2].split(";") if chunk.strip()]
    cfg = ml_freeze_config()
    lines = [
        freeze_status_summary(raw),
        (
            "Locked ML dataset requires "
            f"{int(cfg.baseline_required)} baseline + {int(cfg.interactive_required)} interactive "
            "eligible run(s) per app in data/evidence/dynamic; extra eligible runs in the selected 14-day build group are included."
        ),
    ]
    for chunk in app_chunks:
        app, _, counts = chunk.partition(":")
        if not app:
            continue
        lines.append(f"- {app}: {counts}" if counts else f"- {app}")
    return lines


def duration_tier_status(*, freeze_path: Path, evidence_root: Path) -> str:
    """Summarize run duration tiers for the locked dataset."""

    payload = read_json(freeze_path)
    if not isinstance(payload, dict):
        return "not available"
    run_ids = payload.get("included_run_ids")
    if not isinstance(run_ids, list) or not run_ids:
        return "not available"
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for raw_run_id in run_ids:
        run_id = str(raw_run_id or "").strip()
        if not run_id:
            continue
        inputs = load_run_inputs(evidence_root / run_id)
        duration = get_sampling_duration_seconds(inputs) if inputs else None
        tier = classify_duration_tier(duration)
        counts[tier.key] = int(counts.get(tier.key, 0)) + 1
        labels[tier.key] = tier.label
    if not counts:
        return "not available"
    order = ["short", "minimum", "standard", "extended", "long_observation", "soak", "unknown"]
    return " · ".join(f"{labels.get(key, key)} {counts[key]}" for key in order if key in counts)


def operational_snapshot_status(*, compact: bool = False) -> str:
    """Return current operational ML snapshot status."""

    root = Path(app_config.OUTPUT_DIR) / "operational"
    if not root.exists():
        return "none" if compact else f"none - {relative_path(root)}"
    snapshots = [p for p in root.iterdir() if p.is_dir()]
    if not snapshots:
        return "none" if compact else f"none - {relative_path(root)}"
    latest = max(snapshots, key=lambda p: p.stat().st_mtime)
    if compact:
        return f"{len(snapshots)} snapshot(s) · latest {latest.name}"
    return f"{len(snapshots)} snapshot(s), latest {relative_path(latest)}"


def plan_packages(path: Path) -> set[str] | None:
    payload = read_json(path)
    apps = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, dict):
        return None
    return {str(pkg).strip().lower() for pkg in apps if str(pkg).strip()}


def plan_cohort_alignment(plan_path: Path) -> tuple[bool, str]:
    plan_packages_set = plan_packages(plan_path)
    if plan_packages_set is None:
        return False, f"invalid dataset plan: {relative_path(plan_path)}"
    expected = {str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()}
    if not expected:
        return True, "unknown - active cohort packages unavailable"
    extra = sorted(plan_packages_set - expected)
    missing = sorted(expected - plan_packages_set)
    if not extra and not missing:
        return True, f"ok - {len(plan_packages_set)} app(s)"
    parts: list[str] = []
    if extra:
        suffix = "..." if len(extra) > 3 else ""
        parts.append(f"extra={len(extra)} ({', '.join(extra[:3])}{suffix})")
    if missing:
        suffix = "..." if len(missing) > 3 else ""
        parts.append(f"missing={len(missing)} ({', '.join(missing[:3])}{suffix})")
    return False, "blocked - " + "; ".join(parts)


def freeze_build_status(*, freeze_path: Path, plan_path: Path, evidence_root: Path) -> str:
    """Return locked dataset build status without mutating files."""

    if freeze_path.exists():
        payload = read_json(freeze_path) or {}
        run_count = len(payload.get("included_run_ids") or []) if isinstance(payload.get("included_run_ids"), list) else 0
        app_count = len(payload.get("apps") or {}) if isinstance(payload.get("apps"), dict) else 0
        max_age_days = None
        quota = payload.get("quota_policy") if isinstance(payload.get("quota_policy"), dict) else {}
        if isinstance(quota, dict):
            max_age_days = quota.get("max_age_days")
        if app_count and run_count:
            suffix = f" · {max_age_days}-day window" if max_age_days else ""
            return f"ready - {app_count} apps · {run_count} runs{suffix} · selected build groups"
        return "ready - anchor exists"
    if not plan_path.exists():
        return "blocked - dataset plan missing"
    if not evidence_root.exists():
        return "blocked - evidence root missing"
    alignment_ok, alignment_message = plan_cohort_alignment(plan_path)
    if not alignment_ok:
        return alignment_message
    try:
        payload = build_dataset_freeze_manifest(
            dataset_plan_path=plan_path,
            evidence_root=evidence_root,
            cfg=ml_freeze_config(),
        )
    except Exception as exc:
        return f"blocked - {exc}"
    run_count = len(payload.get("included_run_ids") or [])
    app_count = len(payload.get("apps") or {})
    return f"ready - {app_count} apps · {run_count} runs · selected build groups"


def extract_app_count(status: str) -> int | None:
    marker = "FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:"
    if marker not in status:
        marker = "freeze_insufficient_eligible_runs:"
    lower = status.lower()
    idx = lower.find(marker.lower())
    if idx < 0:
        return None
    rest = status[idx + len(marker) :]
    token = rest.split(None, 1)[0].split(":", 1)[0]
    try:
        return int(token)
    except Exception:
        return None


def ml_freeze_config() -> FreezeConfig:
    return FreezeConfig(baseline_required=1, interactive_required=2, max_age_days=14)


def read_json(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


__all__ = [
    "bundle_status_label",
    "current_file_state",
    "dataset_table_counts",
    "display_freeze_anchor_path",
    "duration_tier_status",
    "extract_app_count",
    "freeze_build_status",
    "freeze_status_details",
    "freeze_status_summary",
    "ml_freeze_config",
    "operational_snapshot_status",
    "plan_cohort_alignment",
    "plan_packages",
    "qa_status_label",
    "read_json",
    "relative_path",
    "runtime_ml_status_snapshot",
    "table_state_label",
]
