"""Dataset run tracker for dynamic collection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_plan_read_path,
    write_dataset_plan_payload,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
    active_research_cohort_key,
    active_research_cohort_packages,
)
from scytaledroid.DynamicAnalysis.tracker_scope import (
    default_resolve_tracker_run_identity,
    scope_tracker_runs_to_active_identity,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    iter_dynamic_run_dirs,
    resolve_dynamic_run_dir,
)
from scytaledroid.DynamicAnalysis.utils.pcap_minima import (
    effective_min_pcap_bytes_for_run_profile,
)

MIN_PCAP_BYTES = int(getattr(profile_config, "MIN_PCAP_BYTES", 50000))
MIN_WINDOWS_PER_RUN = 20
SHORT_RUN_TOLERANCE_SECONDS = 2.0
BASELINE_REQUIRED = 3
INTERACTION_REQUIRED = 4
TOTAL_REQUIRED_PER_APP = BASELINE_REQUIRED + INTERACTION_REQUIRED


def _effective_min_sampling_seconds() -> float:
    configured = float(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120))
    profile_floor = float(getattr(profile_config, "MIN_SAMPLING_SECONDS", 180.0))
    return max(configured, profile_floor)


def _effective_target_sampling_seconds() -> float:
    configured = float(getattr(app_config, "DYNAMIC_TARGET_DURATION_S", 180))
    profile_target = float(getattr(profile_config, "RECOMMENDED_SAMPLING_SECONDS", 240.0))
    return max(configured, profile_target)


@dataclass(frozen=True)
class DatasetTrackerConfig:
    baseline_required: int = field(
        default_factory=lambda: int(getattr(app_config, "DYNAMIC_DATASET_BASELINE_RUNS", BASELINE_REQUIRED))
    )
    interactive_required: int = field(
        default_factory=lambda: int(getattr(app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", INTERACTION_REQUIRED))
    )
    baseline_profile: str = "baseline_idle"
    interactive_profile: str = "interaction_manual"


def _is_baseline_profile(profile: object, cfg: DatasetTrackerConfig) -> bool:
    p = str(profile or "")
    return p.startswith(cfg.baseline_profile) or "baseline" in p or "idle" in p


def _is_interactive_profile(profile: object, cfg: DatasetTrackerConfig) -> bool:
    p = str(profile or "")
    return p.startswith(cfg.interactive_profile) or p.startswith("interaction_") or "interactive" in p


def _known_identity_value(*values: object) -> object | None:
    for value in values:
        text = str(value or "").strip()
        if text and text.lower() not in {"unknown", "none", "null"}:
            return value
    return None


_VALIDITY_ENUM = {
    "INSUFFICIENT_DURATION",
    "PCAP_MISSING",
    "PCAP_TOO_SMALL",
    "PCAP_REPORT_MISSING",
    "PCAP_REPORT_SKIP",
    "MISSING_TOOLS_TSHARK",
    "MISSING_TOOLS_CAPINFOS",
    "PCAP_REPORT_EMPTY_NO_REASON",
    "PCAP_PARSE_ERROR",
    "CAPTURE_INTERRUPTED",
}

_PCAP_FAILURE_DETAILS = {
    "PCAP_DEVICE_FILE_MISSING",
    "PCAP_DEVICE_FILE_EMPTY",
    "PCAP_PULL_FAILED",
    "PCAP_LOCAL_FILE_MISSING",
    "PCAP_LOCAL_FILE_EMPTY",
    "PCAP_PARSE_FAILED",
}


def update_dataset_tracker(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: DatasetTrackerConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> Path | None:
    cfg = config or DatasetTrackerConfig()
    tier = None
    if isinstance(manifest.operator, dict):
        tier = manifest.operator.get("tier")
    if tier and str(tier).lower() != "dataset":
        _log(event_logger, "dataset_tracker_skip", {"tier": tier})
        return None
    package = (manifest.target.get("package_name") or "_unknown").strip()
    if not package:
        package = "_unknown"
    active_packages = _active_dataset_package_set()
    if active_packages and package.lower() not in active_packages:
        _log(
            event_logger,
            "dataset_tracker_skip",
            {
                "package_name": package,
                "reason": "not_in_active_research_cohort",
            },
        )
        return None
    tracker_path = resolve_dataset_plan_read_path()
    tracker_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _load_tracker_payload(tracker_path)
    apps = payload.setdefault("apps", {})
    app_entry = apps.setdefault(package, {"runs": []})
    operator = manifest.operator if isinstance(manifest.operator, dict) else {}
    target = manifest.target if isinstance(manifest.target, dict) else {}
    dataset = manifest.dataset if isinstance(manifest.dataset, dict) else {}
    target_identity = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}
    interaction_level = operator.get("interaction_level")
    if interaction_level == "idle":
        interaction_level = "minimal"
    run_entry = {
        "run_id": manifest.dynamic_run_id,
        "scenario": manifest.scenario.get("id"),
        "started_at": manifest.scenario.get("started_at") or manifest.started_at,
        "ended_at": manifest.scenario.get("ended_at") or manifest.ended_at,
        "static_run_id": target.get("static_run_id"),
        "pcap_size_bytes": _pcap_size(manifest),
        "report_status": _pcap_report_status(run_dir),
        "run_profile": operator.get("run_profile"),
        "run_sequence": operator.get("run_sequence"),
        "interaction_level": interaction_level,
        "messaging_activity": operator.get("messaging_activity"),
        "version_name": target_identity.get("version_name"),
        "version_code": (
            target_identity.get("version_code")
            or target.get("version_code")
        ),
        "observed_version_code": (
            target_identity.get("observed_version_code")
            or target.get("observed_version_code")
        ),
        "base_apk_sha256": target_identity.get("base_apk_sha256"),
        "artifact_set_hash": target_identity.get("artifact_set_hash"),
        "signer_set_hash": _known_identity_value(
            target_identity.get("signer_set_hash"),
            target_identity.get("signer_digest"),
            target.get("signer_set_hash"),
            target.get("observed_signer_set_hash"),
        ),
        "low_signal": (
            True
            if dataset.get("low_signal") is True
            else (False if dataset.get("low_signal") is False else None)
        ),
        "low_signal_reasons": (
            list(dataset.get("low_signal_reasons"))
            if isinstance(dataset.get("low_signal_reasons"), list)
            else []
        ),
    }
    run_entry.update(_netstats_summary(run_dir))
    run_entry.update(_pcap_capture_stats(run_dir))
    run_entry.update(_timeline_status(run_dir))
    # Recompute low-signal from evidence for tracker derivation so reindex picks
    # up policy improvements without mutating evidence manifests.
    ls = compute_low_signal_for_run(
        run_dir,
        package_name=str(package),
        run_profile=str(operator.get("run_profile") or ""),
    )
    if isinstance(ls, dict):
        run_entry["low_signal"] = (
            True
            if ls.get("low_signal") is True
            else (False if ls.get("low_signal") is False else None)
        )
        run_entry["low_signal_reasons"] = (
            list(ls.get("low_signal_reasons"))
            if isinstance(ls.get("low_signal_reasons"), list)
            else []
        )
    else:
        run_entry["low_signal"] = (
            True
            if dataset.get("low_signal") is True
            else (False if dataset.get("low_signal") is False else None)
        )
        run_entry["low_signal_reasons"] = (
            list(dataset.get("low_signal_reasons"))
            if isinstance(dataset.get("low_signal_reasons"), list)
            else []
        )
    try:
        from scytaledroid.DynamicAnalysis.pcap.baseline_activity import (
            compute_baseline_activity_for_run,
        )

        activity = compute_baseline_activity_for_run(
            run_dir,
            package_name=str(package),
            run_profile=str(operator.get("run_profile") or ""),
        )
        if isinstance(activity, dict):
            run_entry["baseline_not_idle"] = (
                True
                if activity.get("baseline_not_idle") is True
                else (False if activity.get("baseline_not_idle") is False else None)
            )
            run_entry["baseline_not_idle_reasons"] = (
                list(activity.get("baseline_not_idle_reasons"))
                if isinstance(activity.get("baseline_not_idle_reasons"), list)
                else []
            )
            if activity.get("exploratory_class"):
                run_entry["exploratory_class"] = activity.get("exploratory_class")
    except Exception:
        if dataset.get("baseline_not_idle") is not None:
            run_entry["baseline_not_idle"] = (
                True
                if dataset.get("baseline_not_idle") is True
                else (False if dataset.get("baseline_not_idle") is False else None)
            )
    validity = evaluate_dataset_validity(run_dir, manifest, run_entry, cfg)
    run_entry.update(validity)
    explicit_countable = dataset.get("countable")
    if explicit_countable is True or explicit_countable is False:
        if not (
            explicit_countable is False
            and _should_ignore_stale_explicit_noncountable(dataset, operator, validity, run_entry)
        ):
            run_entry["countable"] = explicit_countable
        else:
            run_entry["countable"] = None
    explicit_cohort_eligibility = dataset.get("cohort_eligibility")
    if isinstance(explicit_cohort_eligibility, str) and explicit_cohort_eligibility.strip():
        run_entry["cohort_eligibility"] = explicit_cohort_eligibility.strip()
    run_entry.update(
        _derive_paper_eligibility_fields(
            run_dir,
            manifest_payload={
                "dataset": dict(run_entry),
                "operator": dict(operator) if isinstance(operator, dict) else {},
                "target": dict(target) if isinstance(target, dict) else {},
            },
        )
    )

    # Idempotent: update existing entries so older runs can be re-evaluated when
    # QA rules evolve (e.g., PCAP span vs netstats guardrail).
    existing = next((r for r in app_entry["runs"] if r.get("run_id") == manifest.dynamic_run_id), None)
    if existing is None:
        app_entry["runs"].append(run_entry)
    else:
        existing.update(run_entry)
    runs_list = app_entry.get("runs") if isinstance(app_entry, dict) else []
    if not isinstance(runs_list, list):
        runs_list = []
        app_entry["runs"] = runs_list

    app_entry["run_count"] = len([r for r in runs_list if isinstance(r, dict)])
    app_entry["target_runs"] = int(cfg.baseline_required) + int(cfg.interactive_required)

    # Deterministically mark quota-counted runs vs extras.
    _apply_quota_marking(app_entry, cfg, package_name=package)

    def _counted(r: dict[str, Any]) -> bool:
        return r.get("valid_dataset_run") is True and bool(r.get("counts_toward_quota"))

    # Headline counts reflect quota-counted valid runs only (extras are allowed
    # but must not distort completion progress).
    app_entry["valid_runs"] = sum(1 for r in runs_list if isinstance(r, dict) and _counted(r))
    app_entry["baseline_valid_runs"] = sum(
        1
        for r in runs_list
        if isinstance(r, dict)
        and _counted(r)
        and _is_baseline_profile(r.get("run_profile"), cfg)
    )
    app_entry["interactive_valid_runs"] = sum(
        1
        for r in runs_list
        if isinstance(r, dict)
        and _counted(r)
        and _is_interactive_profile(r.get("run_profile"), cfg)
    )
    app_entry["app_complete"] = (
        int(app_entry["baseline_valid_runs"]) >= int(cfg.baseline_required)
        and int(app_entry["interactive_valid_runs"]) >= int(cfg.interactive_required)
    )
    app_entry["overlap_stats"] = _compute_overlap_stats(runs_list)
    payload["updated_at"] = datetime.now(UTC).isoformat()
    tracker_path = write_dataset_plan_payload(payload)
    _log(
        event_logger,
        "dataset_tracker_update",
        {
            "package_name": package,
            "run_count": app_entry["run_count"],
            "valid_runs": app_entry["valid_runs"],
            "run_profile": operator.get("run_profile"),
            "run_sequence": operator.get("run_sequence"),
        },
    )
    return tracker_path


def _should_ignore_stale_explicit_noncountable(
    dataset: dict[str, Any],
    operator: dict[str, Any],
    validity: dict[str, Any],
    run_entry: dict[str, Any] | None = None,
) -> bool:
    """Allow repaired quota-intended runs to re-enter normal quota marking.

    Older manifests can permanently cache ``countable=false`` when a run originally
    finalized invalid and is later repaired by regenerating derived PCAP artifacts.
    If the run was quota-intended at capture time and now recomputes as valid, treat
    the stale explicit false as repairable cache state rather than a lasting policy
    override.
    """
    if dataset.get("countable") is not False:
        return False
    if validity.get("valid_dataset_run") is not True:
        return False
    if operator.get("counts_toward_completion") is not True:
        return False
    if dataset.get("valid_dataset_run") is False:
        return True
    profile_lc = str(operator.get("run_profile") or "").strip().lower()
    stale_low_signal_false = (
        profile_lc == "baseline_idle"
        and dataset.get("valid_dataset_run") is True
        and dataset.get("low_signal") is True
        and isinstance(run_entry, dict)
        and run_entry.get("low_signal") is False
    )
    if stale_low_signal_false:
        return True
    if isinstance(run_entry, dict) and _explicit_noncountable_is_policy_override(run_entry, profile_lc):
        return False
    return True


def _explicit_noncountable_is_policy_override(row: dict[str, Any], profile_lc: str | None = None) -> bool:
    """Return whether explicit ``countable=false`` is a real nonquota policy state."""
    prof_lc = str(profile_lc if profile_lc is not None else row.get("run_profile") or "").strip().lower()
    if not _is_baseline_profile(prof_lc, DatasetTrackerConfig()):
        return True
    if row.get("valid_dataset_run") is False or row.get("paper_eligible") is False:
        return True
    if bool(row.get("extra_run")):
        return True
    if prof_lc == "baseline_idle" and bool(row.get("low_signal")):
        return True
    return False


def load_dataset_tracker() -> dict[str, Any]:
    tracker_path = resolve_dataset_plan_read_path()
    payload = _load_tracker_payload(tracker_path)
    active_key = str(active_research_cohort_key() or "").strip().lower()
    stored_key = str(payload.get("cohort_key") or "").strip().lower() if isinstance(payload, dict) else ""
    if active_key and stored_key and stored_key != active_key:
        raise RuntimeError(
            f"DATASET_PLAN_COHORT_MISMATCH: payload={stored_key} active={active_key}"
        )
    dirty: list[bool] = [False]
    normalized = _normalize_tracker_payload(payload, DatasetTrackerConfig(), dirty=dirty)
    # `load_*` is a pure read path: callers may normalize in memory, but no
    # tracker, mirror, mtime, or directory entry may be changed here.
    return normalized


def _refresh_paper_eligibility_in_place(r: dict[str, Any]) -> bool:
    """Best-effort refresh of paper eligibility fields for a tracker row.

    The tracker is a derived index; eligibility logic can change over time. We
    refresh a small set of known-stale states opportunistically so operators do
    not need to manually reindex after policy shifts.

    Returns True if any field was updated.
    """
    if not isinstance(r, dict):
        return False
    run_id = str(r.get("run_id") or "").strip()
    if not run_id:
        return False
    run_dir = resolve_dynamic_run_dir(run_id)
    if run_dir is None:
        return False
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists():
        return False
    # Note: plan may be missing in incomplete packs; in that case eligibility
    # remains excluded by identity rules.
    manifest = _load(manifest_path)
    plan = _load(run_dir / "inputs" / "static_dynamic_plan.json")
    eligibility = derive_freeze_eligibility(
        manifest=manifest if isinstance(manifest, dict) else {},
        plan=plan if isinstance(plan, dict) else {},
        min_windows=int(MIN_WINDOWS_PER_RUN),
        required_capture_policy_version=int(getattr(profile_config, "PAPER_CONTRACT_VERSION", 1)),
    )
    before = (
        r.get("paper_eligible"),
        r.get("paper_exclusion_primary_reason_code"),
        tuple(r.get("paper_exclusion_all_reason_codes") or []),
    )
    r["paper_eligible"] = bool(eligibility.paper_eligible)
    r["paper_exclusion_primary_reason_code"] = eligibility.reason_code
    r["paper_exclusion_all_reason_codes"] = list(eligibility.all_reason_codes)
    after = (
        r.get("paper_eligible"),
        r.get("paper_exclusion_primary_reason_code"),
        tuple(r.get("paper_exclusion_all_reason_codes") or []),
    )
    return before != after


def _normalize_tracker_payload(
    payload: dict[str, Any],
    cfg: DatasetTrackerConfig,
    *,
    dirty: list[bool] | None = None,
) -> dict[str, Any]:
    """Normalize/repair derived tracker fields in-memory.

    The tracker JSON is a derived index. As the schema evolves, older files may
    be missing computed keys like baseline_valid_runs. Normalization keeps the UI
    and status logic stable without requiring an explicit recompute step.
    """
    if not isinstance(payload, dict):
        return {"apps": {}}
    apps = payload.get("apps")
    if not isinstance(apps, dict):
        payload["apps"] = {}
        return payload

    for _pkg, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            runs = []
            entry["runs"] = runs

        # Opportunistic repair: older trackers may have runs marked paper-excluded
        # under now-retired policy. Refresh eligibility in-memory so quota/progress
        # displays reflect current rules even if the operator hasn't reindexed yet.
        for r in runs:
            if not isinstance(r, dict):
                continue
            primary = str(r.get("paper_exclusion_primary_reason_code") or "").strip()
            prof = str(r.get("run_profile") or "").strip().lower()
            valid_dataset_run = r.get("valid_dataset_run")
            # Opportunistic repairs for known policy shifts where the tracker can
            # hold stale cached eligibility state.
            #
            # - Manual runs may become cohort-eligible.
            # - Protocol fit feedback is informational (not an exclusion).
            # - Superseded scripted templates may remain compatible with their
            #   current successor templates.
            # - A technically invalid run must not remain cached as eligible.
            if (
                (primary == "EXCLUDED_MANUAL_NON_COHORT" and "manual" in prof)
                or (primary == "EXCLUDED_PROTOCOL_FIT_POOR")
                or (primary == "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH")
                or (r.get("paper_eligible") is True and valid_dataset_run is False)
            ):
                if _refresh_paper_eligibility_in_place(r):
                    if isinstance(dirty, list) and dirty:
                        dirty[0] = True

        entry["run_count"] = len([r for r in runs if isinstance(r, dict)])
        entry["target_runs"] = int(cfg.baseline_required) + int(cfg.interactive_required)

        # Ensure quota markings are present for UI labels (extra_run, counts_toward_quota),
        # and then compute counts from those deterministic markings.
        before_run_markers = [
            (
                bool(r.get("counts_toward_quota")),
                int(r.get("extra_run") or 0),
                bool(r.get("countable")),
            )
            for r in runs
            if isinstance(r, dict)
        ]
        before_entry_fields = (
            bool(entry.get("quota_met")),
            entry.get("quota_met_at"),
            entry.get("quota_met_run_id"),
            int(entry.get("extra_valid_runs") or 0),
            int(entry.get("baseline_valid_runs") or 0),
            int(entry.get("interactive_valid_runs") or 0),
            int(entry.get("valid_runs") or 0),
        )

        _apply_quota_marking(entry, cfg, package_name=str(_pkg or ""))

        after_run_markers = [
            (
                bool(r.get("counts_toward_quota")),
                int(r.get("extra_run") or 0),
                bool(r.get("countable")),
            )
            for r in runs
            if isinstance(r, dict)
        ]
        after_entry_fields = (
            bool(entry.get("quota_met")),
            entry.get("quota_met_at"),
            entry.get("quota_met_run_id"),
            int(entry.get("extra_valid_runs") or 0),
            int(entry.get("baseline_valid_runs") or 0),
            int(entry.get("interactive_valid_runs") or 0),
            int(entry.get("valid_runs") or 0),
        )
        if (before_run_markers != after_run_markers or before_entry_fields != after_entry_fields) and isinstance(dirty, list) and dirty:
            dirty[0] = True

        def _counted(r: dict[str, Any]) -> bool:
            return r.get("valid_dataset_run") is True and bool(r.get("counts_toward_quota"))

        entry["valid_runs"] = sum(1 for r in runs if isinstance(r, dict) and _counted(r))
        entry["baseline_valid_runs"] = sum(
            1
            for r in runs
            if isinstance(r, dict)
            and _counted(r)
            and _is_baseline_profile(r.get("run_profile"), cfg)
        )
        entry["interactive_valid_runs"] = sum(
            1
            for r in runs
            if isinstance(r, dict)
            and _counted(r)
            and _is_interactive_profile(r.get("run_profile"), cfg)
        )
        entry["app_complete"] = (
            int(entry["baseline_valid_runs"]) >= int(cfg.baseline_required)
            and int(entry["interactive_valid_runs"]) >= int(cfg.interactive_required)
        )
        entry["quota_met"] = bool(entry.get("quota_met") or entry.get("app_complete"))
        entry["extra_valid_runs"] = int(entry.get("extra_valid_runs") or 0)

    return payload


def peek_next_run_protocol(
    package_name: str,
    *,
    tier: str | None,
    config: DatasetTrackerConfig | None = None,
) -> dict[str, Any] | None:
    """Determine the next dataset run protocol for a package.

    This is operator protocol metadata (baseline vs interactive), not a behavioral
    feature. The intent is to keep Run #1 per app as a low-interaction baseline,
    and to make that intent explicit in run artifacts for later ML analysis.
    """
    if not tier or str(tier).lower() != "dataset":
        return None
    cfg = config or DatasetTrackerConfig()
    package = (package_name or "_unknown").strip() or "_unknown"
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    entry = apps.get(package) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) else []

    baseline_valid = 0
    interactive_valid = 0
    total_valid = 0
    if isinstance(runs, list):
        for r in runs:
            if not isinstance(r, dict) or r.get("valid_dataset_run") is not True:
                continue
            # Only quota-counted runs satisfy the Paper #2 quota and increment
            # the protocol sequence. Extras are allowed but must not influence
            # operator guidance.
            if not bool(r.get("counts_toward_quota", True)):
                continue
            total_valid += 1
            prof = str(r.get("run_profile") or "")
            if _is_baseline_profile(prof, cfg):
                baseline_valid += 1
            elif _is_interactive_profile(prof, cfg):
                interactive_valid += 1

    # Dataset protocol numbering is by quota slot, not attempt count.
    #
    # If Run #1 fails QA, the next retry should still be "Run #1" until a valid run
    # is recorded. This avoids confusing operators ("baseline Run #2") and matches
    # the dataset contract: each app needs baseline + interaction VALID runs; retries
    # fill the same slot.
    needed = int(cfg.baseline_required) + int(cfg.interactive_required)
    run_sequence = max(min(total_valid + 1, needed), 1)

    if baseline_valid < int(cfg.baseline_required):
        run_profile = cfg.baseline_profile
    elif interactive_valid < int(cfg.interactive_required):
        run_profile = cfg.interactive_profile
    else:
        # Quota is satisfied; continue suggesting interactive unless operator chooses otherwise.
        run_profile = cfg.interactive_profile
    return {
        "run_profile": run_profile,
        "run_sequence": run_sequence,
        "valid_runs_so_far": total_valid,
        "baseline_valid_runs": baseline_valid,
        "interactive_valid_runs": interactive_valid,
        "protocol_note": (
            "Run sequence counts valid runs (quota slots), not raw attempts. "
            f"Need baseline={cfg.baseline_required} and interactive={cfg.interactive_required} valid run(s)."
        ),
    }


def recompute_dataset_tracker(*, config: DatasetTrackerConfig | None = None) -> Path | None:
    """Recompute dataset tracker entries from evidence packs (backfill/QA refresh)."""
    cfg = config or DatasetTrackerConfig()
    run_dirs = iter_dynamic_run_dirs()
    if not run_dirs:
        return None
    tracker_path = resolve_dataset_plan_read_path()
    tracker_path.parent.mkdir(parents=True, exist_ok=True)

    # Rebuild from evidence packs only. This intentionally drops tracker entries for
    # evidence packs that were deleted locally (e.g., removing invalid runs).
    tracker_path = write_dataset_plan_payload({"apps": {}, "updated_at": datetime.now(UTC).isoformat()})

    # Iterate all evidence packs and re-run the tracker update.
    for run_dir in run_dirs:
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        operator = raw.get("operator") or {}
        tier = operator.get("tier")
        if not tier or str(tier).lower() != "dataset":
            continue
        target = raw.get("target") or {}
        scenario = raw.get("scenario") or {}
        environment = raw.get("environment") or {}
        if not isinstance(target, dict) or not isinstance(operator, dict):
            continue

        manifest = RunManifest(
            run_manifest_version=int(raw.get("run_manifest_version") or 1),
            dynamic_run_id=str(raw.get("dynamic_run_id") or run_dir.name),
            created_at=str(raw.get("created_at") or ""),
            batch_id=raw.get("batch_id"),
            started_at=raw.get("started_at"),
            ended_at=raw.get("ended_at"),
            status=str(raw.get("status") or "unknown"),
            dataset=dict(raw.get("dataset") or {}) if isinstance(raw.get("dataset"), dict) else {},
            target=target,
            environment=environment if isinstance(environment, dict) else {},
            scenario=scenario if isinstance(scenario, dict) else {},
            operator=operator,
        )
        # Attach artifacts so we can compute PCAP size.
        from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord

        artifacts = []
        for item in raw.get("artifacts") or []:
            if not isinstance(item, dict):
                continue
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(item.get("relative_path") or ""),
                    type=str(item.get("type") or ""),
                    produced_by=str(item.get("produced_by") or ""),
                    sha256=str(item.get("sha256")) if isinstance(item.get("sha256"), str) and item.get("sha256") else None,
                    size_bytes=item.get("size_bytes"),
                    origin=item.get("origin"),
                    device_path=item.get("device_path"),
                    pull_status=item.get("pull_status"),
                )
            )
        manifest.artifacts = artifacts
        update_dataset_tracker(manifest, run_dir, config=cfg, event_logger=None)

    return tracker_path if tracker_path.exists() else None


def _active_dataset_package_set() -> set[str]:
    """Return active research cohort packages for tracker scoping.

    The dataset tracker is the active cohort plan, not a global sink for every
    dataset-tagged evidence pack on disk. If cohort lookup is unavailable, keep
    legacy behavior and avoid blocking local/test workflows.
    """
    try:
        packages = active_research_cohort_packages()
    except Exception:
        return set()
    return {str(pkg).strip().lower() for pkg in packages if str(pkg).strip()}


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"apps": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"apps": {}}


def _load_tracker_payload(path: Path) -> dict[str, Any]:
    """Load the tracker without converting corruption into an empty dataset."""

    if not path.exists():
        return {"apps": {}}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"DATASET_PLAN_READ_FAILED:{path}:{exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"DATASET_PLAN_INVALID_JSON:{path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"DATASET_PLAN_INVALID_ROOT:{path}")
    apps = payload.get("apps")
    if apps is None:
        payload["apps"] = {}
    elif not isinstance(apps, dict):
        raise RuntimeError(f"DATASET_PLAN_INVALID_APPS:{path}")
    else:
        for package, app_entry in apps.items():
            if not isinstance(app_entry, dict):
                raise RuntimeError(f"DATASET_PLAN_INVALID_APP_ENTRY:{path}:{package}")
            runs = app_entry.get("runs")
            if runs is None:
                app_entry["runs"] = []
                continue
            if not isinstance(runs, list):
                raise RuntimeError(f"DATASET_PLAN_INVALID_RUNS:{path}:{package}")
            if any(not isinstance(run, dict) for run in runs):
                raise RuntimeError(f"DATASET_PLAN_INVALID_RUN_ENTRY:{path}:{package}")
    return payload


def _parse_dt(value: object) -> datetime | None:
    """Best-effort parse of ISO-ish timestamps used in manifests and tracker runs."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    # Allow common ISO 'Z' suffix.
    if text.endswith("Z") and "+" not in text:
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _apply_quota_marking(
    app_entry: dict[str, Any],
    cfg: DatasetTrackerConfig,
    *,
    package_name: str | None = None,
    resolve_tracker_run_identity_fn=default_resolve_tracker_run_identity,
    scope_tracker_runs_to_active_identity_fn=scope_tracker_runs_to_active_identity,
) -> None:
    """Mark which runs count toward the first N valid runs (quota) and which are extras.

    This is intentionally deterministic from recorded run history, not from the order in
    which the tracker is updated or recomputed.
    """
    runs = app_entry.get("runs")
    if not isinstance(runs, list):
        return
    baseline_needed = max(0, int(cfg.baseline_required))
    interactive_needed = max(0, int(cfg.interactive_required))
    # Total quota slots (Paper #2 locked): baseline + interactive.
    needed = baseline_needed + interactive_needed
    # Reset markers (idempotent).
    for r in runs:
        if isinstance(r, dict):
            r["counts_toward_quota"] = False
            r["extra_run"] = 0
    package_text = str(package_name or "").strip()
    scoped_active_runs: set[str] | None = None
    if package_text:
        try:
            scoped = scope_tracker_runs_to_active_identity_fn(
                package_text,
                [r for r in runs if isinstance(r, dict)],
                resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
            )
            scoped_active_runs = {
                str(r.get("run_id") or "").strip()
                for r in (scoped.get("active_runs") or [])
                if isinstance(r, dict) and str(r.get("run_id") or "").strip()
            }
        except Exception:
            scoped_active_runs = None

    indexed: list[tuple[int, dict[str, Any]]] = []
    for i, r in enumerate(runs):
        if not isinstance(r, dict):
            continue
        run_id = str(r.get("run_id") or "").strip()
        if scoped_active_runs is not None and run_id and run_id not in scoped_active_runs:
            continue
        indexed.append((i, r))
    indexed.sort(
        key=lambda item: (
            _parse_dt(item[1].get("ended_at"))
            or _parse_dt(item[1].get("started_at"))
            or datetime.min.replace(tzinfo=UTC),
            item[0],
        )
    )

    baseline_seen = 0
    interactive_seen = 0
    unknown_profile_seen = 0
    quota_met_at: str | None = None
    quota_met_run_id: str | None = None
    for _, r in indexed:
        is_valid = r.get("valid_dataset_run") is True
        # Paper-mode quota slots must not be consumed by runs explicitly marked
        # paper-ineligible. Keep backward compatibility for historical tracker
        # rows that do not yet have paper_eligible populated.
        if is_valid and r.get("paper_eligible") is False:
            is_valid = False
        # PM lock: low-signal *idle* baselines are retained for exploratory analysis but
        # must never consume paper cohort quota slots.
        #
        # Important: do NOT apply this to baseline_connected; "low_signal" is a
        # non-invalidating tag (and baseline_connected is required for messaging apps).
        prof_lc = str(r.get("run_profile") or "").strip().lower()
        explicit_countable = r.get("countable")
        explicit_non_countable = explicit_countable is False and _explicit_noncountable_is_policy_override(r, prof_lc)
        if is_valid and prof_lc == "baseline_idle" and bool(r.get("low_signal")):
            r["extra_run"] = 1
            is_valid = False
        if not is_valid:
            continue
        if explicit_non_countable:
            r["extra_run"] = 1
            continue
        prof = str(r.get("run_profile") or "")
        is_baseline = _is_baseline_profile(prof, cfg)
        is_interactive = _is_interactive_profile(prof, cfg)

        counted = False
        if is_baseline and baseline_seen < baseline_needed:
            baseline_seen += 1
            counted = True
        elif is_interactive and interactive_seen < interactive_needed:
            interactive_seen += 1
            counted = True
        elif (baseline_seen + interactive_seen + unknown_profile_seen) < needed and not (is_baseline or is_interactive):
            # If profile tagging is inconsistent/unknown, still allow runs to fill
            # total quota slots rather than failing closed. Do not let extra baseline
            # runs satisfy interactive quota (Paper #2 quota is strict).
            unknown_profile_seen += 1
            counted = True

        if counted and (baseline_seen + interactive_seen + unknown_profile_seen) <= needed:
            r["counts_toward_quota"] = True
            if (
                quota_met_at is None
                and baseline_seen >= baseline_needed
                and interactive_seen >= interactive_needed
            ):
                quota_met_at = r.get("ended_at") or r.get("started_at")
                quota_met_run_id = r.get("run_id")
        else:
            r["extra_run"] = 1

    # Stable boolean alias for downstream consumers (menus, DB indexer, exports).
    # "countable" means "counts toward the fixed dataset quota by construction".
    for r in runs:
        if isinstance(r, dict):
            r["countable"] = bool(r.get("counts_toward_quota"))
    _apply_three_verdicts(runs)

    app_entry["quota_met"] = bool(
        baseline_seen >= baseline_needed and interactive_seen >= interactive_needed
    )
    app_entry["quota_met_at"] = quota_met_at
    app_entry["quota_met_run_id"] = quota_met_run_id
    app_entry["extra_valid_runs"] = sum(
        1
        for r in runs
        if isinstance(r, dict)
        and r.get("valid_dataset_run") is True
        and bool(r.get("extra_run"))
    )


def _pcap_size(manifest: RunManifest) -> int | None:
    for artifact in manifest.artifacts:
        if artifact.type == "pcapdroid_capture":
            return int(artifact.size_bytes or 0)
    return None


def _pcap_size_with_meta_fallback(run_dir: Path, manifest: RunManifest) -> int | None:
    direct = _pcap_size(manifest)
    if direct is not None:
        return direct
    meta_rel = None
    for artifact in manifest.artifacts:
        if artifact.type == "pcapdroid_capture_meta" and artifact.relative_path:
            meta_rel = artifact.relative_path
            break
    if not meta_rel:
        return None
    meta_path = run_dir / meta_rel
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    meta_size = payload.get("pcap_size_bytes")
    if isinstance(meta_size, int):
        return meta_size
    resolved_name = payload.get("resolved_pcap_name") or payload.get("pcap_name")
    if not isinstance(resolved_name, str) or not resolved_name.strip():
        return None
    candidate = run_dir / "artifacts" / "pcapdroid_capture" / resolved_name
    if not candidate.exists():
        return None
    try:
        return int(candidate.stat().st_size)
    except OSError:
        return None


def _pcap_report_status(run_dir: Path) -> str | None:
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        return None
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload.get("report_status")


def _features_ok(run_dir: Path) -> bool:
    return (run_dir / "analysis/pcap_features.json").exists()


def evaluate_dataset_validity(
    run_dir: Path,
    manifest: RunManifest,
    entry: dict[str, Any],
    cfg: DatasetTrackerConfig,
) -> dict[str, Any]:
    """Deterministic dataset validity classifier (Paper #2).

    Contract:
    - valid_dataset_run: bool
    - invalid_reason_code: str | None (exactly one when invalid)
    - flags: short_run, no_traffic_observed (ints 0/1)
    """
    flags: dict[str, int] = {"short_run": 0, "no_traffic_observed": 0}
    timeline_state = _timeline_status(run_dir)
    netstats_summary = _netstats_summary(run_dir)
    try:
        netstats_total_bytes = int(
            entry.get("netstats_total_bytes")
            if entry.get("netstats_total_bytes") is not None
            else netstats_summary.get("netstats_total_bytes")
            or 0
        )
    except Exception:
        netstats_total_bytes = 0

    operator = manifest.operator if isinstance(manifest.operator, dict) else {}
    target = manifest.target if isinstance(manifest.target, dict) else {}
    min_bytes = int(
        effective_min_pcap_bytes_for_run_profile(
            run_profile=str(operator.get("run_profile") or ""),
            scenario_id=str((manifest.scenario or {}).get("id") or ""),
            package_name=str(target.get("package_name") or entry.get("package_name") or ""),
            messaging_activity=str(operator.get("messaging_activity") or entry.get("messaging_activity") or ""),
        )
    )

    def _invalid_current(
        code: str,
        flags_payload: dict[str, int],
        **kwargs: Any,
    ) -> dict[str, Any]:
        return _invalid(
            code,
            flags_payload,
            run_dir,
            min_pcap_bytes=min_bytes,
            **kwargs,
        )

    # Dataset protocol metadata is part of the Paper #2 dataset contract.
    missing_protocol = []
    if not operator.get("run_profile"):
        missing_protocol.append("run_profile")
    if operator.get("run_sequence") in (None, "", 0):
        missing_protocol.append("run_sequence")
    if not operator.get("interaction_level"):
        missing_protocol.append("interaction_level")
    if missing_protocol:
        return _invalid_current(
            "PCAP_PARSE_ERROR",
            {**flags, "protocol_missing": 1},
        )

    # Capture interrupted (observer failure) is always invalid for dataset tier.
    #
    # Reason precedence (locked enum, Paper #2):
    # - If PCAP is missing/too small, that is the more specific invalidation than a generic interruption.
    # - Otherwise, fall back to CAPTURE_INTERRUPTED.
    #
    # This avoids "CAPTURE_INTERRUPTED" masking the actionable remediation ("PCAP too small").
    pcap_size = entry.get("pcap_size_bytes")
    try:
        pcap_size_int = int(
            pcap_size
            if pcap_size is not None
            else (_pcap_size_with_meta_fallback(run_dir, manifest) or 0)
        )
    except Exception:
        pcap_size_int = 0
    for obs in manifest.observers or []:
        if getattr(obs, "observer_id", None) == "pcapdroid_capture":
            if str(getattr(obs, "status", "")).lower() == "failed":
                observer_error = str(getattr(obs, "error", "") or "").strip().lower()
                if pcap_size_int <= 0:
                    detail = _pcap_failure_detail(run_dir)
                    return _invalid_current(
                        "PCAP_MISSING",
                        flags,
                        pcap_failure_detail=detail,
                        pcap_failure_summary=_pcap_failure_summary(
                            detail,
                            netstats_total_bytes=netstats_total_bytes,
                            timeline_available=bool(timeline_state.get("timeline_available")),
                            timeline_complete=timeline_state.get("timeline_complete"),
                        ),
                        netstats_observed_bytes=netstats_total_bytes,
                        pcap_available=False,
                        pcap_size_bytes=pcap_size_int,
                        timeline_available=bool(timeline_state.get("timeline_available")),
                        timeline_complete=timeline_state.get("timeline_complete"),
                    )
                if pcap_size_int < min_bytes:
                    return _invalid_current("PCAP_TOO_SMALL", flags)
                if "too small" in observer_error or "smaller than minimum" in observer_error:
                    # Older runs may have been marked observer-failed under a
                    # stricter generic floor even though the retained PCAP is
                    # acceptable under the current run-profile threshold.
                    break
                return _invalid_current("CAPTURE_INTERRUPTED", flags)

    report = _load_report(run_dir)
    telemetry_seconds = _sampling_duration_seconds(run_dir)
    capinfos_seconds = _recompute_duration_seconds_from_report(report)
    # Paper-mode authoritative duration source:
    # prefer parsed PCAP capture span; fallback to telemetry only if capinfos span is unavailable.
    sampling_seconds = capinfos_seconds if capinfos_seconds is not None else telemetry_seconds
    sampling_source = (
        "capinfos_capture_duration_s"
        if capinfos_seconds is not None
        else ("telemetry_sampling_duration_seconds" if telemetry_seconds is not None else "missing")
    )
    if sampling_source == "capinfos_capture_duration_s" and telemetry_seconds is None:
        recompute_wc = _window_count_for_duration(
            float(sampling_seconds),
            window_size_s=float(getattr(profile_config, "WINDOW_SIZE_S", 10.0)),
            stride_s=float(getattr(profile_config, "WINDOW_STRIDE_S", 5.0)),
        )
        _write_recompute_attempt(
            run_dir,
            {
                "attempt_index": 1,
                "trigger_condition": "WINDOW_COUNT_MISSING",
                "started_utc": datetime.now(UTC).isoformat(),
                "ended_utc": datetime.now(UTC).isoformat(),
                "window_count_original": None,
                "window_count_final": int(recompute_wc),
                "window_count_source": "recompute_capinfos_capture_duration_s",
                "outcome": "success" if int(recompute_wc) >= int(MIN_WINDOWS_PER_RUN) else "fail",
            },
        )
    if sampling_source == "missing":
        return _invalid_current(
            "INSUFFICIENT_DURATION",
            flags,
            window_count_original=None,
            window_count_final=None,
            window_count_source="missing",
            actual_sampling_seconds=None,
            actual_sampling_seconds_source="missing",
            sampling_duration_seconds=telemetry_seconds,
        )

    if float(sampling_seconds) < _effective_min_sampling_seconds():
        return _invalid_current(
            "INSUFFICIENT_DURATION",
            flags,
            window_count_original=None,
            window_count_final=None,
            window_count_source="sampling_duration_seconds",
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
        )
    # Capinfos capture span may differ by ~1s from the guided/script target due
    # to recorder start/stop boundaries. Keep short_run as a quality hint, but
    # avoid flagging tiny jitter that operators cannot control.
    short_run_floor = _effective_target_sampling_seconds() - float(SHORT_RUN_TOLERANCE_SECONDS)
    if float(sampling_seconds) < short_run_floor:
        flags["short_run"] = 1
    window_count_original = _window_count_for_duration(
        sampling_seconds,
        window_size_s=float(getattr(profile_config, "WINDOW_SIZE_S", 10.0)),
        stride_s=float(getattr(profile_config, "WINDOW_STRIDE_S", 5.0)),
    )
    window_count_final = int(window_count_original)
    window_count_source = (
        "recompute_capinfos_capture_duration_s"
        if sampling_source == "capinfos_capture_duration_s" and telemetry_seconds is None
        else f"computed_from_{sampling_source}"
    )
    if int(window_count_original) < int(MIN_WINDOWS_PER_RUN):
        recompute_duration = telemetry_seconds if sampling_source == "capinfos_capture_duration_s" else capinfos_seconds
        recompute_wc = None
        if recompute_duration is not None:
            recompute_wc = _window_count_for_duration(
                recompute_duration,
                window_size_s=float(getattr(profile_config, "WINDOW_SIZE_S", 10.0)),
                stride_s=float(getattr(profile_config, "WINDOW_STRIDE_S", 5.0)),
            )
            _write_recompute_attempt(
                run_dir,
                {
                    "attempt_index": 1,
                    "trigger_condition": "WINDOW_COUNT_TOO_LOW",
                    "started_utc": datetime.now(UTC).isoformat(),
                    "ended_utc": datetime.now(UTC).isoformat(),
                    "window_count_original": int(window_count_original),
                    "window_count_final": int(recompute_wc),
                    "window_count_source": "recompute_capinfos_capture_duration_s",
                    "outcome": "success" if int(recompute_wc) >= int(MIN_WINDOWS_PER_RUN) else "fail",
                },
            )
        if recompute_wc is not None and int(recompute_wc) >= int(MIN_WINDOWS_PER_RUN):
            window_count_final = int(recompute_wc)
            window_count_source = "recompute_capinfos_capture_duration_s"
        else:
            return _invalid_current(
                "INSUFFICIENT_DURATION",
                {**flags, "window_count_too_low": 1, "retry_attempted": 1},
                window_count_original=int(window_count_original),
                window_count_final=(int(recompute_wc) if recompute_wc is not None else int(window_count_original)),
                window_count_source=(
                    "recompute_capinfos_capture_duration_s"
                    if recompute_wc is not None
                    else "sampling_duration_seconds"
                ),
                actual_sampling_seconds=float(sampling_seconds),
                actual_sampling_seconds_source=sampling_source,
                sampling_duration_seconds=telemetry_seconds,
            )

    # PCAP size policy.
    if pcap_size_int <= 0:
        detail = _pcap_failure_detail(run_dir)
        return _invalid_current(
            "PCAP_MISSING",
            flags,
            pcap_failure_detail=detail,
            pcap_failure_summary=_pcap_failure_summary(
                detail,
                netstats_total_bytes=netstats_total_bytes,
                timeline_available=bool(timeline_state.get("timeline_available")),
                timeline_complete=timeline_state.get("timeline_complete"),
            ),
            netstats_observed_bytes=netstats_total_bytes,
            pcap_available=False,
            pcap_size_bytes=pcap_size_int,
            timeline_available=bool(timeline_state.get("timeline_available")),
            timeline_complete=timeline_state.get("timeline_complete"),
        )
    if pcap_size_int < min_bytes:
        return _invalid_current("PCAP_TOO_SMALL", flags)

    # PCAP report must exist and not be skipped for dataset tier.
    if report is None:
        return _invalid_current(
            "PCAP_REPORT_MISSING",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
        )
    report_status = report.get("report_status")
    if report_status is None:
        return _invalid_current(
            "PCAP_REPORT_MISSING",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
        )
    if str(report_status).lower() == "skip":
        detail = _pcap_failure_detail(run_dir)
        return _invalid_current(
            "PCAP_REPORT_SKIP",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
            pcap_failure_detail=detail,
            pcap_failure_summary=_pcap_failure_summary(
                detail,
                netstats_total_bytes=netstats_total_bytes,
                timeline_available=bool(timeline_state.get("timeline_available")),
                timeline_complete=timeline_state.get("timeline_complete"),
            ),
            netstats_observed_bytes=netstats_total_bytes,
            pcap_available=False,
            pcap_size_bytes=pcap_size_int,
            timeline_available=bool(timeline_state.get("timeline_available")),
            timeline_complete=timeline_state.get("timeline_complete"),
        )

    # Missing tools are a dataset-tier invalidation (environment not dataset-ready).
    missing = report.get("missing_tools") or []
    missing_set = {str(x).lower() for x in missing if x}
    if "tshark" in missing_set:
        return _invalid_current(
            "MISSING_TOOLS_TSHARK",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
        )
    if "capinfos" in missing_set:
        return _invalid_current(
            "MISSING_TOOLS_CAPINFOS",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
        )

    # Protocol hierarchy may be empty only with an explicit no_traffic_observed flag.
    proto = report.get("protocol_hierarchy") or []
    no_traffic = report.get("no_traffic_observed")
    try:
        no_traffic_int = int(no_traffic or 0)
    except Exception:
        no_traffic_int = 0
    if not proto:
        if no_traffic_int == 1:
            flags["no_traffic_observed"] = 1
        else:
            return _invalid_current(
                "PCAP_REPORT_EMPTY_NO_REASON",
                flags,
                window_count_original=int(window_count_original),
                window_count_final=int(window_count_final),
                window_count_source=window_count_source,
                actual_sampling_seconds=float(sampling_seconds),
                actual_sampling_seconds_source=sampling_source,
                sampling_duration_seconds=telemetry_seconds,
            )

    # Features must exist for dataset counting.
    if not _features_ok(run_dir):
        # We intentionally map this to a report parse error-like code to avoid
        # expanding the locked enum set for Paper #2.
        detail = "PCAP_PARSE_FAILED" if pcap_size_int > 0 else _pcap_failure_detail(run_dir)
        return _invalid_current(
            "PCAP_PARSE_ERROR",
            flags,
            window_count_original=int(window_count_original),
            window_count_final=int(window_count_final),
            window_count_source=window_count_source,
            actual_sampling_seconds=float(sampling_seconds),
            actual_sampling_seconds_source=sampling_source,
            sampling_duration_seconds=telemetry_seconds,
            pcap_failure_detail=detail,
            pcap_failure_summary=_pcap_failure_summary(
                detail,
                netstats_total_bytes=netstats_total_bytes,
                timeline_available=bool(timeline_state.get("timeline_available")),
                timeline_complete=timeline_state.get("timeline_complete"),
            ),
            netstats_observed_bytes=netstats_total_bytes,
            pcap_available=pcap_size_int > 0,
            pcap_size_bytes=pcap_size_int,
            timeline_available=bool(timeline_state.get("timeline_available")),
            timeline_complete=timeline_state.get("timeline_complete"),
        )

    return {
        "valid_dataset_run": True,
        "invalid_reason_code": None,
        "sampling_duration_seconds": telemetry_seconds,
        "actual_sampling_seconds": float(sampling_seconds),
        "actual_sampling_seconds_source": sampling_source,
        "min_pcap_bytes": min_bytes,
        "netstats_observed_bytes": netstats_total_bytes,
        "pcap_available": True,
        "pcap_size_bytes": pcap_size_int,
        "pcap_failure_detail": None,
        "pcap_failure_summary": None,
        "timeline_available": bool(timeline_state.get("timeline_available")),
        "timeline_complete": timeline_state.get("timeline_complete"),
        "window_count_original": int(window_count_original),
        "window_count_final": int(window_count_final),
        "window_count_source": window_count_source,
        "window_count": int(window_count_final),
        "min_window_count": int(MIN_WINDOWS_PER_RUN),
        **flags,
    }


def _netstats_summary(run_dir: Path) -> dict[str, Any]:
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    stats = (payload.get("telemetry") or {}).get("stats") or {}
    total_in = stats.get("netstats_bytes_in_total")
    total_out = stats.get("netstats_bytes_out_total")
    try:
        total = int(total_in or 0) + int(total_out or 0)
    except Exception:
        total = None
    return {
        "netstats_bytes_in_total": total_in,
        "netstats_bytes_out_total": total_out,
        "netstats_total_bytes": total,
    }


def _pcap_capture_stats(run_dir: Path) -> dict[str, Any]:
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        return {}
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    parsed = (payload.get("capinfos") or {}).get("parsed") or {}
    return {
        "pcap_packet_count": parsed.get("packet_count"),
        "pcap_capture_duration_s": parsed.get("capture_duration_s"),
        "pcap_data_size_bytes": parsed.get("data_size_bytes"),
    }


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _timeline_status(run_dir: Path) -> dict[str, Any]:
    timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json")
    if not isinstance(timeline, dict):
        return {"timeline_available": False, "timeline_complete": None}
    return {
        "timeline_available": True,
        "timeline_complete": bool(timeline.get("timeline_complete")),
    }


def _pcap_failure_detail(run_dir: Path) -> str | None:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import dataset_pcap_failure_detail

    return dataset_pcap_failure_detail(run_dir, pcap_size_int=0)


def _pcap_failure_summary(
    detail: str | None,
    *,
    netstats_total_bytes: int | None = None,
    timeline_available: bool = False,
    timeline_complete: bool | None = None,
) -> str | None:
    if not detail:
        return None
    observed_traffic = False
    try:
        observed_traffic = int(netstats_total_bytes or 0) > 0
    except Exception:
        observed_traffic = False
    if observed_traffic:
        base = "Network traffic was observed by Android netstats, but the PCAP capture artifact is empty or unavailable."
    else:
        base = "PCAP capture artifact is empty or unavailable."
    if timeline_available:
        suffix = " Scripted interaction timeline is still available for protocol validation."
        if timeline_complete is False:
            suffix = " Scripted interaction timeline is present but incomplete."
    else:
        suffix = ""
    return base + suffix


def _derive_paper_eligibility_fields(
    run_dir: Path,
    *,
    manifest_payload: dict[str, Any] | None = None,
    plan_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Backfill tracker with evidence-derived paper eligibility state.

    Tracker fields are cache only; canonical truth remains evidence-pack manifests.
    """
    manifest = manifest_payload if isinstance(manifest_payload, dict) else _load(run_dir / "run_manifest.json")
    plan = plan_payload if isinstance(plan_payload, dict) else _load(run_dir / "inputs" / "static_dynamic_plan.json")
    if not isinstance(manifest, dict):
        return {
            "paper_eligible": False,
            "paper_exclusion_primary_reason_code": "EXCLUDED_NO_EVIDENCE_PACK",
            "paper_exclusion_all_reason_codes": ["EXCLUDED_NO_EVIDENCE_PACK"],
        }
    eligibility = derive_freeze_eligibility(
        manifest=manifest if isinstance(manifest, dict) else {},
        plan=plan if isinstance(plan, dict) else {},
        min_windows=int(MIN_WINDOWS_PER_RUN),
        required_capture_policy_version=int(getattr(profile_config, "PAPER_CONTRACT_VERSION", 1)),
    )
    return {
        "paper_eligible": bool(eligibility.paper_eligible),
        "paper_exclusion_primary_reason_code": eligibility.reason_code,
        "paper_exclusion_all_reason_codes": list(eligibility.all_reason_codes),
    }


_PROTOCOL_REASON_CODES = {
    "EXCLUDED_SCRIPT_HASH_MISMATCH",
    "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH",
    "EXCLUDED_PROTOCOL_LEGACY_TEMPLATE",
    "EXCLUDED_SCRIPT_PROTOCOL_SEND",
    "EXCLUDED_SCRIPT_ABORT",
    "EXCLUDED_SCRIPT_END_MISSING",
    "EXCLUDED_SCRIPT_STEP_MISSING",
    "EXCLUDED_SCRIPT_TIMEOUT",
    "EXCLUDED_SCRIPT_UI_STATE_MISMATCH",
    "EXCLUDED_PROTOCOL_FIT_POOR",
    "EXCLUDED_INTENT_NOT_ALLOWED",
}


def derive_three_verdicts_for_row(row: dict[str, Any]) -> tuple[str, str, str]:
    """Return (technical_validity, protocol_compliance, cohort_eligibility)."""
    technical_validity = "VALID" if row.get("valid_dataset_run") is True else "INVALID"
    all_reasons = row.get("paper_exclusion_all_reason_codes")
    all_reasons_set = {str(x) for x in all_reasons} if isinstance(all_reasons, list) else set()
    protocol_compliance = (
        "NON_COMPLIANT"
        if any(reason in _PROTOCOL_REASON_CODES for reason in all_reasons_set)
        else "COMPLIANT"
    )
    if row.get("paper_eligible") is True:
        cohort_eligibility = "COUNTABLE" if bool(row.get("countable")) else "EXTRA"
    else:
        cohort_eligibility = "EXCLUDED"
    return technical_validity, protocol_compliance, cohort_eligibility


def _apply_three_verdicts(runs: list[dict[str, Any]]) -> None:
    """Populate three independent verdict layers on tracker rows."""
    for r in runs:
        if not isinstance(r, dict):
            continue
        technical_validity, protocol_compliance, cohort_eligibility = derive_three_verdicts_for_row(r)
        r["technical_validity"] = technical_validity
        r["protocol_compliance"] = protocol_compliance
        r["cohort_eligibility"] = cohort_eligibility


def _compute_overlap_stats(runs: list[dict[str, Any]]) -> dict[str, Any]:
    ratios = []
    dynamic_only = []
    bytes_per_sec = []
    per_source: dict[str, list[float]] = {}
    for entry in runs:
        if not entry.get("valid_dataset_run"):
            continue
        run_id = entry.get("run_id")
        if not run_id:
            continue
        run_dir = resolve_dynamic_run_dir(str(run_id))
        if run_dir is None:
            continue
        overlap_path = run_dir / "analysis" / "static_dynamic_overlap.json"
        features_path = run_dir / "analysis" / "pcap_features.json"
        if not overlap_path.exists():
            continue
        try:
            payload = json.loads(overlap_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        features_payload = None
        if features_path.exists():
            try:
                features_payload = json.loads(features_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                features_payload = None
        ratio = payload.get("overlap_ratio")
        if isinstance(ratio, (int, float)):
            ratios.append(float(ratio))
        dyn_ratio = payload.get("dynamic_only_ratio")
        if isinstance(dyn_ratio, (int, float)):
            dynamic_only.append(float(dyn_ratio))
        if isinstance(features_payload, dict):
            metrics = features_payload.get("metrics")
            if isinstance(metrics, dict):
                byte_rate = metrics.get("data_byte_rate_bps")
                if isinstance(byte_rate, (int, float)):
                    bytes_per_sec.append(float(byte_rate))
        for source, source_payload in (payload.get("overlap_by_source") or {}).items():
            if not isinstance(source_payload, dict):
                continue
            src_ratio = source_payload.get("overlap_ratio")
            if isinstance(src_ratio, (int, float)):
                per_source.setdefault(str(source), []).append(float(src_ratio))
    return {
        "runs": len(ratios),
        "overlap_ratio_mean": _mean_or_none(ratios),
        "overlap_ratio_std": _std_or_none(ratios),
        "overlap_ratio_variance": _variance_or_none(ratios),
        "overlap_ratio_cv": _cv_or_none(ratios),
        "overlap_ratio_max_delta": _max_delta_or_none(ratios),
        "dynamic_only_ratio_mean": _mean_or_none(dynamic_only),
        "dynamic_only_ratio_std": _std_or_none(dynamic_only),
        "dynamic_only_ratio_variance": _variance_or_none(dynamic_only),
        "dynamic_only_ratio_cv": _cv_or_none(dynamic_only),
        "dynamic_only_ratio_max_delta": _max_delta_or_none(dynamic_only),
        "bytes_per_sec_mean": _mean_or_none(bytes_per_sec),
        "bytes_per_sec_std": _std_or_none(bytes_per_sec),
        "bytes_per_sec_variance": _variance_or_none(bytes_per_sec),
        "bytes_per_sec_cv": _cv_or_none(bytes_per_sec),
        "bytes_per_sec_max_delta": _max_delta_or_none(bytes_per_sec),
        "per_source": {
            source: {
                "mean": _mean_or_none(values),
                "std": _std_or_none(values),
                "variance": _variance_or_none(values),
                "cv": _cv_or_none(values),
                "max_delta": _max_delta_or_none(values),
                "runs": len(values),
            }
            for source, values in sorted(per_source.items())
        },
    }


def _mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return float(mean(values))


def _std_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(pstdev(values))


def _variance_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(pvariance(values))


def _cv_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    avg = _mean_or_none(values)
    if avg is None or avg == 0:
        return None
    std = _std_or_none(values)
    if std is None:
        return None
    return float(std) / float(avg)


def _max_delta_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(max(values) - min(values))


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, Any]) -> None:
    if event_logger:
        event_logger.log(event, payload)


def _invalid(
    code: str,
    flags: dict[str, int],
    run_dir: Path,
    *,
    min_pcap_bytes: int | None = None,
    window_count: int | None = None,
    window_count_original: int | None = None,
    window_count_final: int | None = None,
    window_count_source: str | None = None,
    actual_sampling_seconds: float | None = None,
    actual_sampling_seconds_source: str | None = None,
    sampling_duration_seconds: float | None = None,
    pcap_failure_detail: str | None = None,
    pcap_failure_summary: str | None = None,
    netstats_observed_bytes: int | None = None,
    pcap_available: bool | None = None,
    pcap_size_bytes: int | None = None,
    timeline_available: bool | None = None,
    timeline_complete: bool | None = None,
) -> dict[str, Any]:
    if code not in _VALIDITY_ENUM:
        code = "PCAP_PARSE_ERROR"
    if pcap_failure_detail and pcap_failure_detail not in _PCAP_FAILURE_DETAILS:
        pcap_failure_detail = None
    wc_final = window_count_final if window_count_final is not None else window_count
    wc_original = window_count_original if window_count_original is not None else window_count
    wc_source = str(window_count_source or "sampling_duration_seconds")
    telemetry_sampling = sampling_duration_seconds if sampling_duration_seconds is not None else _sampling_duration_seconds(run_dir)
    return {
        "valid_dataset_run": False,
        "invalid_reason_code": code,
        "sampling_duration_seconds": telemetry_sampling,
        "actual_sampling_seconds": actual_sampling_seconds,
        "actual_sampling_seconds_source": actual_sampling_seconds_source,
        "min_pcap_bytes": int(min_pcap_bytes if min_pcap_bytes is not None else MIN_PCAP_BYTES),
        "netstats_observed_bytes": netstats_observed_bytes,
        "pcap_available": pcap_available,
        "pcap_size_bytes": pcap_size_bytes,
        "pcap_failure_detail": pcap_failure_detail,
        "pcap_failure_summary": pcap_failure_summary,
        "timeline_available": timeline_available,
        "timeline_complete": timeline_complete,
        "window_count_original": wc_original,
        "window_count_final": wc_final,
        "window_count_source": wc_source,
        "window_count": wc_final,
        "min_window_count": int(MIN_WINDOWS_PER_RUN),
        **flags,
    }


def _window_count_for_duration(duration_s: float, *, window_size_s: float, stride_s: float) -> int:
    try:
        t = float(duration_s)
        w = float(window_size_s)
        s = float(stride_s)
    except Exception:
        return 0
    if t <= 0 or w <= 0 or s <= 0:
        return 0
    if t < w:
        return 0
    return int(((t - w) // s) + 1)


def _sampling_duration_seconds(run_dir: Path) -> float | None:
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    telemetry = (payload.get("telemetry") or {}).get("stats") or {}
    sampling_duration = telemetry.get("sampling_duration_seconds")
    try:
        return float(sampling_duration)
    except Exception:
        return None


def _load_report(run_dir: Path) -> dict[str, Any] | None:
    report_path = run_dir / "analysis" / "pcap_report.json"
    if not report_path.exists():
        return None
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return {"report_status": None}


def _recompute_duration_seconds_from_report(report: dict[str, Any] | None) -> float | None:
    if not isinstance(report, dict):
        return None
    parsed = (report.get("capinfos") or {}).get("parsed") if isinstance(report.get("capinfos"), dict) else {}
    if not isinstance(parsed, dict):
        return None
    try:
        value = float(parsed.get("capture_duration_s"))
    except Exception:
        return None
    if value <= 0:
        return None
    return value


def _write_recompute_attempt(run_dir: Path, payload: dict[str, Any]) -> None:
    try:
        analysis_dir = run_dir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        path = analysis_dir / "recompute_attempt.jsonl"
        line = json.dumps(payload, sort_keys=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception:
        # Audit artifact writing must never break classification.
        return


__all__ = [
    "DatasetTrackerConfig",
    "derive_three_verdicts_for_row",
    "load_dataset_tracker",
    "peek_next_run_protocol",
    "recompute_dataset_tracker",
    "update_dataset_tracker",
]
