"""Read-only build-aware paper-freeze selection for dynamic evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    _normalize_tracker_payload,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
    active_research_cohort_label,
    active_research_cohort_packages,
)
from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_plan_read_path
from scytaledroid.DynamicAnalysis.tracker_scope import (
    default_resolve_tracker_run_identity,
    resolve_active_package_identity,
)


@dataclass(frozen=True)
class PaperFreezeBuildCandidate:
    package_name: str
    version_code: str
    version_name: str
    static_run_id: str
    base_apk_sha256: str
    strict_idle_runs: int
    quiescent_fg_runs: int
    baseline_valid_runs: int
    interactive_valid_runs: int
    valid_pcap_count: int
    qa_valid_count: int
    first_capture_at: str
    last_capture_at: str
    relation_to_active_target: str
    missing_baseline_runs: int
    missing_interactive_runs: int
    status: str
    static_run_ids: tuple[str, ...] = field(default_factory=tuple)
    run_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PaperFreezeRecommendation:
    package_name: str
    installed_target_version_code: str
    installed_target_version_name: str
    installed_target_static_run_id: str
    installed_target_base_apk_sha256: str
    selected_build: PaperFreezeBuildCandidate | None
    build_candidates: tuple[PaperFreezeBuildCandidate, ...]
    refresh_candidate: bool
    retained_prior_build_selected: bool


@dataclass(frozen=True)
class PaperFreezeDecisionRow:
    package_name: str
    selected_version_code: str
    selected_version_name: str
    installed_version_code: str
    relation: str
    strict_idle_count: int
    quiescent_fg_count: int
    baseline_count: int
    interactive_count: int
    missing_baseline_runs: int
    missing_interactive_runs: int
    valid_pcap_count: int
    baseline_class_note: str
    draft_role: str
    collectability: str
    action: str
    blocker: bool
    reason: str
    bucket: str


@dataclass(frozen=True)
class PaperEvidenceTierRow:
    package_name: str
    evidence_tier: str
    paper_usable: str
    selected_relation: str
    selected_version_code: str
    selected_version_name: str
    installed_version_code: str
    current_installed_drifted: str
    operational_installed_version_code: str
    operational_live_drifted: str
    operational_drift_detail: str
    selected_static_run_ids: str
    selected_dynamic_run_ids: str
    pcap_available_count: int
    strict_idle_count: int
    quiescent_fg_count: int
    baseline_count: int
    interactive_count: int
    retained_prior_build_count: int
    build_candidates_seen: int
    evidence_scope: str
    caveat: str
    recommended_final_run_tonight: str
    future_work: str


_DECISION_BUCKET_ORDER = (
    "MUST_RUN_NOW",
    "READY_DO_NOT_TOUCH",
    "SWITCH_TARGET_CANDIDATE",
    "RUN_ONLY_IF_EASY",
    "DEFER_REFRESH_WAVE",
)

_PAPER_EVIDENCE_TIER_ORDER = {
    "STRICT_CURRENT_BUILD_COMPLETE": 1,
    "CURRENT_BUILD_MIXED_BASELINE": 2,
    "PRIOR_BUILD_PAPER_EVIDENCE": 3,
    "SUPPLEMENTAL_LEGACY_CONTEXT": 4,
    "TRUE_EVIDENCE_HOLE": 5,
}


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_tracker_payload(
    cfg: DatasetTrackerConfig,
) -> tuple[str, dict[str, object], dict[str, object] | None]:
    tracker_path = Path(resolve_dataset_plan_read_path())
    if not tracker_path.exists():
        return "missing", {"apps": {}}, None
    try:
        raw_payload = json.loads(tracker_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "invalid", {"apps": {}}, None
    except OSError:
        return "unavailable", {"apps": {}}, None
    if not isinstance(raw_payload, dict):
        return "invalid", {"apps": {}}, None

    apps = raw_payload.get("apps")
    status = "ok" if isinstance(apps, dict) or "apps" not in raw_payload else "invalid"
    normalized = _normalize_tracker_payload(raw_payload, cfg, dirty=[False])
    normalized_apps = normalized.get("apps")
    if not isinstance(normalized_apps, dict):
        return "invalid", {"apps": {}}, None
    return status, normalized, raw_payload


def _run_mode(run: dict[str, Any]) -> str:
    profile = _norm_text(run.get("run_profile")).lower()
    if profile.startswith("baseline") or "baseline" in profile or "idle" in profile:
        return "baseline"
    if "interaction" in profile or "interactive" in profile:
        return "interactive"
    return "unknown"


def _is_quiescent_fg_run(run: dict[str, Any]) -> bool:
    profile = _norm_text(run.get("run_profile")).lower()
    return profile == "baseline_idle" and run.get("baseline_not_idle") is True


def _run_identity_key(package_name: str, run: dict[str, Any]) -> tuple[str, str, str, str]:
    version_code, base_sha = default_resolve_tracker_run_identity(package_name, run)
    return (
        _norm_text(package_name).lower(),
        _norm_text(version_code or run.get("version_code") or run.get("observed_version_code")),
        _norm_text(run.get("version_name")),
        _norm_text(base_sha or run.get("base_apk_sha256")).lower(),
    )


def _build_status(*, baseline_valid_runs: int, interactive_valid_runs: int, cfg: DatasetTrackerConfig) -> tuple[str, int, int]:
    missing_baseline = max(0, int(cfg.baseline_required) - int(baseline_valid_runs))
    missing_interactive = max(0, int(cfg.interactive_required) - int(interactive_valid_runs))
    if baseline_valid_runs <= 0 and interactive_valid_runs <= 0:
        return ("insufficient", missing_baseline, missing_interactive)
    if missing_baseline > 0:
        return ("needs baseline", missing_baseline, missing_interactive)
    if missing_interactive > 0:
        return ("needs interactive", missing_baseline, missing_interactive)
    return ("ready", 0, 0)


def _relation_to_active_target(
    *,
    version_code: str,
    base_apk_sha256: str,
    active_version_code: str,
    active_base_sha: str,
) -> str:
    active_vc = _norm_text(active_version_code)
    active_sha = _norm_text(active_base_sha).lower()
    build_vc = _norm_text(version_code)
    build_sha = _norm_text(base_apk_sha256).lower()
    if active_vc or active_sha:
        if (active_sha and build_sha and active_sha == build_sha) or (
            active_vc and build_vc and active_vc == build_vc
        ):
            return "current"
        return "prior-build"
    return "retained"


def _missing_total(candidate: PaperFreezeBuildCandidate | None) -> int:
    if candidate is None:
        return 0
    return int(candidate.missing_baseline_runs) + int(candidate.missing_interactive_runs)


def _current_candidate(
    candidates: tuple[PaperFreezeBuildCandidate, ...],
    *,
    installed_version_code: str,
) -> PaperFreezeBuildCandidate | None:
    installed_vc = _norm_text(installed_version_code)
    for candidate in candidates:
        if candidate.relation_to_active_target != "current":
            continue
        if installed_vc and _norm_text(candidate.version_code) != installed_vc:
            continue
        return candidate
    return None


def _action_for_current_gap(candidate: PaperFreezeBuildCandidate) -> str:
    if int(candidate.missing_baseline_runs) > 0:
        return "baseline"
    if int(candidate.missing_interactive_runs) > 0:
        return "interactive"
    return "none"


def _reason_for_current_gap(candidate: PaperFreezeBuildCandidate) -> str:
    if int(candidate.missing_baseline_runs) > 0:
        return "Selected current build is collectable now and missing baseline evidence."
    return "Selected current build is collectable now and missing interactive evidence."


def _reason_for_optional_interactive_depth(candidate: PaperFreezeBuildCandidate) -> str:
    if int(candidate.quiescent_fg_runs) > 0:
        return (
            "Selected build has baseline evidence, including Quiescent FG app-activity tags; "
            "additional interactive captures improve depth but do not block the rough draft."
        )
    return (
        "Selected build has complete baseline evidence and is paper-usable; "
        "additional interactive captures improve depth but do not block the rough draft."
    )


def _baseline_class_note(candidate: PaperFreezeBuildCandidate | None) -> str:
    if candidate is None:
        return "No selected paper target."
    strict_i = int(candidate.strict_idle_runs)
    quiescent_i = int(candidate.quiescent_fg_runs)
    if strict_i > 0 and quiescent_i > 0:
        return "Baseline evidence includes Quiescent FG app-activity tags for this selected build."
    if quiescent_i > 0:
        return "Quiescent FG evidence exists as app-activity tagged baseline evidence for this selected build."
    return "No-touch foreground baseline evidence is the quota baseline lane for paper readiness."


def _strict_no_touch_count(candidate: PaperFreezeBuildCandidate | None) -> int:
    if candidate is None:
        return 0
    return max(0, int(candidate.strict_idle_runs))


def _recommended_plan_action(
    *,
    status: str,
    selected: PaperFreezeBuildCandidate | None,
) -> str:
    if status == "needs interactive":
        return "interactive"
    if status in {"needs baseline", "insufficient"}:
        return "baseline"
    return "none"


def _classify_decision_row(
    recommendation: PaperFreezeRecommendation,
) -> PaperFreezeDecisionRow:
    selected = recommendation.selected_build
    selected_relation = selected.relation_to_active_target if selected else "none"
    installed_vc = _norm_text(recommendation.installed_target_version_code)
    current_candidate = _current_candidate(
        recommendation.build_candidates,
        installed_version_code=installed_vc,
    )

    if selected and selected.status == "ready":
        collectability = (
            "ready_current_build"
            if selected_relation == "current"
            else "ready_prior_build"
        )
        reason = (
            "Paper target is ready on current build."
            if selected_relation == "current"
            else "Paper target is ready on selected build; current build is refresh work."
        )
        return PaperFreezeDecisionRow(
            package_name=recommendation.package_name,
            selected_version_code=_norm_text(selected.version_code),
            selected_version_name=_norm_text(selected.version_name),
            installed_version_code=installed_vc,
            relation=selected_relation or "none",
            strict_idle_count=_strict_no_touch_count(selected),
            quiescent_fg_count=int(selected.quiescent_fg_runs),
            baseline_count=int(selected.baseline_valid_runs),
            interactive_count=int(selected.interactive_valid_runs),
            missing_baseline_runs=int(selected.missing_baseline_runs),
            missing_interactive_runs=int(selected.missing_interactive_runs),
            valid_pcap_count=int(selected.valid_pcap_count),
            baseline_class_note=_baseline_class_note(selected),
            draft_role="ready_coverage",
            collectability=collectability,
            action="leave frozen",
            blocker=False,
            reason=reason,
            bucket="READY_DO_NOT_TOUCH",
        )

    if (
        selected
        and selected_relation == "current"
        and installed_vc
        and _norm_text(selected.version_code) == installed_vc
        and _missing_total(selected) > 0
    ):
        missing_baseline = int(selected.missing_baseline_runs)
        if missing_baseline <= 0 and int(selected.missing_interactive_runs) > 0:
            return PaperFreezeDecisionRow(
                package_name=recommendation.package_name,
                selected_version_code=_norm_text(selected.version_code),
                selected_version_name=_norm_text(selected.version_name),
                installed_version_code=installed_vc,
                relation=selected_relation,
                strict_idle_count=_strict_no_touch_count(selected),
                quiescent_fg_count=int(selected.quiescent_fg_runs),
                baseline_count=int(selected.baseline_valid_runs),
                interactive_count=int(selected.interactive_valid_runs),
                missing_baseline_runs=int(selected.missing_baseline_runs),
                missing_interactive_runs=int(selected.missing_interactive_runs),
                valid_pcap_count=int(selected.valid_pcap_count),
                baseline_class_note=_baseline_class_note(selected),
                draft_role="interactive_depth_gap",
                collectability="optional_current_depth",
                action="interactive if claim needs it",
                blocker=False,
                reason=_reason_for_optional_interactive_depth(selected),
                bucket="RUN_ONLY_IF_EASY",
            )
        return PaperFreezeDecisionRow(
            package_name=recommendation.package_name,
            selected_version_code=_norm_text(selected.version_code),
            selected_version_name=_norm_text(selected.version_name),
            installed_version_code=installed_vc,
            relation=selected_relation,
            strict_idle_count=_strict_no_touch_count(selected),
            quiescent_fg_count=int(selected.quiescent_fg_runs),
            baseline_count=int(selected.baseline_valid_runs),
            interactive_count=int(selected.interactive_valid_runs),
            missing_baseline_runs=int(selected.missing_baseline_runs),
            missing_interactive_runs=int(selected.missing_interactive_runs),
            valid_pcap_count=int(selected.valid_pcap_count),
            baseline_class_note=_baseline_class_note(selected),
            draft_role="current_gap",
            collectability="collectable_now",
            action=_action_for_current_gap(selected),
            blocker=True,
            reason=_reason_for_current_gap(selected),
            bucket="MUST_RUN_NOW",
        )

    if selected and selected_relation == "prior-build" and _missing_total(selected) > 0:
        current_collectable = bool(
            current_candidate
            and installed_vc
            and _norm_text(current_candidate.version_code) == installed_vc
        )
        current_missing = _missing_total(current_candidate)
        selected_missing = _missing_total(selected)
        current_faster = bool(
            current_collectable
            and current_candidate is not None
            and (
                (
                    int(current_candidate.missing_baseline_runs) == 0
                    and int(selected.missing_interactive_runs) > 0
                )
                or
                (
                    int(current_candidate.missing_baseline_runs) == 0
                    and int(current_candidate.missing_interactive_runs)
                    < int(selected.missing_interactive_runs)
                )
                or (
                    current_missing > 0
                    and current_missing <= selected_missing
                )
            )
        )
        if current_faster:
            basis = current_candidate if current_candidate is not None else selected
            basis_note = _baseline_class_note(basis)
            if basis is current_candidate:
                basis_note = (
                    f"{basis_note} Counts in this decision row describe the current installed "
                    "switch candidate; selected prior-build paper evidence counts remain in "
                    "paper_freeze_manifest and paper_evidence_tiers."
                )
            return PaperFreezeDecisionRow(
                package_name=recommendation.package_name,
                selected_version_code=_norm_text(selected.version_code),
                selected_version_name=_norm_text(selected.version_name),
                installed_version_code=installed_vc,
                relation=selected_relation,
                strict_idle_count=_strict_no_touch_count(selected),
                quiescent_fg_count=int(selected.quiescent_fg_runs),
                baseline_count=int(basis.baseline_valid_runs),
                interactive_count=int(basis.interactive_valid_runs),
                missing_baseline_runs=int(basis.missing_baseline_runs),
                missing_interactive_runs=int(basis.missing_interactive_runs),
                valid_pcap_count=int(basis.valid_pcap_count),
                baseline_class_note=basis_note,
                draft_role="target_decision",
                collectability="switch_target_candidate",
                action="decide target",
                blocker=False,
                reason=(
                    "Selected prior build is incomplete; installed build appears faster to finish. "
                    "This row's run-count columns use the current installed switch candidate, not "
                    "the selected prior-build paper evidence."
                ),
                bucket="SWITCH_TARGET_CANDIDATE",
            )
        if selected_missing <= 2 and (
            int(selected.baseline_valid_runs) + int(selected.interactive_valid_runs)
        ) > 0:
            return PaperFreezeDecisionRow(
                package_name=recommendation.package_name,
                selected_version_code=_norm_text(selected.version_code),
                selected_version_name=_norm_text(selected.version_name),
                installed_version_code=installed_vc,
                relation=selected_relation,
                strict_idle_count=_strict_no_touch_count(selected),
                quiescent_fg_count=int(selected.quiescent_fg_runs),
                baseline_count=int(selected.baseline_valid_runs),
                interactive_count=int(selected.interactive_valid_runs),
                missing_baseline_runs=int(selected.missing_baseline_runs),
                missing_interactive_runs=int(selected.missing_interactive_runs),
                valid_pcap_count=int(selected.valid_pcap_count),
                baseline_class_note=_baseline_class_note(selected),
                draft_role="optional_restore",
                collectability="needs_prior_build_restore",
                action="restore if easy",
                blocker=False,
                reason="Selected prior build is close, but more capture requires restore.",
                bucket="RUN_ONLY_IF_EASY",
            )
        return PaperFreezeDecisionRow(
            package_name=recommendation.package_name,
            selected_version_code=_norm_text(selected.version_code),
            selected_version_name=_norm_text(selected.version_name),
            installed_version_code=installed_vc,
            relation=selected_relation,
            strict_idle_count=_strict_no_touch_count(selected),
            quiescent_fg_count=int(selected.quiescent_fg_runs),
            baseline_count=int(selected.baseline_valid_runs),
            interactive_count=int(selected.interactive_valid_runs),
            missing_baseline_runs=int(selected.missing_baseline_runs),
            missing_interactive_runs=int(selected.missing_interactive_runs),
            valid_pcap_count=int(selected.valid_pcap_count),
            baseline_class_note=_baseline_class_note(selected),
            draft_role="deferred",
            collectability="defer_refresh",
            action="defer",
            blocker=False,
            reason="Too much missing evidence for weekend draft; defer to refresh wave.",
            bucket="DEFER_REFRESH_WAVE",
        )

    if selected is None:
        return PaperFreezeDecisionRow(
            package_name=recommendation.package_name,
            selected_version_code="",
            selected_version_name="",
            installed_version_code=installed_vc,
            relation="none",
            strict_idle_count=0,
            quiescent_fg_count=0,
            baseline_count=0,
            interactive_count=0,
            missing_baseline_runs=0,
            missing_interactive_runs=0,
            valid_pcap_count=0,
            baseline_class_note="No selected paper target.",
            draft_role="deferred",
            collectability="not_selected",
            action="defer",
            blocker=False,
            reason="No selected paper target and full capture burden remains.",
            bucket="DEFER_REFRESH_WAVE",
        )

    return PaperFreezeDecisionRow(
        package_name=recommendation.package_name,
        selected_version_code=_norm_text(selected.version_code),
        selected_version_name=_norm_text(selected.version_name),
        installed_version_code=installed_vc,
        relation=selected_relation or "none",
        strict_idle_count=_strict_no_touch_count(selected),
        quiescent_fg_count=int(selected.quiescent_fg_runs),
        baseline_count=int(selected.baseline_valid_runs),
        interactive_count=int(selected.interactive_valid_runs),
        missing_baseline_runs=int(selected.missing_baseline_runs),
        missing_interactive_runs=int(selected.missing_interactive_runs),
        valid_pcap_count=int(selected.valid_pcap_count),
        baseline_class_note=_baseline_class_note(selected),
        draft_role="deferred",
        collectability="unknown_collectability",
        action="inspect workbench",
        blocker=False,
        reason="Collectability unclear; inspect app workbench before running.",
        bucket="DEFER_REFRESH_WAVE",
    )


def summarize_build_candidates(
    package_name: str,
    runs: list[dict[str, Any]],
    *,
    cfg: DatasetTrackerConfig | None = None,
    active_identity: tuple[str | None, str | None] | None = None,
) -> tuple[PaperFreezeBuildCandidate, ...]:
    tracker_cfg = cfg or DatasetTrackerConfig()
    active_version_code, active_base_sha = active_identity or resolve_active_package_identity(package_name)

    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict) or run.get("valid_dataset_run") is not True:
            continue
        run_id = _norm_text(run.get("run_id"))
        if not run_id:
            continue
        key = _run_identity_key(package_name, run)
        row = grouped.setdefault(
            key,
            {
                "package_name": key[0],
                "version_code": key[1],
                "version_name": key[2],
                "base_apk_sha256": key[3],
                "static_run_ids": set(),
                "run_ids": set(),
                "strict_idle_runs": 0,
                "quiescent_fg_runs": 0,
                "baseline_valid_runs": 0,
                "interactive_valid_runs": 0,
                "valid_pcap_count": 0,
                "qa_valid_count": 0,
                "first_capture_at": "",
                "last_capture_at": "",
            },
        )
        if run_id in row["run_ids"]:
            continue
        row["run_ids"].add(run_id)
        static_run_id = _norm_text(run.get("static_run_id"))
        if static_run_id:
            row["static_run_ids"].add(static_run_id)
        mode = _run_mode(run)
        if mode == "baseline":
            if _is_quiescent_fg_run(run):
                row["quiescent_fg_runs"] += 1
            else:
                row["strict_idle_runs"] += 1
            row["baseline_valid_runs"] += 1
        elif mode == "interactive":
            row["interactive_valid_runs"] += 1
        if bool(run.get("pcap_available")) or _safe_int(run.get("pcap_size_bytes")) > 0:
            row["valid_pcap_count"] += 1
        row["qa_valid_count"] += 1
        ts = _norm_text(run.get("ended_at") or run.get("started_at"))
        if ts and (not row["first_capture_at"] or ts < row["first_capture_at"]):
            row["first_capture_at"] = ts
        if ts and (not row["last_capture_at"] or ts > row["last_capture_at"]):
            row["last_capture_at"] = ts

    out: list[PaperFreezeBuildCandidate] = []
    for row in grouped.values():
        static_run_ids = tuple(sorted(str(value) for value in row["static_run_ids"] if _norm_text(value)))
        status, missing_baseline, missing_interactive = _build_status(
            baseline_valid_runs=int(row["baseline_valid_runs"]),
            interactive_valid_runs=int(row["interactive_valid_runs"]),
            cfg=tracker_cfg,
        )
        out.append(
            PaperFreezeBuildCandidate(
                package_name=_norm_text(row["package_name"]).lower(),
                version_code=_norm_text(row["version_code"]),
                version_name=_norm_text(row["version_name"]),
                static_run_id=static_run_ids[0] if static_run_ids else "",
                static_run_ids=static_run_ids,
                run_ids=tuple(sorted(str(value) for value in row["run_ids"] if _norm_text(value))),
                base_apk_sha256=_norm_text(row["base_apk_sha256"]).lower(),
                strict_idle_runs=int(row["strict_idle_runs"]),
                quiescent_fg_runs=int(row["quiescent_fg_runs"]),
                baseline_valid_runs=int(row["baseline_valid_runs"]),
                interactive_valid_runs=int(row["interactive_valid_runs"]),
                valid_pcap_count=int(row["valid_pcap_count"]),
                qa_valid_count=int(row["qa_valid_count"]),
                first_capture_at=_norm_text(row["first_capture_at"]),
                last_capture_at=_norm_text(row["last_capture_at"]),
                relation_to_active_target=_relation_to_active_target(
                    version_code=_norm_text(row["version_code"]),
                    base_apk_sha256=_norm_text(row["base_apk_sha256"]).lower(),
                    active_version_code=_norm_text(active_version_code),
                    active_base_sha=_norm_text(active_base_sha).lower(),
                ),
                missing_baseline_runs=missing_baseline,
                missing_interactive_runs=missing_interactive,
                status=status,
            )
        )

    def _sort_key(item: PaperFreezeBuildCandidate) -> tuple[int, int, int, int, int, int, str, int]:
        ready = 1 if item.status == "ready" else 0
        has_both = 1 if item.baseline_valid_runs > 0 and item.interactive_valid_runs > 0 else 0
        coverage = min(int(item.baseline_valid_runs), int(tracker_cfg.baseline_required)) + min(
            int(item.interactive_valid_runs), int(tracker_cfg.interactive_required)
        )
        total_valid = int(item.baseline_valid_runs) + int(item.interactive_valid_runs)
        current_match = 1 if item.relation_to_active_target == "current" else 0
        version_code_num = _safe_int(item.version_code, default=-1)
        return (
            ready,
            has_both,
            coverage,
            total_valid,
            int(item.valid_pcap_count),
            int(item.qa_valid_count),
            _norm_text(item.last_capture_at),
            current_match,
            version_code_num,
        )

    return tuple(sorted(out, key=_sort_key, reverse=True))


def recommend_paper_freeze_for_runs(
    package_name: str,
    runs: list[dict[str, Any]],
    *,
    cfg: DatasetTrackerConfig | None = None,
    active_identity: tuple[str | None, str | None] | None = None,
) -> PaperFreezeRecommendation:
    tracker_cfg = cfg or DatasetTrackerConfig()
    active_version_code, active_base_sha = active_identity or resolve_active_package_identity(package_name)
    candidates = summarize_build_candidates(
        package_name,
        runs,
        cfg=tracker_cfg,
        active_identity=(active_version_code, active_base_sha),
    )
    selected = candidates[0] if candidates else None
    selected_is_current = bool(selected and selected.relation_to_active_target == "current")
    return PaperFreezeRecommendation(
        package_name=_norm_text(package_name).lower(),
        installed_target_version_code=_norm_text(active_version_code),
        installed_target_version_name="",
        installed_target_static_run_id="",
        installed_target_base_apk_sha256=_norm_text(active_base_sha).lower(),
        selected_build=selected,
        build_candidates=candidates,
        refresh_candidate=bool(selected and not selected_is_current and (_norm_text(active_version_code) or _norm_text(active_base_sha))),
        retained_prior_build_selected=bool(selected and selected.relation_to_active_target == "prior-build"),
    )


def build_paper_freeze_manifest(
    *,
    package_filter: list[str] | tuple[str, ...] | None = None,
    cfg: DatasetTrackerConfig | None = None,
) -> dict[str, Any]:
    tracker_cfg = cfg or DatasetTrackerConfig()
    tracker_status, payload, _raw_payload = _load_tracker_payload(tracker_cfg)
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    app_rows = apps if isinstance(apps, dict) else {}
    wanted = [
        _norm_text(package).lower()
        for package in (
            package_filter
            or active_research_cohort_packages()
            or tuple(sorted(_norm_text(pkg).lower() for pkg in app_rows.keys() if _norm_text(pkg)))
        )
        if _norm_text(package)
    ]

    rows: list[dict[str, Any]] = []
    plan_rows: list[dict[str, Any]] = []
    ready = needs_baseline = needs_interactive = insufficient = refresh_candidates = 0
    ready_current = ready_prior = 0
    for package_name in wanted:
        entry = app_rows.get(package_name) if isinstance(app_rows, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) and isinstance(entry.get("runs"), list) else []
        recommendation = recommend_paper_freeze_for_runs(package_name, runs, cfg=tracker_cfg)
        selected = recommendation.selected_build
        status = selected.status if selected else "insufficient"
        if status == "ready":
            ready += 1
            if selected and selected.relation_to_active_target == "current":
                ready_current += 1
            elif selected and selected.relation_to_active_target == "prior-build":
                ready_prior += 1
        elif status == "needs baseline":
            needs_baseline += 1
        elif status == "needs interactive":
            needs_interactive += 1
        else:
            insufficient += 1
        if recommendation.refresh_candidate:
            refresh_candidates += 1

        selected_relation = selected.relation_to_active_target if selected else "none"
        row = {
            "app": package_name,
            "package_name": package_name,
            "selected_paper_build": _norm_text(selected.version_name if selected else ""),
            "selected_version_code": _norm_text(selected.version_code if selected else ""),
            "selected_version_name": _norm_text(selected.version_name if selected else ""),
            "selected_static_run_id": _norm_text(selected.static_run_id if selected else ""),
            "selected_static_run_ids": ",".join(selected.static_run_ids) if selected else "",
            "selected_dynamic_run_ids": ",".join(selected.run_ids) if selected else "",
            "selected_base_apk_sha256": _norm_text(selected.base_apk_sha256 if selected else ""),
            "strict_idle_count": _strict_no_touch_count(selected),
            "quiescent_fg_count": int(selected.quiescent_fg_runs) if selected else 0,
            "baseline_count": int(selected.baseline_valid_runs) if selected else 0,
            "interactive_count": int(selected.interactive_valid_runs) if selected else 0,
            "valid_pcap_count": int(selected.valid_pcap_count) if selected else 0,
            "qa_valid_count": int(selected.qa_valid_count) if selected else 0,
            "selected_relation": selected_relation,
            "missing_baseline_runs": int(selected.missing_baseline_runs) if selected else int(tracker_cfg.baseline_required),
            "missing_interactive_runs": int(selected.missing_interactive_runs) if selected else int(tracker_cfg.interactive_required),
            "status": status,
            "installed_target_version_code": recommendation.installed_target_version_code,
            "installed_target_base_apk_sha256": recommendation.installed_target_base_apk_sha256,
            "refresh_candidate": "yes" if recommendation.refresh_candidate else "no",
            "retained_prior_build_selected": "yes" if recommendation.retained_prior_build_selected else "no",
            "build_candidates_seen": len(recommendation.build_candidates),
            "strict_idle_ready": "yes" if selected and int(selected.missing_baseline_runs) == 0 else "no",
            "quiescent_fg_available": "yes" if selected and int(selected.quiescent_fg_runs) > 0 else "no",
            "strict_workflow_blocked": (
                "yes"
                if selected
                and int(selected.missing_baseline_runs) > 0
                and int(selected.interactive_valid_runs) > 0
                else "no"
            ),
            "baseline_class_note": _baseline_class_note(selected),
        }
        rows.append(row)
        if status != "ready":
            plan_rows.append(
                {
                    "app": package_name,
                    "package_name": package_name,
                    "paper_target_version_code": row["selected_version_code"],
                    "paper_target_relation": selected_relation,
                    "paper_target_static_run_ids": row["selected_static_run_ids"],
                    "status": status,
                    "missing_baseline_runs": row["missing_baseline_runs"],
                    "missing_interactive_runs": row["missing_interactive_runs"],
                    "installed_target_version_code": recommendation.installed_target_version_code,
                    "refresh_candidate": row["refresh_candidate"],
                    "strict_idle_count": row["strict_idle_count"],
                    "quiescent_fg_count": row["quiescent_fg_count"],
                    "strict_idle_ready": row["strict_idle_ready"],
                    "baseline_class_note": row["baseline_class_note"],
                    "recommended_next_action": _recommended_plan_action(
                        status=status,
                        selected=selected,
                    ),
                }
            )

        row["build_candidates"] = [
            {
                "version_code": candidate.version_code,
                "version_name": candidate.version_name,
                "static_run_id": candidate.static_run_id,
                "static_run_ids": list(candidate.static_run_ids),
                "base_apk_sha256": candidate.base_apk_sha256,
                "strict_idle_runs": candidate.strict_idle_runs,
                "quiescent_fg_runs": candidate.quiescent_fg_runs,
                "baseline_valid_runs": candidate.baseline_valid_runs,
                "interactive_valid_runs": candidate.interactive_valid_runs,
                "valid_pcap_count": candidate.valid_pcap_count,
                "qa_valid_count": candidate.qa_valid_count,
                "first_capture_at": candidate.first_capture_at,
                "last_capture_at": candidate.last_capture_at,
                "relation_to_active_target": candidate.relation_to_active_target,
                "missing_baseline_runs": candidate.missing_baseline_runs,
                "missing_interactive_runs": candidate.missing_interactive_runs,
                "status": candidate.status,
                "run_ids": list(candidate.run_ids),
            }
            for candidate in recommendation.build_candidates
        ]

    return {
        "tracker_status": tracker_status,
        "cohort_label": active_research_cohort_label(),
        "baseline_required": int(tracker_cfg.baseline_required),
        "interactive_required": int(tracker_cfg.interactive_required),
        "apps": rows,
        "paper_minimal_run_plan": plan_rows,
        "summary": {
            "apps_total": len(rows),
            "ready": ready,
            "ready_current": ready_current,
            "ready_prior": ready_prior,
            "needs_baseline": needs_baseline,
            "needs_interactive": needs_interactive,
            "insufficient": insufficient,
            "refresh_candidates": refresh_candidates,
        },
    }


def build_paper_freeze_decision_board(
    *,
    package_filter: list[str] | tuple[str, ...] | None = None,
    cfg: DatasetTrackerConfig | None = None,
) -> dict[str, Any]:
    tracker_cfg = cfg or DatasetTrackerConfig()
    manifest = build_paper_freeze_manifest(package_filter=package_filter, cfg=tracker_cfg)
    app_rows = manifest.get("apps") if isinstance(manifest.get("apps"), list) else []
    decision_rows: list[PaperFreezeDecisionRow] = []
    for row in app_rows:
        if not isinstance(row, dict):
            continue
        selected = None
        if _norm_text(row.get("selected_version_code")):
            selected = PaperFreezeBuildCandidate(
                package_name=_norm_text(row.get("package_name")).lower(),
                version_code=_norm_text(row.get("selected_version_code")),
                version_name=_norm_text(row.get("selected_version_name")),
                static_run_id=_norm_text(row.get("selected_static_run_id")),
                static_run_ids=tuple(
                    value.strip()
                    for value in str(row.get("selected_static_run_ids") or "").split(",")
                    if value.strip()
                ),
                base_apk_sha256=_norm_text(row.get("selected_base_apk_sha256")).lower(),
                strict_idle_runs=_safe_int(row.get("strict_idle_count")),
                quiescent_fg_runs=_safe_int(row.get("quiescent_fg_count")),
                baseline_valid_runs=_safe_int(row.get("baseline_count")),
                interactive_valid_runs=_safe_int(row.get("interactive_count")),
                valid_pcap_count=_safe_int(row.get("valid_pcap_count")),
                qa_valid_count=_safe_int(row.get("qa_valid_count")),
                first_capture_at="",
                last_capture_at="",
                relation_to_active_target=_norm_text(row.get("selected_relation")),
                missing_baseline_runs=_safe_int(row.get("missing_baseline_runs")),
                missing_interactive_runs=_safe_int(row.get("missing_interactive_runs")),
                status=_norm_text(row.get("status")),
                run_ids=tuple(
                    value.strip()
                    for value in str(row.get("selected_dynamic_run_ids") or "").split(",")
                    if value.strip()
                ),
            )
        build_candidates = tuple(
            PaperFreezeBuildCandidate(
                package_name=_norm_text(row.get("package_name")).lower(),
                version_code=_norm_text(candidate.get("version_code")),
                version_name=_norm_text(candidate.get("version_name")),
                static_run_id=_norm_text(candidate.get("static_run_id")),
                static_run_ids=tuple(
                    _norm_text(value)
                    for value in (candidate.get("static_run_ids") or [])
                    if _norm_text(value)
                ),
                base_apk_sha256=_norm_text(candidate.get("base_apk_sha256")).lower(),
                strict_idle_runs=_safe_int(candidate.get("strict_idle_runs")),
                quiescent_fg_runs=_safe_int(candidate.get("quiescent_fg_runs")),
                baseline_valid_runs=_safe_int(candidate.get("baseline_valid_runs")),
                interactive_valid_runs=_safe_int(candidate.get("interactive_valid_runs")),
                valid_pcap_count=_safe_int(candidate.get("valid_pcap_count")),
                qa_valid_count=_safe_int(candidate.get("qa_valid_count")),
                first_capture_at=_norm_text(candidate.get("first_capture_at")),
                last_capture_at=_norm_text(candidate.get("last_capture_at")),
                relation_to_active_target=_norm_text(candidate.get("relation_to_active_target")),
                missing_baseline_runs=_safe_int(candidate.get("missing_baseline_runs")),
                missing_interactive_runs=_safe_int(candidate.get("missing_interactive_runs")),
                status=_norm_text(candidate.get("status")),
                run_ids=tuple(
                    _norm_text(value)
                    for value in (candidate.get("run_ids") or [])
                    if _norm_text(value)
                ),
            )
            for candidate in (row.get("build_candidates") or [])
            if isinstance(candidate, dict)
        )
        decision_rows.append(
            _classify_decision_row(
                PaperFreezeRecommendation(
                    package_name=_norm_text(row.get("package_name")).lower(),
                    installed_target_version_code=_norm_text(row.get("installed_target_version_code")),
                    installed_target_version_name="",
                    installed_target_static_run_id="",
                    installed_target_base_apk_sha256=_norm_text(row.get("installed_target_base_apk_sha256")).lower(),
                    selected_build=selected,
                    build_candidates=build_candidates,
                    refresh_candidate=str(row.get("refresh_candidate") or "").strip().lower() == "yes",
                    retained_prior_build_selected=str(row.get("retained_prior_build_selected") or "").strip().lower() == "yes",
                )
            )
        )

    sections: dict[str, list[dict[str, Any]]] = {name: [] for name in _DECISION_BUCKET_ORDER}
    for row in decision_rows:
        sections[row.bucket].append(
            {
                "package_name": row.package_name,
                "selected_version_code": row.selected_version_code,
                "selected_version_name": row.selected_version_name,
                "installed_version_code": row.installed_version_code,
                "relation": row.relation,
                "strict_idle_count": row.strict_idle_count,
                "quiescent_fg_count": row.quiescent_fg_count,
                "baseline_count": row.baseline_count,
                "interactive_count": row.interactive_count,
                "missing_baseline_runs": row.missing_baseline_runs,
                "missing_interactive_runs": row.missing_interactive_runs,
                "valid_pcap_count": row.valid_pcap_count,
                "baseline_class_note": row.baseline_class_note,
                "draft_role": row.draft_role,
                "collectability": row.collectability,
                "action": row.action,
                "rough_draft_blocker": "yes" if row.blocker else "no",
                "reason": row.reason,
                "bucket": row.bucket,
            }
        )

    return {
        "cohort_label": manifest.get("cohort_label"),
        "draft_decision_mode": "heuristic default; no explicit draft target set configured.",
        "top_note": (
            "Paper-freeze readiness is draft-oriented. It selects the strongest build-backed "
            "evidence set for the paper, which may be a retained prior build. Use Current-build "
            "collection queue for installed-build refresh work. No-touch foreground baselines "
            "are the quota baseline; Quiescent FG remains visible as an app-activity tag."
        ),
        "sections": sections,
        "rows": [
            row
            for bucket in _DECISION_BUCKET_ORDER
            for row in sections[bucket]
        ],
        "summary": dict(manifest.get("summary") or {}),
    }


def _prior_build_candidate_count(candidates: tuple[PaperFreezeBuildCandidate, ...]) -> int:
    return sum(1 for candidate in candidates if candidate.relation_to_active_target == "prior-build")


def _paper_tier_for_candidate(
    *,
    selected: PaperFreezeBuildCandidate | None,
    tracker_cfg: DatasetTrackerConfig,
) -> tuple[str, str, str, str, str]:
    if selected is None or int(selected.valid_pcap_count) <= 0:
        return (
            "TRUE_EVIDENCE_HOLE",
            "no",
            "none",
            "No useful valid dynamic evidence was available by the cutoff.",
            "Seed at least baseline evidence in a future refresh wave.",
        )

    strict_no_touch = _strict_no_touch_count(selected)
    relation = _norm_text(selected.relation_to_active_target) or "retained"
    baseline_ready = int(selected.baseline_valid_runs) >= int(tracker_cfg.baseline_required)
    strict_ready = strict_no_touch >= int(tracker_cfg.baseline_required)
    interactive_ready = int(selected.interactive_valid_runs) >= int(tracker_cfg.interactive_required)
    static_linked = bool(selected.static_run_ids)

    if relation == "current" and strict_ready and interactive_ready and static_linked:
        return (
            "STRICT_CURRENT_BUILD_COMPLETE",
            "yes",
            "current-build",
            "Strict no-touch baseline and interactive evidence are complete on the current installed build.",
            "Freeze this evidence bundle; do not chase app updates for the rough draft.",
        )
    if relation == "current" and baseline_ready and static_linked:
        return (
            "CURRENT_BUILD_MIXED_BASELINE",
            "yes",
            "current-build",
            (
                "Current-build baseline evidence is usable; strict idle and QFG/no-touch foreground "
                "evidence must be reported separately and interactive coverage may be incomplete."
            ),
            "Run interactive only if tonight's time permits; otherwise use as current-build baseline evidence.",
        )
    if relation == "prior-build" and static_linked and int(selected.valid_pcap_count) > 0 and (
        baseline_ready or int(selected.interactive_valid_runs) > 0
    ):
        return (
            "PRIOR_BUILD_PAPER_EVIDENCE",
            "yes",
            "prior-build",
            "Valid retained prior-build evidence is build-backed, static-linked, and PCAP-backed; label it as prior-build evidence.",
            "Do not refresh for the rough draft unless the app is already open and easy to capture tonight.",
        )
    return (
        "SUPPLEMENTAL_LEGACY_CONTEXT",
        "context-only",
        "mixed-or-legacy",
        "Evidence exists but is incomplete for primary claims; use only as supporting context.",
        "Treat refresh/current-build completion as future work.",
    )


def _final_run_recommendation_for_tier(
    *,
    package_name: str,
    tier: str,
    selected: PaperFreezeBuildCandidate | None,
    tracker_cfg: DatasetTrackerConfig,
) -> str:
    if tier == "TRUE_EVIDENCE_HOLE":
        return "seed baseline only if time remains after current apps; otherwise list as evidence hole"
    if selected is None:
        return "none"
    strict_no_touch = _strict_no_touch_count(selected)
    if package_name == "com.snapchat.android" and selected.relation_to_active_target == "current":
        if strict_no_touch < int(tracker_cfg.baseline_required):
            return "one strict idle retry is worthwhile tonight"
        return "skip strict idle; baseline is cutoff-usable, interactive is optional"
    if package_name == "com.reddit.frontpage" and selected.relation_to_active_target == "current":
        return "do not chase strict idle; current mixed baseline is sufficient for rough draft"
    if package_name == "com.pinterest" and selected.relation_to_active_target == "current":
        return "finish current baseline run if already in progress; interactive is optional for rough draft"
    if tier == "CURRENT_BUILD_MIXED_BASELINE" and int(selected.interactive_valid_runs) <= 0:
        return "interactive run only if easy after Snapchat/Telegram priorities"
    if tier == "PRIOR_BUILD_PAPER_EVIDENCE":
        return "no tonight run required for rough draft; label prior-build provenance"
    if tier == "STRICT_CURRENT_BUILD_COMPLETE":
        return "none; freeze evidence"
    return "none"


def build_paper_evidence_tier_report(
    *,
    package_filter: list[str] | tuple[str, ...] | None = None,
    cfg: DatasetTrackerConfig | None = None,
    live_drift_map: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    tracker_cfg = cfg or DatasetTrackerConfig()
    tracker_status, payload, _raw_payload = _load_tracker_payload(tracker_cfg)
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    app_rows = apps if isinstance(apps, dict) else {}
    wanted = [
        _norm_text(package).lower()
        for package in (
            package_filter
            or active_research_cohort_packages()
            or tuple(sorted(_norm_text(pkg).lower() for pkg in app_rows.keys() if _norm_text(pkg)))
        )
        if _norm_text(package)
    ]

    rows: list[dict[str, Any]] = []
    live_drift_checked = live_drift_map is not None
    operational_drift = {
        _norm_text(package).lower(): value
        for package, value in (live_drift_map or {}).items()
        if _norm_text(package)
    }
    for package_name in wanted:
        entry = app_rows.get(package_name) if isinstance(app_rows, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) and isinstance(entry.get("runs"), list) else []
        recommendation = recommend_paper_freeze_for_runs(package_name, runs, cfg=tracker_cfg)
        selected = recommendation.selected_build
        tier, usable, scope, caveat, future_work = _paper_tier_for_candidate(
            selected=selected,
            tracker_cfg=tracker_cfg,
        )
        strict_no_touch = _strict_no_touch_count(selected)
        selected_version_code = _norm_text(selected.version_code if selected else "")
        drift_info = operational_drift.get(package_name) or {}
        if live_drift_checked:
            operational_installed_version_code = _norm_text(
                drift_info.get("observed_version_code") if isinstance(drift_info, Mapping) else ""
            ) or recommendation.installed_target_version_code
            operational_live_drifted = (
                "yes"
                if selected_version_code
                and operational_installed_version_code
                and selected_version_code != operational_installed_version_code
                else "no"
            )
        else:
            operational_installed_version_code = ""
            operational_live_drifted = "not_checked"
        operational_drift_detail = ""
        if operational_live_drifted == "yes":
            operational_drift_detail = (
                f"live installed build {operational_installed_version_code} differs from selected paper build "
                f"{selected_version_code}; retain selected build as paper evidence and treat refresh as future work"
            )
        elif operational_live_drifted == "not_checked":
            operational_drift_detail = "live installed-build drift was not checked for this report"
        row = PaperEvidenceTierRow(
            package_name=package_name,
            evidence_tier=tier,
            paper_usable=usable,
            selected_relation=_norm_text(selected.relation_to_active_target if selected else "none") or "none",
            selected_version_code=selected_version_code,
            selected_version_name=_norm_text(selected.version_name if selected else ""),
            installed_version_code=recommendation.installed_target_version_code,
            current_installed_drifted=(
                "yes"
                if selected
                and selected.relation_to_active_target == "prior-build"
                and _norm_text(recommendation.installed_target_version_code)
                else "no"
            ),
            operational_installed_version_code=operational_installed_version_code,
            operational_live_drifted=operational_live_drifted,
            operational_drift_detail=operational_drift_detail,
            selected_static_run_ids=",".join(selected.static_run_ids) if selected else "",
            selected_dynamic_run_ids=",".join(selected.run_ids) if selected else "",
            pcap_available_count=int(selected.valid_pcap_count) if selected else 0,
            strict_idle_count=strict_no_touch,
            quiescent_fg_count=int(selected.quiescent_fg_runs) if selected else 0,
            baseline_count=int(selected.baseline_valid_runs) if selected else 0,
            interactive_count=int(selected.interactive_valid_runs) if selected else 0,
            retained_prior_build_count=_prior_build_candidate_count(recommendation.build_candidates),
            build_candidates_seen=len(recommendation.build_candidates),
            evidence_scope=scope,
            caveat=caveat,
            recommended_final_run_tonight=_final_run_recommendation_for_tier(
                package_name=package_name,
                tier=tier,
                selected=selected,
                tracker_cfg=tracker_cfg,
            ),
            future_work=future_work,
        )
        rows.append(
            {
                "package_name": row.package_name,
                "evidence_tier": row.evidence_tier,
                "paper_usable": row.paper_usable,
                "selected_relation": row.selected_relation,
                "selected_version_code": row.selected_version_code,
                "selected_version_name": row.selected_version_name,
                "installed_version_code": row.installed_version_code,
                "current_installed_drifted": row.current_installed_drifted,
                "operational_installed_version_code": row.operational_installed_version_code,
                "operational_live_drifted": row.operational_live_drifted,
                "operational_drift_detail": row.operational_drift_detail,
                "selected_static_run_ids": row.selected_static_run_ids,
                "selected_dynamic_run_ids": row.selected_dynamic_run_ids,
                "pcap_available_count": row.pcap_available_count,
                "strict_idle_count": row.strict_idle_count,
                "quiescent_fg_count": row.quiescent_fg_count,
                "baseline_count": row.baseline_count,
                "interactive_count": row.interactive_count,
                "retained_prior_build_count": row.retained_prior_build_count,
                "build_candidates_seen": row.build_candidates_seen,
                "evidence_scope": row.evidence_scope,
                "caveat": row.caveat,
                "recommended_final_run_tonight": row.recommended_final_run_tonight,
                "future_work": row.future_work,
            }
        )

    rows.sort(
        key=lambda row: (
            _PAPER_EVIDENCE_TIER_ORDER.get(str(row["evidence_tier"]), 99),
            str(row["package_name"]),
        )
    )
    tier_counts: dict[str, int] = {}
    for row in rows:
        tier = str(row["evidence_tier"])
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    usable_count = sum(1 for row in rows if row["paper_usable"] == "yes")
    drifted_usable_count = sum(
        1
        for row in rows
        if row["paper_usable"] == "yes" and row.get("operational_live_drifted") == "yes"
    )
    prior_build_usable_count = sum(
        1
        for row in rows
        if row["paper_usable"] == "yes" and row.get("current_installed_drifted") == "yes"
    )
    context_count = sum(1 for row in rows if row["paper_usable"] == "context-only")
    hole_count = sum(1 for row in rows if row["evidence_tier"] == "TRUE_EVIDENCE_HOLE")
    return {
        "tracker_status": tracker_status,
        "cohort_label": active_research_cohort_label(),
        "cutoff_policy": "collection_cutoff_build_backed_evidence_bundles",
        "methodology_current_build_churn": (
            "Dynamic collection was closed at a fixed cutoff because consumer applications update frequently "
            "during study execution. Evidence was assembled as app-level build-backed bundles rather than "
            "an endless current-build chase."
        ),
        "methodology_baseline_classes": (
            "Strict idle baselines, quiescent foreground baselines, and interactive captures are reported "
            "as separate evidence classes and are not silently merged."
        ),
        "rows": rows,
        "summary": {
            "apps_total": len(rows),
            "paper_usable": usable_count,
            "drifted_but_paper_usable": drifted_usable_count,
            "prior_build_paper_usable": prior_build_usable_count,
            "live_drift_checked": live_drift_checked,
            "context_only": context_count,
            "true_evidence_holes": hole_count,
            "tier_counts": tier_counts,
        },
    }


__all__ = [
    "PaperFreezeBuildCandidate",
    "PaperFreezeDecisionRow",
    "PaperEvidenceTierRow",
    "PaperFreezeRecommendation",
    "build_paper_evidence_tier_report",
    "build_paper_freeze_decision_board",
    "build_paper_freeze_manifest",
    "recommend_paper_freeze_for_runs",
    "summarize_build_candidates",
]
