"""Evidence qualification helpers for dynamic runs.

Separates quota accounting from analysis inclusion and low-signal retention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def _truthy_flag(value: object) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, (int, float)):
        return int(value) == 1
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _falsey_flag(value: object) -> bool:
    if value is False:
        return True
    if value is True or value is None:
        return False
    if isinstance(value, (int, float)):
        return int(value) == 0
    if isinstance(value, str):
        return value.strip().lower() in {"0", "false", "no", "n"}
    return False


@dataclass(frozen=True)
class BucketQualification:
    quota_counted_valid: int
    extra_valid: int
    low_signal_retained: int
    non_idle_retained: int
    required: int

    @property
    def total_valid_retained(self) -> int:
        return (
            int(self.quota_counted_valid)
            + int(self.extra_valid)
            + int(self.low_signal_retained)
            + int(self.non_idle_retained)
        )

    @property
    def analysis_included_valid(self) -> int:
        """Valid retained runs included in default analysis aggregation."""
        return self.total_valid_retained

    @property
    def quota_satisfied(self) -> bool:
        return int(self.quota_counted_valid) >= int(self.required)


def baseline_ml_training_pool_count(*, extra_valid: int = 0, low_signal_retained: int = 0) -> int:
    """Valid supplemental baseline runs retained for ML training (not quota-counted)."""
    return max(0, int(extra_valid)) + max(0, int(low_signal_retained))


def row_baseline_ml_pool_size(row: Any) -> int:
    return baseline_ml_training_pool_count(
        extra_valid=int(getattr(row, "baseline_extra", 0) or 0),
        low_signal_retained=int(getattr(row, "baseline_low_signal_supplemental", 0) or 0),
    )


def cohort_baseline_ml_pool_total(row_models: list[Any]) -> int:
    return sum(row_baseline_ml_pool_size(row) for row in row_models)


def supplemental_baseline_queue_action(action: str | None) -> bool:
    return str(action or "").strip().lower() in {"baseline", "supplemental baseline"}


def format_baseline_ml_training_pool_phrase(
    *,
    extra_valid: int = 0,
    low_signal_retained: int = 0,
    compact: bool = False,
) -> str | None:
    total = baseline_ml_training_pool_count(extra_valid=extra_valid, low_signal_retained=low_signal_retained)
    if total <= 0:
        return None
    extra = max(0, int(extra_valid))
    low = max(0, int(low_signal_retained))
    if compact:
        return f"ML pool {total}"
    parts: list[str] = []
    if extra > 0:
        parts.append(f"{extra} supplemental")
    if low > 0:
        parts.append(f"{low} low-signal")
    detail = " + ".join(parts) if parts else str(total)
    return f"ML training pool: {total} ({detail})"


@dataclass(frozen=True)
class EvidenceQualificationSummary:
    baseline: BucketQualification
    interactive: BucketQualification

    @property
    def quota_counted_valid(self) -> int:
        return int(self.baseline.quota_counted_valid) + int(self.interactive.quota_counted_valid)

    @property
    def extra_valid(self) -> int:
        return int(self.baseline.extra_valid) + int(self.interactive.extra_valid)

    @property
    def low_signal_retained(self) -> int:
        return int(self.baseline.low_signal_retained) + int(self.interactive.low_signal_retained)

    @property
    def total_valid_retained(self) -> int:
        return int(self.baseline.total_valid_retained) + int(self.interactive.total_valid_retained)

    @property
    def analysis_included_valid(self) -> int:
        return int(self.baseline.analysis_included_valid) + int(self.interactive.analysis_included_valid)

    @property
    def quota_satisfied(self) -> bool:
        return bool(self.baseline.quota_satisfied and self.interactive.quota_satisfied)


def summarize_bucket_qualification(
    *,
    countable: int,
    extra: int,
    low_signal: int,
    non_idle: int = 0,
    required: int,
) -> BucketQualification:
    return BucketQualification(
        quota_counted_valid=max(0, int(countable)),
        extra_valid=max(0, int(extra)),
        low_signal_retained=max(0, int(low_signal)),
        non_idle_retained=max(0, int(non_idle)),
        required=max(0, int(required)),
    )


def summarize_evidence_qualification(
    scoped_counts: Mapping[str, Any],
    *,
    baseline_required: int,
    interactive_required: int,
) -> EvidenceQualificationSummary:
    return EvidenceQualificationSummary(
        baseline=summarize_bucket_qualification(
            countable=int(scoped_counts.get("baseline_countable") or 0),
            extra=int(scoped_counts.get("baseline_extra") or 0),
            low_signal=int(scoped_counts.get("baseline_low_signal_supplemental") or 0),
            non_idle=int(scoped_counts.get("baseline_not_idle_supplemental") or 0),
            required=int(baseline_required),
        ),
        interactive=summarize_bucket_qualification(
            countable=int(scoped_counts.get("interactive_countable") or 0),
            extra=int(scoped_counts.get("interactive_extra") or 0),
            low_signal=int(scoped_counts.get("interactive_low_signal_supplemental") or 0),
            required=int(interactive_required),
        ),
    )


def format_supplemental_suffix(*, extra: int = 0, low_signal: int = 0, non_idle: int = 0) -> str:
    """Display suffix for queue quota labels, e.g. `` (+1 extra, +1 low)``."""
    parts: list[str] = []
    extra_i = max(0, int(extra))
    low_i = max(0, int(low_signal))
    non_idle_i = max(0, int(non_idle))
    if extra_i > 0:
        word = "extra" if extra_i == 1 else "extras"
        parts.append(f"+{extra_i} {word}")
    if non_idle_i > 0:
        parts.append(f"+{non_idle_i} non-idle")
    if low_i > 0:
        word = "low" if low_i == 1 else "low"
        parts.append(f"+{low_i} {word}")
    if not parts:
        return ""
    return f" ({', '.join(parts)})"


def format_bucket_queue_label(
    *,
    countable: int,
    extra: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
    required: int,
    need: int = 0,
) -> str:
    """Legacy row/debug label: total retained/min, with optional need suffix."""
    evidence = bucket_evidence_label(
        countable=countable,
        extra=extra,
        low_signal=low_signal,
        non_idle=non_idle,
        required=required,
    )
    need_i = max(0, int(need))
    if need_i > 0:
        return f"{evidence} need {need_i}"
    return evidence


def format_quota_progress_label(
    *,
    countable: int,
    required: int,
    extra: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
) -> str:
    return f"{max(0, int(countable))}/{max(0, int(required))}{format_supplemental_suffix(extra=extra, low_signal=low_signal, non_idle=non_idle)}"


def format_supplemental_inline(*, extra: int = 0, low_signal: int = 0, non_idle: int = 0) -> str:
    """Compact supplemental tag for narrow queue columns, e.g. ``+1`` or ``+2L``."""
    parts: list[str] = []
    extra_i = max(0, int(extra))
    low_i = max(0, int(low_signal))
    non_idle_i = max(0, int(non_idle))
    if extra_i > 0:
        parts.append(f"+{extra_i}")
    if non_idle_i > 0:
        parts.append(f"+{non_idle_i}N")
    if low_i > 0:
        parts.append(f"+{low_i}L")
    return "".join(parts)


def format_quota_progress_compact(
    *,
    countable: int,
    required: int,
    extra: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
) -> str:
    return f"{max(0, int(countable))}/{max(0, int(required))}{format_supplemental_inline(extra=extra, low_signal=low_signal, non_idle=non_idle)}"


def classify_run_qualification_role(
    *,
    valid_dataset_run: object,
    countable: object = None,
    extra_run: object = None,
    low_signal: object = None,
    baseline_not_idle: object = None,
) -> str:
    if _falsey_flag(valid_dataset_run):
        return "invalid"
    if not _truthy_flag(valid_dataset_run):
        return "unknown"
    if _truthy_flag(countable):
        return "quota_counted"
    if _truthy_flag(low_signal):
        return "low_signal_retained"
    if _truthy_flag(extra_run) or _falsey_flag(countable):
        return "extra_valid"
    return "valid_retained"


def qualification_fields_from_dataset(dataset: Mapping[str, Any]) -> dict[str, Any]:
    """Shared per-run qualification/export fields derived from manifest.dataset."""
    analysis_included = run_included_in_default_analysis(
        valid_dataset_run=dataset.get("valid_dataset_run"),
        paper_eligible=dataset.get("paper_eligible"),
    )
    role = classify_run_qualification_role(
        valid_dataset_run=dataset.get("valid_dataset_run"),
        countable=dataset.get("countable"),
        extra_run=dataset.get("extra_run"),
        low_signal=dataset.get("low_signal"),
        baseline_not_idle=dataset.get("baseline_not_idle"),
    )
    return {
        "low_signal": dataset.get("low_signal"),
        "qualification_role": role,
        "analysis_included": analysis_included,
        "quota_counted_valid": _truthy_flag(dataset.get("countable")),
        "extra_valid": role == "extra_valid",
        "low_signal_retained": role == "low_signal_retained",
        "non_idle_retained": role == "non_idle_retained",
    }


def row_analysis_included(row: Mapping[str, Any]) -> bool:
    """Return whether a flat report/export row belongs in default analysis."""
    if row.get("analysis_included") is not None:
        return bool(row.get("analysis_included"))
    return run_included_in_default_analysis(
        valid_dataset_run=row.get("valid_dataset_run"),
        paper_eligible=row.get("paper_eligible"),
    )


def analysis_included_rows(rows: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...]) -> list[Mapping[str, Any]]:
    return [row for row in rows if row_analysis_included(row)]


def summarize_tracker_runs_qualification(
    runs: list[Mapping[str, Any]],
    *,
    baseline_required: int,
    interactive_required: int,
) -> EvidenceQualificationSummary:
    scoped = {
        "baseline_countable": 0,
        "baseline_extra": 0,
        "baseline_low_signal_supplemental": 0,
        "interactive_countable": 0,
        "interactive_extra": 0,
        "interactive_low_signal_supplemental": 0,
    }
    for run in runs:
        if not _truthy_flag(run.get("valid_dataset_run")):
            continue
        if _falsey_flag(run.get("paper_eligible")):
            continue
        prof = str(run.get("run_profile") or "").strip().lower()
        is_baseline = prof.startswith("baseline") or ("baseline" in prof) or ("idle" in prof)
        is_interactive = ("interaction" in prof) or ("interactive" in prof)
        role = classify_run_qualification_role(
            valid_dataset_run=True,
            countable=run.get("countable"),
            extra_run=run.get("extra_run"),
            low_signal=run.get("low_signal"),
            baseline_not_idle=run.get("baseline_not_idle"),
        )
        if role == "quota_counted":
            if is_baseline:
                scoped["baseline_countable"] += 1
            elif is_interactive:
                scoped["interactive_countable"] += 1
        elif role == "extra_valid":
            if is_baseline:
                scoped["baseline_extra"] += 1
            elif is_interactive:
                scoped["interactive_extra"] += 1
        elif role == "low_signal_retained":
            if is_baseline:
                scoped["baseline_low_signal_supplemental"] += 1
            elif is_interactive:
                scoped["interactive_low_signal_supplemental"] += 1
        elif role == "non_idle_retained":
            if is_baseline:
                scoped["baseline_not_idle_supplemental"] = int(scoped.get("baseline_not_idle_supplemental") or 0) + 1
    return summarize_evidence_qualification(
        scoped,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )


def summarize_evidence_qualification_from_counts(
    *,
    baseline_countable: int,
    baseline_extra: int,
    baseline_low_signal: int,
    baseline_non_idle: int = 0,
    interactive_countable: int,
    interactive_extra: int,
    interactive_low_signal: int,
    baseline_required: int,
    interactive_required: int,
) -> EvidenceQualificationSummary:
    return summarize_evidence_qualification(
        {
            "baseline_countable": baseline_countable,
            "baseline_extra": baseline_extra,
            "baseline_low_signal_supplemental": baseline_low_signal,
            "baseline_not_idle_supplemental": baseline_non_idle,
            "interactive_countable": interactive_countable,
            "interactive_extra": interactive_extra,
            "interactive_low_signal_supplemental": interactive_low_signal,
        },
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )


def qualification_summary_from_row(
    row: Any,
    *,
    baseline_required: int,
    interactive_required: int,
) -> EvidenceQualificationSummary:
    return summarize_evidence_qualification_from_counts(
        baseline_countable=int(getattr(row, "baseline_countable", 0) or 0),
        baseline_extra=int(getattr(row, "baseline_extra", 0) or 0),
        baseline_low_signal=int(getattr(row, "baseline_low_signal_supplemental", 0) or 0),
        baseline_non_idle=int(getattr(row, "baseline_not_idle_supplemental", 0) or 0),
        interactive_countable=int(getattr(row, "interactive_countable", 0) or 0),
        interactive_extra=int(getattr(row, "interactive_extra", 0) or 0),
        interactive_low_signal=int(getattr(row, "interactive_low_signal_supplemental", 0) or 0),
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )


def qualification_summary_from_app_counts(app: Any) -> EvidenceQualificationSummary:
    counts = app.counts
    cfg = app.cfg
    return summarize_evidence_qualification_from_counts(
        baseline_countable=int(counts.baseline_valid_runs),
        baseline_extra=int(getattr(counts, "baseline_extra_valid", 0) or 0),
        baseline_low_signal=int(getattr(counts, "baseline_low_signal_valid", 0) or 0),
        baseline_non_idle=int(getattr(counts, "baseline_not_idle_valid", 0) or 0),
        interactive_countable=int(counts.interactive_valid_runs),
        interactive_extra=int(getattr(counts, "interactive_extra_valid", 0) or 0),
        interactive_low_signal=int(getattr(counts, "interactive_low_signal_valid", 0) or 0),
        baseline_required=int(cfg.baseline_required),
        interactive_required=int(cfg.interactive_required),
    )


def sum_qualification_summaries(
    summaries: list[EvidenceQualificationSummary],
) -> EvidenceQualificationSummary:
    baseline = BucketQualification(
        quota_counted_valid=sum(item.baseline.quota_counted_valid for item in summaries),
        extra_valid=sum(item.baseline.extra_valid for item in summaries),
        low_signal_retained=sum(item.baseline.low_signal_retained for item in summaries),
        non_idle_retained=sum(item.baseline.non_idle_retained for item in summaries),
        required=0,
    )
    interactive = BucketQualification(
        quota_counted_valid=sum(item.interactive.quota_counted_valid for item in summaries),
        extra_valid=sum(item.interactive.extra_valid for item in summaries),
        low_signal_retained=sum(item.interactive.low_signal_retained for item in summaries),
        non_idle_retained=sum(item.interactive.non_idle_retained for item in summaries),
        required=0,
    )
    return EvidenceQualificationSummary(baseline=baseline, interactive=interactive)


def bucket_evidence_label(
    *,
    countable: int,
    extra: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
    required: int,
) -> str:
    """Total valid retained runs over the minimum required (queue/S summary display)."""
    total = max(0, int(countable)) + max(0, int(extra)) + max(0, int(low_signal)) + max(0, int(non_idle))
    return f"{total}/{max(0, int(required))}"


def bucket_quota_label(*, countable: int, required: int) -> str:
    """Quota-counted runs over the minimum (archive/quota math grain)."""
    return f"{max(0, int(countable))}/{max(0, int(required))}"


def bucket_detail_column_label(
    *,
    countable: int,
    extra: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
    required: int,
) -> str:
    """Queue + column: quota gap and/or supplemental retained evidence."""
    parts: list[str] = []
    quota = max(0, int(countable))
    req = max(0, int(required))
    if quota < req:
        parts.append(f"q{quota}/{req}")
    supplemental = format_supplemental_column_label(extra=extra, low_signal=low_signal, non_idle=non_idle)
    if supplemental != "—":
        parts.append(supplemental)
    return " · ".join(parts) if parts else "—"


def format_bucket_evidence_line(
    *,
    label: str,
    bucket: BucketQualification,
) -> str:
    progress = bucket_evidence_label(
        countable=bucket.quota_counted_valid,
        extra=bucket.extra_valid,
        required=bucket.required,
    )
    return f"{label:<13}{progress}"


def format_supplemental_column_label(*, extra: int = 0, low_signal: int = 0, non_idle: int = 0) -> str:
    suffix = format_supplemental_suffix(extra=extra, low_signal=low_signal, non_idle=non_idle).strip()
    if suffix.startswith("(") and suffix.endswith(")"):
        suffix = suffix[1:-1].strip()
    return suffix or "—"


def qualification_table_cells(summary: EvidenceQualificationSummary) -> tuple[str, str, str, str]:
    return (
        bucket_evidence_label(
            countable=summary.baseline.quota_counted_valid,
            extra=summary.baseline.extra_valid,
            low_signal=summary.baseline.low_signal_retained,
            required=summary.baseline.required,
        ),
        bucket_detail_column_label(
            countable=summary.baseline.quota_counted_valid,
            extra=summary.baseline.extra_valid,
            low_signal=summary.baseline.low_signal_retained,
            required=summary.baseline.required,
        ),
        bucket_evidence_label(
            countable=summary.interactive.quota_counted_valid,
            extra=summary.interactive.extra_valid,
            low_signal=summary.interactive.low_signal_retained,
            required=summary.interactive.required,
        ),
        bucket_detail_column_label(
            countable=summary.interactive.quota_counted_valid,
            extra=summary.interactive.extra_valid,
            low_signal=summary.interactive.low_signal_retained,
            required=summary.interactive.required,
        ),
    )


def format_current_build_evidence_lines(summary: EvidenceQualificationSummary) -> list[str]:
    return [
        "Current build evidence",
        "----------------------",
        format_bucket_evidence_line(label="Strict idle", bucket=summary.baseline),
        f"Quiescent FG  {summary.baseline.non_idle_retained}",
        format_bucket_evidence_line(label="Interactive", bucket=summary.interactive),
    ]


def format_qualification_summary_lines(summary: EvidenceQualificationSummary) -> list[str]:
    satisfied = "yes" if summary.quota_satisfied else "no"
    return [
        "",
        "Qualification",
        "-------------",
        f"Quota-counted valid     : {summary.quota_counted_valid}",
        f"Extra valid             : {summary.extra_valid}",
        f"Low-signal retained     : {summary.low_signal_retained}",
        f"Quiescent FG retained   : {summary.baseline.non_idle_retained}",
        f"Total valid retained    : {summary.total_valid_retained}",
        f"Analysis-included valid : {summary.analysis_included_valid}",
        f"Quota satisfied         : {satisfied}",
    ]


def format_workbench_qualification_lines(app: Any) -> list[str]:
    summary = qualification_summary_from_app_counts(app)
    lines = format_current_build_evidence_lines(summary)
    strict_idle_gate_incomplete = not summary.baseline.quota_satisfied
    interactive_raw = (
        int(summary.interactive.quota_counted_valid)
        + int(summary.interactive.extra_valid)
        + int(summary.interactive.low_signal_retained)
    )
    if strict_idle_gate_incomplete:
        lines[-1] = f"Interactive  {interactive_raw}/{summary.interactive.required} held by strict idle"
    lines += format_qualification_summary_lines(summary)
    if strict_idle_gate_incomplete:
        lines.append(
            f"Strict-idle workflow gate: incomplete ({summary.baseline.quota_counted_valid}/{summary.baseline.required})"
        )
    if summary.baseline.non_idle_retained > 0:
        lines.append(
            "Quiescent FG: valid no-touch foreground baseline evidence with app-generated activity tags; low-signal baselines remain the supplemental baseline case."
        )
    if strict_idle_gate_incomplete and interactive_raw > 0:
        lines.append(
            "Interactive evidence is already captured for the current build, but it remains held until Strict Idle is complete."
        )
    pool_line = format_baseline_ml_training_pool_phrase(
        extra_valid=summary.baseline.extra_valid,
        low_signal_retained=summary.baseline.low_signal_retained,
    )
    if pool_line:
        lines.append(pool_line)
    elif summary.baseline.quota_satisfied:
        lines.append(
            "ML training pool: none yet — supplemental baselines improve pattern averages"
        )
    return lines


def run_included_in_default_analysis(
    *,
    valid_dataset_run: object,
    paper_eligible: object = None,
) -> bool:
    """Default analysis/export inclusion: all valid retained runs, quota or supplemental."""
    if not _truthy_flag(valid_dataset_run):
        return False
    if _falsey_flag(paper_eligible):
        return False
    return True


__all__ = [
    "BucketQualification",
    "EvidenceQualificationSummary",
    "baseline_ml_training_pool_count",
    "cohort_baseline_ml_pool_total",
    "format_baseline_ml_training_pool_phrase",
    "row_baseline_ml_pool_size",
    "supplemental_baseline_queue_action",
    "bucket_detail_column_label",
    "bucket_evidence_label",
    "bucket_quota_label",
    "classify_run_qualification_role",
    "format_bucket_queue_label",
    "format_current_build_evidence_lines",
    "format_qualification_summary_lines",
    "format_quota_progress_label",
    "format_supplemental_column_label",
    "format_supplemental_suffix",
    "format_workbench_qualification_lines",
    "qualification_table_cells",
    "qualification_fields_from_dataset",
    "qualification_summary_from_app_counts",
    "qualification_summary_from_row",
    "row_analysis_included",
    "run_included_in_default_analysis",
    "sum_qualification_summaries",
    "summarize_evidence_qualification_from_counts",
    "summarize_bucket_qualification",
    "summarize_evidence_qualification",
    "summarize_tracker_runs_qualification",
]
