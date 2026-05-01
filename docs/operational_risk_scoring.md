# Operational Risk Scoring (Phase F2)

This document defines the **operational, heuristic** scoring and grading outputs written under `output/operational/<snapshot_id>/tables/`.

Scope and safety:
- These scores are **not** Paper #2 (Phase E) claims and must not be cited as paper outputs.
- Dynamic ML measures **deviation** from a learned baseline distribution. Deviation is **not** ground-truth harm, maliciousness, or exploitation.
- The “final” field is a **rule-based posture regime** (capability vs deviation), not a fused probabilistic risk score.

## 1) Static Axis: Exposure (Capability)

Source: `static_dynamic_plan.json` embedded in evidence packs.

Raw inputs per group/app:
- `E_raw`: exported component count (`exported_components.total`)
- `P_raw`: dangerous permission count (`len(permissions.dangerous)`)
- `C`: cleartext capability flag (`risk_flags.uses_cleartext_traffic` in {0,1})
- `S`: SDK indicator score in [0,1] if available; otherwise 0 (may be missing in the frozen cohort)

Normalisation (operational snapshots only):
- `E_norm`, `P_norm` are min–max normalised **over the selected snapshot cohort** (by group).
- Degenerate case: if only one group is selected, norms are set to 1 when the raw value is non-zero (to avoid forcing exposure to 0).

Exposure score:
```
StaticExposureScore = 100 * (0.25*E_norm + 0.25*P_norm + 0.25*C + 0.25*S)
```

Exposure grade:
- `Low`  : score < 33.4
- `Medium`: 33.4 <= score < 66.7
- `High` : score >= 66.7

## 2) Dynamic Axis: Deviation (Observed Runtime Deviation)

Per model (Isolation Forest, OC-SVM), for **interactive mode only**:
- `p`: interactive anomaly prevalence (`anomalous_pct` in [0,1])
- `L`: persistence ratio = `longest_streak_windows / total_windows` in [0,1]

Confidence modifier:
- `high` -> 1.0
- `medium` -> 0.8
- `low` -> 0.6

Deviation score (operational heuristic):
```
DynamicDeviationScore = 100 * (0.7*p + 0.3*L) * confidence_modifier
```

Deviation grade (interpretive):
- `High`   if p >= 0.20 OR longest_streak_seconds >= 60
- `Medium` if p >= 0.05 OR longest_streak_seconds >= 20
- `Low`    otherwise
- Append `"(Low confidence)"` when confidence is `low`.

## 3) Final Posture (Rule-Based Regime)

Final regime label (primary model = Isolation Forest):
- `"<ExposureGrade> Exposure + <DeviationGrade> Deviation"`

Final grade:
- `Low`    if Exposure=Low and Deviation=Low
- `High`   if Exposure=High and Deviation=High
- `Medium` otherwise

No fused scalar “final risk score” is produced here; the final is deliberately rule-based.

## 4) Outputs

Written to `output/operational/<snapshot_id>/tables/`:
- `dynamic_math_audit_per_group_model.csv`: training_mode, training_samples, threshold stability, prevalence, persistence, confidence.
- `risk_summary_per_group.csv`: exposure score/grade, deviation score/grade (IF primary + OC-SVM secondary), final regime/grade, confidence, and rationale fields.

