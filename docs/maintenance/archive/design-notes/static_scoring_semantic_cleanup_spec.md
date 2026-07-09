# Static Scoring Semantic Cleanup Spec

## Purpose

This document defines the next-step scoring contract for ScytaleDroid static
analysis. It is intentionally a semantic cleanup, not a large scoring rewrite.

The immediate goal is to stop overloading the word `risk` across different
static-analysis surfaces that currently mean different things:

- permission posture
- technical severity
- heuristic/composite prioritization
- contextual or study-specific risk

This spec keeps the current pipeline intact where possible, but makes the
conceptual boundaries explicit so code, DB surfaces, UI copy, and future paper
outputs can converge on a defensible model.

## External guidance alignment

This direction aligns with current external guidance:

- OWASP MASTG / MASVS should be the primary control taxonomy for static
  findings and test references.
- Android platform guidance should define the concrete control checks for
  exported components, permission guards, cleartext traffic, network security
  configuration, storage, backup, and cryptography.
- CVSS-style or CWSS-style logic should be treated as intrinsic or technical
  severity, not as full contextual risk.
- Contextual risk should require an explicit profile and documented weighting
  model.
- Composite outputs should be labeled `priority`, `triage`, `heuristic`, or
  `selected indicators` unless they are backed by a documented canonical model.

## Canonical model

ScytaleDroid static analysis should be modeled as five separate layers.

### 1. Control evidence

This is the canonical evidence layer and should remain the foundation.

Expected characteristics:

- one or more rows or records per concrete finding/signal
- detector/stage provenance
- affected package / APK context
- raw evidence pointers
- MASVS area / control mapping where known
- MASTG test or technique reference where known
- Android issue family
- CWE / MASWE mapping where known
- confidence and reproducibility metadata

This layer must not be reduced to a single score in storage contracts.

### 2. Technical severity

This is the intrinsic seriousness of a finding or weakness before study- or
environment-specific interpretation.

Typical inputs:

- exported component exposure
- missing permission guards
- cleartext traffic posture
- insecure network security configuration
- sensitive permission posture
- storage / backup exposure
- secrets and high-entropy indicators
- crypto misuse
- WebView posture
- dynamic loading / native hardening findings

This layer should be called `severity` or `technical severity`, not generic
`risk`.

### 3. Permission posture

Permission posture is its own model and remains useful, but it is not overall
static app risk.

Canonical names for this concept should be:

- `permission_posture_score`
- `permission_risk_score`
- `permission_risk_grade`

Any compatibility surface that still stores this under a generic
`risk_score` name must be clearly documented as permission-scoped.

### 4. App-level static exposure posture

This is a broader static summary across control families such as:

- permissions
- platform / components / providers
- network
- storage
- privacy
- crypto
- secrets
- WebView / dynamic loading / native posture
- third-party SDK or library posture

This can become a canonical summary later, but only if the aggregation model is
documented, persisted intentionally, and tested. Until then it should be
labeled experimental, heuristic, or triage-oriented.

### 5. Contextual risk profile

This is the decision layer. It depends on an explicit profile such as:

- social-media / privacy research
- messaging app
- finance app
- enterprise deployment
- OEM / system app
- general consumer app
- paper-specific research profile

Contextual risk must not be silently mixed into technical severity or permission
posture.

## Current code surface map

The current repo exposes multiple static scoring surfaces. They are not
interchangeable.

| Current surface | Current code | Actual meaning | Target classification |
| --- | --- | --- | --- |
| Permission score / grade | `scytaledroid/StaticAnalysis/risk/permission.py` | Tunable permission posture model using dangerous/signature/vendor permissions and related penalties/credits | Canonical permission posture |
| Permission persistence | `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py` | Persists the permission posture model into `risk_scores` and `static_permission_risk_vnext` | Permission posture persistence |
| Metrics bundle | `scytaledroid/StaticAnalysis/cli/persistence/metrics_writer.py` | Builds permission posture inputs plus bucket-style static summary signals | Mixed helper, not a canonical score surface by itself |
| Composite static row | `scytaledroid/StaticAnalysis/cli/execution/analytics.py` | Runtime composite built from permissions, network, storage, components, secrets, and correlation | Heuristic app-level static exposure / triage |
| HTML/report risk card | `scytaledroid/StaticAnalysis/risk/scoring.py` and `scytaledroid/StaticAnalysis/reporting/view.py` | Narrow heuristic from permissions, secrets, and cleartext | Selected static risk indicators / heuristic highlights |
| Correlation detector score | `scytaledroid/StaticAnalysis/detectors/correlation/scoring.py` | Composite prioritization signal emitted as a synthetic finding | Correlation prioritization / synthetic finding |
| Canonical findings | `static_analysis_findings` and related writers | Row-level evidence, severity, MASVS mappings, evidence JSON | Canonical control evidence |

## Current semantic problems

### 1. `risk_scores` is permission-only in practice

The current persistence path stores the output of the permission model in
`risk_scores`. That means the table name is broader than the underlying
meaning.

Immediate interpretation rule:

- `risk_scores.risk_score` currently means permission posture score
- `risk_scores.risk_grade` currently means permission posture grade

It must not be presented as overall static app risk.

### 2. `permission_risk_grade()` is reused outside permission posture

The analytics composite currently converts a broader multi-factor static score
into a `0..10` range and then uses `permission_risk_grade()` to label it. That
couples a broader static composite to thresholds designed for permission
posture.

This should be treated as semantically incorrect and cleaned up early.

### 3. Multiple “risk” surfaces are rendered without one canonical contract

At least three separate surfaces currently use `risk` language:

- permission posture persistence
- HTML/reporting heuristic highlights
- runtime composite / correlation prioritization

These should be renamed or relabeled according to their actual role.

### 4. Canonical evidence already exists, but scoring labels drift

The strongest foundation in the repo is the finding and evidence layer:

- `static_analysis_runs`
- `static_analysis_findings`
- MASVS mappings
- detector metrics
- evidence JSON

The short-term fix is therefore semantic: scoring should become honest about
what it summarizes, not more mathematically complicated.

## Proposed scoring contract by layer

### Control evidence contract

Preferred canonical fields and concepts:

- `finding_id`
- `detector_id`
- `stage_id`
- `package_name`
- `artifact identity`
- `evidence pointer`
- `masvs_area`
- `masvs_control`
- `mastg_test`
- `mastg_technique`
- `android_issue_family`
- `cwe_id`
- `maswe_id`
- `confidence`
- `reproducibility`
- `provenance`

Existing canonical tables already cover much of this through
`static_analysis_findings`, evidence JSON, and detector metadata.

### Technical severity contract

This layer should answer:

> How serious is this issue technically before applying environment-specific
> weighting?

Recommended naming:

- `technical_severity`
- `technical_severity_score`
- `technical_severity_grade`

This layer can be per-finding, per-control-family, or per-app summary, but
must remain distinct from contextual risk.

### Permission posture contract

Recommended naming:

- `permission_score`
- `permission_grade`
- `permission_posture_score`
- `permission_risk_score`
- `permission_risk_grade`

Compatibility note:

- the existing physical `risk_scores` table may remain temporarily
- readers, views, and docs should make clear that this surface is
  permission-scoped

### Static exposure posture contract

Recommended naming:

- `static_exposure_score`
- `static_exposure_grade`
- `static_exposure_summary`
- `static_app_exposure_summary`

If the current composite remains heuristic, label it explicitly as:

- `heuristic_static_exposure_score`
- `triage_priority_score`
- `selected_static_risk_indicators`

### Contextual risk contract

Recommended naming:

- `context_profile`
- `contextual_risk_score`
- `contextual_risk_grade`

This layer should not be populated unless an explicit profile is supplied.

## DB and read-model impact

The first pass should preserve compatibility while correcting semantics.

### Existing physical surfaces

Keep:

- `risk_scores`
- `static_permission_risk_vnext`
- existing compatibility views that already consume `risk_scores`

Interpretation:

- `risk_scores` remains the storage location for permission posture during the
  compatibility period

### Read-model direction

Add or evolve naming toward:

- `v_static_permission_risk`
- `v_static_permission_posture`
- `v_static_app_exposure_summary`

Suggested future field names:

- `permission_score`
- `permission_grade`
- `technical_severity_score`
- `technical_severity_grade`
- `static_exposure_score`
- `static_exposure_grade`
- `context_profile`
- `contextual_risk_score`
- `triage_priority_score`

### Immediate reader/writer policy

- do not overload one column name to represent multiple concepts
- do not silently fall back from missing app-level exposure posture to
  permission posture
- do not present heuristic or correlation outputs as canonical app risk

## Minimal compatibility-safe implementation plan

### Phase 1: semantic correctness

1. Keep `StaticAnalysis/risk/permission.py` as the permission posture model.
2. Make `StaticAnalysis/cli/persistence/permission_risk.py` and related docs
   explicitly permission-scoped.
3. Treat `risk_scores` as a compatibility surface for permission posture.
4. Stop using `permission_risk_grade()` for broader static composites.
5. Relabel HTML/report wording if the card remains narrow and heuristic.
6. Reclassify correlation scoring as prioritization or synthetic finding unless
   and until a canonical app-level model is defined.

### Phase 2: read-model cleanup

1. Introduce permission-scoped read models and aliases.
2. Audit menus, dashboards, exports, and reports that say generic `risk`.
3. Ensure static app-level summary surfaces use distinct terminology such as
   `exposure`, `triage`, or `heuristic`.

### Phase 3: optional canonical summary

Only after semantic cleanup:

1. define a documented app-level static exposure model
2. persist it intentionally
3. test it independently from permission posture
4. add contextual profiles only when there is an explicit research need

## First implementation targets in code

### `scytaledroid/StaticAnalysis/risk/permission.py`

Status:

- keep as the canonical permission posture model

Required cleanup:

- none to the formula in the first pass
- clarify naming through surrounding callers and docs

### `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py`

Status:

- canonical writer for permission posture persistence

Required cleanup:

- clarify that writes to `risk_scores` are permission-scoped
- prefer permission-specific naming in warnings, logs, readers, and docs

### `risk_scores` readers and views

Status:

- compatibility surface with semantically broad naming

Required cleanup:

- document and, where practical, alias as permission posture
- avoid presenting it as overall static app risk

### `scytaledroid/StaticAnalysis/cli/execution/analytics.py`

Status:

- heuristic app-level composite / triage surface

Required cleanup:

- stop calling `permission_risk_grade()` for this composite
- introduce a dedicated grade helper or mark the result as triage-only
- prefer `exposure`, `priority`, or `heuristic` terminology

### `scytaledroid/StaticAnalysis/risk/scoring.py`
### `scytaledroid/StaticAnalysis/reporting/view.py`

Status:

- narrow heuristic for reporting

Required cleanup:

- relabel output as `Selected static risk indicators`,
  `Heuristic risk highlights`, or `Technical severity highlights`
- do not present it as generic overall risk unless the model is widened and
  documented

### `scytaledroid/StaticAnalysis/detectors/correlation/scoring.py`

Status:

- synthetic prioritization surface

Required cleanup:

- classify as prioritization signal or synthetic finding
- do not present as canonical app-level risk by default

## Test expectations for the cleanup

The first implementation pass should add or update tests that lock in semantic
correctness:

- persisted permission score is labeled permission-scoped
- generic “risk” wording does not point to permission-only data
- missing app-level exposure posture does not silently fall back to permission
  score
- analytics composite does not call `permission_risk_grade()`
- HTML/report wording reflects heuristic or selected-indicator semantics
- correlation output is identified as synthetic or prioritization-oriented if
  it is not canonical
- exports and reports distinguish:
  - control evidence
  - technical severity
  - permission posture
  - contextual risk

## Remaining ambiguity

These points still require explicit decisions later:

- whether app-level static exposure posture becomes a canonical persisted model
- whether technical severity is per-finding only or also needs a per-app
  summary
- how MASVS, Android issue families, and CWE / MASWE mappings should be exposed
  in analyst-facing exports
- which contextual profiles, if any, become first-class study presets

## Deliverable summary

This spec establishes the first-pass contract:

- permission risk must mean permission risk
- technical severity must not be mislabeled as contextual risk
- composite prioritization must not be treated as canonical app risk
- control evidence remains the authoritative static-analysis foundation

The next implementation pass should optimize for semantic correctness and
compatibility safety, not for a new scoring formula.
