# Runtime ML Refactor Audit

This audit covers `scytaledroid/DynamicAnalysis/ml` as of the current working
tree. It is focused on maintainability, supportability, and safe refactor order.
It does not change runtime behavior.

## Research Basis

The refactor direction is aligned with these engineering references:

- Sculley et al., "Hidden Technical Debt in Machine Learning Systems":
  ML systems carry traditional software debt plus ML-specific risks such as
  boundary erosion, entanglement, undeclared consumers, data dependencies,
  configuration issues, and changes in the external world.
- Google "Rules of Machine Learning": prioritize a solid end-to-end pipeline,
  simple features, and durable infrastructure before adding model complexity.
- scikit-learn common pitfalls and `Pipeline`: transformations must be learned
  from training data only; pipeline-style boundaries help prevent leakage and
  make preprocessing/model steps explicit.
- Google MLOps guidance: production-grade ML requires data validation, model
  validation, process/metadata management, monitoring, and reproducibility in
  addition to ordinary code tests.

## Package Snapshot

`scytaledroid/DynamicAnalysis/ml` currently has about `10,855` Python lines.
The package is not large by itself, but line concentration is high:

| File | Lines | Main issue |
| --- | ---: | --- |
| `artifact_bundle_writer.py` | 2,089 | figures, publication tables, static context, bundle manifest assembly, and cleanup live together; format and validation helpers are now extracted |
| `evidence_pack_ml_orchestrator.py` | 1,347 | freeze/profile orchestration and scoring are still coupled, but writers/tables/identity checks have been extracted |
| `query_mode_runner.py` | 1,185 | one large operational query runner combines grouping, preprocessing, scoring, persistence, and output writing |
| `freeze_profile/dataset_tables.py` | 760 | cohesive extracted table module; monitor for future table-splitting needs |
| `query_mode_phases.py` | 594 | useful extraction target, but still contains a large group-preparation function |
| `menu.py` | 494 | CLI prompts, readiness status, and action execution are mixed |
| `snapshot_freeze.py` | 301 | one large manifest builder does selection reads, input checks, hash collection, and final status |
| `profile_v3_ml_derive.py` | 306 | profile derivation and artifact layout logic are still together |

Largest functions:

| Function | File | Approx. lines |
| --- | --- | ---: |
| `run_ml_query_mode` | `query_mode_runner.py` | 752 |
| `run_ml_on_evidence_packs` | `evidence_pack_ml_orchestrator.py` | 553 |
| `_rebuild_dataset_outputs_from_v1` | `evidence_pack_ml_orchestrator.py` | 237 |
| `prepare_group_training_inputs` | `query_mode_phases.py` | 227 |
| `build_snapshot_freeze_manifest` | `snapshot_freeze.py` | 184 |
| `_write_table_8_model_comparison_metrics` | `artifact_bundle_writer.py` | 179 |
| `_write_table_5_masvs_coverage` | `artifact_bundle_writer.py` | 175 |
| `write_phase_e_deliverables_bundle` | `artifact_bundle_writer.py` | 162 |

## Current Strengths

- The package has started to separate selectors, IO helpers, model training,
  feature matrix construction, method basis, operational lint, and snapshot
  output writing.
- Freeze/profile per-run manifest, config sidecar, skip/status, and cohort
  status writers now live in `freeze_profile/run_artifacts.py`; the legacy
  orchestrator imports these helpers through private aliases so public callers
  remain unchanged.
- Freeze/profile app/build identity eligibility checks now live in
  `freeze_profile/identity_contract.py`, with focused tests for malformed
  hashes, missing static features, app drift, and mixed artifact sets.
- Freeze/profile dataset-level reporting tables now live in
  `freeze_profile/dataset_tables.py`; prevalence, overlap, audit, DARS,
  baseline stability, static/dynamic stratification, and transport mix helpers
  are separated from scoring orchestration.
- Publication bundle exporters and validation reports now live under
  `publication_bundle/`; CSV/TEX/XLSX writing, required-field validation,
  phrase linting, checksum anchoring, and required file copying are separated
  from figure/table content generation.
- Query mode already has `query_mode_phases.py` and
  `query_mode_snapshot_outputs.py`, which are good refactor anchors.
- Freeze/profile and operational parameter modules are separate.
- Tests exist for seed/windowing, feature matrix behavior, archive path
  resolution, query snapshot outputs, operational lint, model tuning, and menu
  contracts.
- Recent method-basis metadata improves output interpretability and reduces
  undeclared-consumer risk.

## Design Debt

### 1. Orchestrator Boundary Erosion

`evidence_pack_ml_orchestrator.py` and `query_mode_runner.py` both act as:

- selector consumers;
- preflight/gate enforcement;
- feature matrix builders;
- model trainers;
- score writers;
- dataset table writers;
- status/receipt writers.

This is the largest ML technical-debt risk because a change to output layout,
identity checks, or table generation can accidentally affect model scoring.

Target shape:

```text
freeze_profile/
  runner.py              thin orchestration only
  identity_contract.py   reason codes, hash checks, app/build grouping
  run_artifacts.py       per-run model_manifest/ml_summary writers
  dataset_tables.py      prevalence, overlap, audit, DARS, transport tables
  exemplar_selection.py  deterministic exemplar lock selection

operational/
  runner.py              thin orchestration only
  group_training.py      group prep, baseline checks, fallback decisions
  scoring.py             model fit/score/threshold orchestration
  run_artifacts.py       per-run operational outputs
  snapshot_outputs.py    snapshot summary, registry, bundle manifest
```

Preserve current public imports during the move:

- `run_ml_on_evidence_packs`
- `run_ml_query_mode`
- `write_phase_e_deliverables_bundle`

### 2. Report Rendering Is Overloaded

`artifact_bundle_writer.py` mixes figure generation, table generation, file
format export, manifest writing, phrase linting, static posture calculation,
and cleanup of older output files.

Target shape:

```text
publication_bundle/
  writer.py       public write function and high-level ordering
  figures.py      Fig B1/B2/B4 generation only
  tables.py       table row construction only
  exporters.py    csv/tex/xlsx helpers
  manifest.py     bundle manifest, closure record, checksums
  static_context.py
  lint.py
```

This should be done with import-compatible wrappers first so Reporting menu
callers do not change.

### 3. Model Step Boundaries Are Still Informal

The code now has a shared `feature_matrix.py`, but the full preprocessing and
scoring sequence is not represented as a single explicit pipeline object. That
makes leakage/audit reasoning harder.

Target shape:

```text
pipeline_contract.py
  FeatureMatrix
  PreprocessingSpec
  TrainingSet
  ScoringSet
  ModelFitResult
  RunScoreResult
```

Do not jump straight to a heavy framework. First make the existing sequence
explicit in dataclasses and tests:

1. rows -> feature matrix
2. optional winsorization
3. optional robust scaling
4. fit on baseline/training windows only
5. transform/score selected windows
6. write immutable output metadata

### 4. Menu Surface Still Knows Too Much

`menu.py` imports and executes scoring/reporting actions directly. It also
calculates readiness status and output map text.

Target shape:

```text
menu.py             display loop and dispatch only
menu_status.py      readiness model and status rows
menu_actions.py     action functions
menu_help.py        command/output map text
```

This keeps operator UX stable while making menu tests smaller.

### 5. Legacy Phase Naming Still Leaks

Several docstrings and comments still use `Phase E/F/G` or older paper-specific
language. That is not always wrong internally, but it makes support harder
because the active operator model is now:

- freeze/profile mode;
- operational query mode;
- publication bundle generation.

Use phase labels only where the artifact contract requires historical
compatibility.

## Refactor Order

### Pass 1: Extract Pure Writers From `evidence_pack_ml_orchestrator.py`

Complete for the initial writer boundary.

- Per-run model manifest, semantic config sidecar, fingerprint reader, skip
  writers, and cohort status writers live in `freeze_profile/run_artifacts.py`.
- Per-run ML summary, DARS, top-k windows, z-score attribution, score loaders,
  CSV helpers, and stable model filename labels live in
  `freeze_profile/run_summary.py`.
- The legacy orchestrator imports these helpers through private aliases so
  existing tests and callers that still reference private helper names remain
  compatible during the staged split.

### Pass 2: Extract Dataset Table Builders/Writers

Complete for the freeze/profile table boundary.

Table computation and writers now live together in
`freeze_profile/dataset_tables.py`:

- prevalence rows/writers;
- model overlap;
- ML audit;
- DARS components;
- baseline stability;
- static/dynamic stratification;
- transport mix.

The orchestrator imports these helpers through private aliases, preserving the
current call surface while separating dataset reporting from model scoring.
Focused tests cover phase-row metrics, PCAP byte fallback, transport ratio
clamping, and prevalence CSV aggregation.

### Pass 3: Split `query_mode_runner.py`

Move operational per-run writers and model manifest writers into
`operational/run_artifacts.py`; move group fit/score logic into
`operational/scoring.py`. Keep `run_ml_query_mode` as the only public entrypoint.

The first success metric is reducing `run_ml_query_mode` below about 250 lines.

### Pass 4: Split Publication Bundle Writer

Format writers are extracted to `publication_bundle/exporters.py`:

- `_write_csv_with_provenance`
- `_write_tex_table`
- `_write_xlsx`
- `_tex_escape`

Validation and manifest helpers are also extracted:

- `_copy_required`
- `_sha256_stream`
- `_write_required_fields_validation_report`
- `_write_phrase_lint_report`
- `_write_determinism_checksums`

The legacy bundle writer imports these through private aliases so table and
manifest call sites remain stable. Next, split figures and tables. Keep the
current output filenames stable.

### Pass 5: Menu Cleanup

Only after the backend split, move readiness/status/action helpers out of
`menu.py`. This prevents the menu from becoming another compatibility layer over
unstable internals.

## Do Not Do Yet

- Do not change output paths while extracting modules.
- Do not change scoring thresholds or model parameters during refactor.
- Do not introduce DB reads into freeze/profile scoring.
- Do not remove compatibility function names until Reporting and script callers
  are migrated.
- Do not convert to a full external MLOps framework; the current research tool
  needs explicit local contracts more than infrastructure complexity.

## Suggested Acceptance Gates

After each extraction pass:

```bash
python -m py_compile scytaledroid/DynamicAnalysis/ml/**/*.py
pytest tests/ml -q
pytest tests/scripts/test_profile_v3_tools.py tests/scripts/test_publication_ml_audit_report.py -q
pytest tests/gates/test_no_new_legacy_term_leakage_docs_and_scripts.py -q
```

For behavior-sensitive changes:

```bash
PYTHONPATH=. python scripts/operational/phase_f3_acceptance_gate.py --package com.facebook.katana
```

The main design goal is to make the package read like a pipeline:

```text
select evidence -> validate identity -> build features -> train/score -> write
per-run outputs -> write dataset/reporting outputs -> lint/provenance bundle
```

Each step should be testable without running the whole pipeline.
