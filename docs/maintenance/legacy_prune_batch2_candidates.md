# Legacy Prune Batch 2 Candidates (2026-04-13)

## Goal

Identify script and test assets that can be removed or consolidated to reduce maintenance cost while preserving critical coverage.

## Current Inventory Snapshot

- Script files under `scripts/`: **66**
- Largest script groups:
  - `scripts/operator/` (14)
  - `scripts/publication/` (12)
  - `scripts/profile_tools/` (10)

## How to Decide If Something Is Safe to Remove

Use this checklist before deleting any script/test:

1. **No active call sites** in code, tests, runbooks, or CI config.
2. **Replacement exists** (canonical command/library API).
3. **Contract coverage retained** (either existing test still covers behavior or a merged test replaces it).
4. **Rollback path documented** (git restore tag/branch and migration note).

Suggested verification commands:

```bash
rg -n "<script_name>|<entrypoint_name>" scripts scytaledroid tests docs .github
pytest -q
```

## Priority Matrix (Actionable)

| Priority | Area | Candidates | Risk | Suggested action |
|---|---|---|---|---|
| P0 | Demo/wrapper scripts | `scripts/operator/run_profile_v2_demo.sh`, `scripts/dev/setup_android_tools.sh` | Low | Remove if no references remain |
| P1 | Publication alias writers | `scripts/publication/publication_exports.py`, `publication_results_numbers.py`, `publication_ml_audit_report.py`, `publication_pipeline_audit.py` | Medium | Deprecate alias paths, then remove alias writes |
| P1 | Migration-only device scripts | `scripts/device_analysis/migrate_legacy_harvest_storage.py`, `replay_harvest_db_mirror.py` | Medium | Mark migration-only, archive after completion milestone |
| P2 | Profile preflight overlap | `profile_v3_integrity_gates.py`, `profile_v3_catalog_validate.py`, `profile_v3_catalog_freeze_check.py`, `profile_v3_static_ready_check.py` | Medium | Merge into one orchestrator CLI with subcommands |
| P2 | Evidence tooling overlap | `scripts/dynamic/evidence_hunt.py`, `scripts/operator/profile_v3_freeze_bundle.py`, `scripts/operational/write_snapshot_bundle.py` | Medium | Consolidate into one canonical evidence CLI |

## Script Prune/Consolidation Details

## A) Publication alias and duplicate output writers (Start now)

### Why
- Multiple scripts still emit compatibility aliases plus canonical artifacts.
- This increases drift risk and multiplies output validation burden.

### Success criteria
- One canonical output location per artifact type.
- Alias writes removed after one release train of deprecation messaging.

## B) Migration-only device tooling lifecycle (Start now)

### Why
- Migration tools are useful during transition but confusing as permanent operator entrypoints.

### Success criteria
- Scripts explicitly tagged `migration-only` in help text/runbook.
- Removal date tied to migration completion checklist.

## C) Profile preflight entrypoint overlap (Near-term)

### Why
- Several scripts run adjacent checks with fragmented UX.

### Success criteria
- Single orchestrator command with focused subcommands:
  - `catalog`
  - `freeze`
  - `static-ready`
  - `integrity`

## D) Evidence/bundle helper sprawl (Near-term)

### Why
- Overlapping responsibilities across dynamic/operator/operational script trees.

### Success criteria
- One canonical evidence CLI + shared library calls.
- Remaining wrappers deleted once references are cut.

## Test-Suite Prune Targets

## 1) Completed in this batch

- Shared API helper extracted:
  - `tests/api/helpers.py`
- API tests now consume shared helper:
  - `tests/api/test_scan_jobs.py`
  - `tests/api/test_service_upload.py`

## 2) Near-term removable tests (after legacy cleanup milestones)

- `tests/docs/test_legacy_doc_stubs.py`
- `tests/publication/test_legacy_publication_isolation.py`
- `tests/publication/test_no_legacy_script_wrappers.py`

## 3) Consolidation targets (keep coverage, reduce file count)

- Merge overlapping permission-risk guards:
  - `tests/persistence/test_legacy_permission_risk_reference_guard.py`
  - `tests/database/test_permission_risk_reader_sources.py`
- Parameterize repetitive dynamic template assertions:
  - `tests/dynamic/test_manual_scenario_protocol.py`
  - `tests/dynamic/test_profile_v3_template_mapping.py`
  - portions of `tests/dynamic/test_cohort_eligibility.py`

## Recommended Next 3 PRs

1. **PR-A (small):** remove low-risk demo wrappers with zero call sites; update runbook references.
2. **PR-B (medium):** merge profile preflight scripts into one CLI orchestrator.
3. **PR-C (medium):** remove publication alias writes; keep canonical outputs only.
