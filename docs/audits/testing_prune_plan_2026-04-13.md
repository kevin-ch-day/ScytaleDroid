# Testing Simplification & Legacy Prune Plan (2026-04-13)

## Scope

This pass reviews the current test suite for pruning opportunities and simplification targets.

## Current Test Inventory Snapshot

- Total collected tests: **572** (`pytest --collect-only`)
- Total test files: **196**
- Heaviest folders by test-file count:
  - `tests/static_analysis/` (43 files)
  - `tests/dynamic/` (40 files)
  - `tests/persistence/` (15 files)
  - `tests/unit/` (14 files)
  - `tests/ml/` (13 files)

## What Can Be Pruned or Consolidated

## 1) Consolidate duplicated API test setup (Do now)

### Problem
`tests/api/test_scan_jobs.py` and `tests/api/test_service_upload.py` contained duplicate helper logic for optional `fastapi.testclient` dependency checks.

### Action
- Move helper into shared `tests/api/helpers.py` (`require_fastapi_testclient`) and import from both files.

### Outcome
- Less duplicated test boilerplate.
- Fewer places to edit when API test dependency behavior changes.

## 2) Retire legacy doc-stub gate once v4 path cleanup lands (Near-term)

### Candidate
- `tests/docs/test_legacy_doc_stubs.py`

### Why it exists
- It enforces stub redirects from legacy doc-path aliases to newer paths.

### Prune trigger
- Remove this test once legacy stub files are removed as planned (comments already note planned removal around v4.0).

## 3) Collapse legacy wording gate allow-list over time (Near-term)

### Candidate
- `tests/gates/test_no_new_legacy_term_leakage_docs_and_scripts.py`

### Why it exists
- Prevents reintroduction of legacy terminology, but still has temporary allow-list exceptions.

### Simplification path
- Shrink exceptions each release, then replace with a stricter/shorter policy test (single-source allow-list in one fixture).

## 4) Remove legacy publication isolation tests after publication legacy toggle is deleted (Mid-term)

### Candidates
- `tests/publication/test_legacy_publication_isolation.py`
- `tests/publication/test_no_legacy_script_wrappers.py`

### Prune trigger
- Once legacy publication mode and compatibility wrappers are fully deleted from runtime.

## 5) Merge overlapping persistence legacy guards (Mid-term)

### Candidates (possible merge)
- `tests/persistence/test_legacy_permission_risk_reference_guard.py`
- `tests/database/test_permission_risk_reader_sources.py`

### Why
- Both enforce migration away from legacy permission-risk table paths.

### Simplification idea
- Replace with one contract-focused test module that validates both query sources and runtime references.

## 6) Dynamic profile/template legacy matrix reduction (Mid-term)

### Candidates for parameterization/compression
- `tests/dynamic/test_manual_scenario_protocol.py`
- `tests/dynamic/test_profile_v3_template_mapping.py`
- parts of `tests/dynamic/test_cohort_eligibility.py`

### Why
- These files contain repeated template-id assertions that can be expressed as table-driven parametrized tests with fewer lines and clearer coverage intent.

## 7) Freeze-gate fixture refactor to reduce repeated ML v1 artifact setup (Mid-term)

### Candidate
- `tests/dynamic/test_freeze_gate.py`

### Why
- Repeated creation of `analysis/ml/v1/*` fixture data inflates file size and maintenance cost.

### Simplification idea
- Add local helper fixtures/builders to create canonical run trees once per scenario family.

## High-Confidence “Keep” Areas (Do NOT prune)

- `tests/gates/test_offline_contracts.py`: protects offline behavior when DB schema gates fail.
- `tests/persistence/test_persist_run_summary_atomicity.py`: currently among the slowest tests, but high-value transactional safety coverage.
- `tests/deviceanalysis/test_adb_subprocess_guard.py`: critical security/process-boundary guard.

## Suggested Execution Order

1. **Immediate cleanup (small, low risk):** shared API helper extraction + import hygiene.
2. **Near-term cleanup:** remove legacy doc-stub and wording exception complexity as soon as legacy docs/scripts are removed.
3. **Mid-term refactor:** parameterize dynamic template/eligibility and freeze-gate tests to reduce maintenance overhead.
4. **Final prune:** remove publication/persistence legacy-specific tests once legacy runtime paths are fully deleted.
