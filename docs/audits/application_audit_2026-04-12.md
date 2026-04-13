# ScytaleDroid Application Audit

**Date:** 2026-04-12  
**Auditor:** Codex agent  
**Scope:** Repository-level quality, security posture, test/lint health, and operational readiness.

## Executive Summary

ScytaleDroid has strong architectural direction (clear persistence boundaries, path validation in API upload/scan flow, and explicit DB error taxonomy), but current engineering hygiene is **below release-grade** due to lint drift, failing tests, and unresolved dependency CVEs discovered at audit time.

**Overall rating:** **Moderate-to-High delivery risk** until CI baseline is restored.

## Method

Audit steps executed:

1. Reviewed project metadata and entrypoints (`README.md`, `pyproject.toml`, `requirements.txt`, `main.py`).
2. Ran static quality checks:
   - `ruff check scytaledroid scripts tests`
   - `pytest -q`
3. Ran dependency vulnerability scan:
   - `pip-audit -r requirements.txt`
4. Performed targeted code review of sensitive execution paths:
   - API server auth/upload/scan flow (`scytaledroid/Api/service.py`)
   - ADB command execution wrapper (`scytaledroid/DeviceAnalysis/adb/client.py`)
   - DB execution and retry logic (`scytaledroid/Database/db_core/db_engine.py`)

## Detailed Findings

### 1) CI/Lint Baseline Is Not Clean (High)

- `ruff` currently reports **255 violations** (179 auto-fixable), including:
  - import-order drift (`I001`)
  - module import placement issues (`E402`)
  - unused imports (`F401`)
  - exception-chaining hygiene (`B904`)
  - test correctness concerns (`B011`, `F601`)
- The volume indicates the project cannot currently enforce a strict lint gate without significant cleanup.

**Risk:** regressions can hide inside style/noise churn; lowers reviewer signal-to-noise.

### 2) Test Suite Has Functional and Environment Breakages (High)

`pytest -q` result during audit: **5 failed, 550 passed, 6 skipped, 11 errors**.

Representative failures/errors:

- API tests fail because `fastapi.testclient` pulls `starlette.testclient`, which requires `httpx`, but `httpx` is unavailable in environment during test execution.
- Persistence tests error because test setup tries to clear `static_permission_risk` when that table is missing in the current sqlite test schema.
- Contract drift in harvest tests: `HarvestRunMetrics` now requires `packages_drifted` and `packages_with_mirror_failures`, but tests instantiate without those required arguments.

**Risk:** broken feedback loop for contributors; false confidence if only subsets are run.

### 3) Dependency Vulnerabilities Detected (High)

`pip-audit` reported **6 known vulnerabilities** across transitive dependencies in the active environment:

- `flask 3.1.2` → CVE-2026-27205 (fix: 3.1.3)
- `pyopenssl 25.3.0` → CVE-2026-27448 / CVE-2026-27459 (fix: 26.0.0)
- `tornado 6.5.2` → GHSA-78cv-mqj4-43f7 / CVE-2026-31958 / CVE-2026-35536 (fix: 6.5.5)

**Risk:** exploitable runtime surface depending on which optional components are deployed.

### 4) API Auth Is Optional by Environment Configuration (Medium)

In `_require_api_key`, auth enforcement is bypassed when `SCYTALEDROID_API_KEY` is unset.

- This is practical for local development.
- But it is risky for accidental non-local deployment because unauthenticated endpoints remain active by default.

**Risk:** accidental exposure if operator assumes key is mandatory.

### 5) API Error Handling Catches `BaseException` in Worker Path (Medium)

`_run_static_scan` catches `BaseException`, which includes `KeyboardInterrupt` and `SystemExit`.

**Risk:** process-level control-flow exceptions can be swallowed, making shutdown and orchestration behavior less predictable.

### 6) Positive Controls Observed (Strengths)

- API path validation restricts scan requests to approved base directories and validates existence before execution.
- ADB wrappers build subprocess argv as tokenized lists (not shell interpolation), reducing command injection risk.
- DB layer has explicit parameter normalization and transient error handling with bounded retries.

These are strong foundations worth preserving.

## Prioritized Remediation Plan

### P0 (Immediate, 1–2 days)

1. **Restore CI signal:**
   - Add/lock missing API test dependency (`httpx`) in dev/test workflow.
   - Fix failing tests in `tests/persistence/test_permission_risk.py`, `tests/harvest/test_harvest_views.py`, and `tests/gates/test_offline_contracts.py` to match current contracts/schemas.
2. **Patch vulnerable dependency graph:**
   - upgrade impacted transitive packages via dependency bumps/constraints and rerun `pip-audit`.

### P1 (This sprint)

1. **Lint stabilization campaign:**
   - run `ruff --fix` for mechanical issues first,
   - then manually resolve residual correctness warnings (`B*`, duplicated dict keys, assert patterns).
2. **API hardening defaults:**
   - consider explicit `SCYTALEDROID_API_REQUIRE_KEY=1` default in non-dev modes.
3. **Exception hygiene:**
   - narrow `except BaseException` to `except Exception` in API worker routine.

### P2 (Next sprint)

1. Add CI stages that separately gate:
   - unit tests,
   - contract/integration tests,
   - lint,
   - dependency audit.
2. Publish an `environment bootstrap` doc for test parity (tools + optional extras).

## Audit Conclusion

The application is architecturally mature in several core modules, but current quality gates are not reliable enough for high-confidence release operations. Addressing CI breakages and dependency CVEs should be treated as release blockers.

## Addendum (2026-04-13): Repository Size + Test Runtime Snapshot

Additional profiling requested:

- **Repository footprint (tracked files in working tree scan):**
  - Total files scanned: **1,017**
  - Total bytes scanned: **6,466,646** (~6.17 MiB)
- **Largest files (top examples):**
  - `scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py` (116,933 bytes)
  - `scytaledroid/DynamicAnalysis/menu.py` (100,580 bytes)
  - `scytaledroid/DynamicAnalysis/ml/artifact_bundle_writer.py` (97,421 bytes)
  - `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py` (89,709 bytes)
  - `scytaledroid/DynamicAnalysis/ml/query_mode_runner.py` (74,029 bytes)

- **Test runtime hotspot snapshot (`pytest --durations=15`):**
  - Slowest tests are concentrated in persistence retry/atomicity flows and compileall/publication/profile tools checks.
  - Slowest single-call durations observed were approximately **0.31s–0.38s** per test (not counting setup).

Interpretation:

- Codebase size itself is moderate, but complexity is concentrated in a small number of very large modules under DynamicAnalysis/StaticAnalysis.
- Test runtime is currently acceptable for local full-run loops, but continued growth in the largest modules is likely to increase maintenance and review overhead.
