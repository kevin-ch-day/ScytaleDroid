# Error Handling Audit (Hardening Sprint)

Date: 2026-01-23

Goal: Fail loud in logs, fail clean in UI, and never silently succeed when core persistence/harvest steps fail.

## Scope

Critical flows audited first:
- Pull APKs / harvest
- Static analysis persistence + verification
- Permission-only scan persistence
- Inventory sync / device workflows
- Reporting exports

Out of scope: web UI, schema redesign, performance tuning.

## Recent fixes (baseline)

- Pull APKs: full traceback logged on failure; UI hint added. (`scytaledroid/DeviceAnalysis/device_menu/actions.py`)
- Harvest summary failures: full traceback logged; UI stays clean. (`scytaledroid/DeviceAnalysis/apk_pull.py`)
- Permission-only scan: persistence failures logged and surfaced in UI; static run status marked FAILED on persistence failure. (`scytaledroid/StaticAnalysis/cli/execution/permission_flow.py`)
- Permission audit persistence: catch-all now logs full traceback + context. (`scytaledroid/StaticAnalysis/modules/permissions/audit.py`)
- OperationResult contract introduced and wired into harvest + permission audit persistence. (`scytaledroid/Utils/ops/operation_result.py`, `scytaledroid/DeviceAnalysis/apk_pull.py`)
- Permission audit app persistence now returns PARTIAL on per-app failures and logs tracebacks. (`scytaledroid/StaticAnalysis/modules/permissions/audit.py`)
- Permission snapshot header/fallback now logs full tracebacks. (`scytaledroid/StaticAnalysis/persistence/snapshots.py`)
- Pull APKs now returns OperationResult on all early exits (no silent `None`). (`scytaledroid/DeviceAnalysis/apk_pull.py`)

## Audit scan summary (rg results)

Pattern search:
- `except Exception: pass`
- `return None` on error paths
- UI error panels without traceback logging

Observed hotspots (triaged):

### P0 (must fix in this sprint)

- **Permission persistence** still has silent failure paths outside the permission-only flow:
  - `scytaledroid/StaticAnalysis/persistence/permissions_db.py`
- **Static persistence writers** return None with no explicit result contract:
  - `scytaledroid/StaticAnalysis/cli/persistence/findings_writer.py`
  - `scytaledroid/StaticAnalysis/cli/persistence/metrics_writer.py`
  - `scytaledroid/StaticAnalysis/cli/persistence/utils.py`
- **Core DB write wrapper** returns None (potentially flattening exceptions):
  - `scytaledroid/Database/db_core/db_queries.py`
  - `scytaledroid/Database/db_core/db_engine.py`

### P1 (should fix)

- **Harvest / inventory** workflows return None on error without a structured result:
  - `scytaledroid/DeviceAnalysis/harvest/scope.py`
  - `scytaledroid/DeviceAnalysis/inventory_meta.py`
  - `scytaledroid/DeviceAnalysis/device_menu/inventory_guard/*`
- **Reporting menu actions**: return None on failure with limited context:
  - `scytaledroid/Reporting/menu_actions.py`

### P2 (nice to fix / monitor)

- Utility helpers return None as a normal control signal (may be OK but needs documentation):
  - `scytaledroid/Utils/AndroidPermCatalog/*`
  - `scytaledroid/StaticAnalysis/modules/string_analysis/*`
  - `scytaledroid/StaticAnalysis/analytics/*`

## Known exceptions and current behavior

- **Pull APKs**: now logs traceback and shows clean panel; root cause is still surfaced in logs.
- **Permission-only scan**: logs persistence failure and marks run FAILED.
- **Snapshot header fallback**: uses fallback insert when summary rows are absent, but does not currently emit a UI note.

## Proposed standard (OperationResult)

Introduce a lightweight return contract for critical operations:

```
OperationResult:
  ok: bool
  status: OK|FAILED|PARTIAL|ABORTED
  user_message: str
  log_hint: str
  error_code: str
  context: dict
```

Apply to:
- harvest start + summary render
- permission snapshot/app persistence
- static run persistence writers

## Remaining work (planned)

1) Implement OperationResult (new module) and wire into 3 critical flows.
2) Add failure-injection tests (DB down, harvest exception, snapshot insert failure).
3) Enforce run ledger updates for FAILED/PARTIAL/ABORTED paths.

## Test expectations

- No silent persistence failures.
- UI shows one-line warning + “See logs for traceback.”
- Logs always have full stack trace.
- Run status is updated to FAILED or PARTIAL on persistence failure.
