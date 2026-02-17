# `static_permission_risk` Reader Migration Map

This map identifies current read paths that touch legacy
`static_permission_risk` and the target cutover state.

## Contract

1. During migration, legacy reads are allowed only where listed below.
2. After cutover, core reporting paths must read run-aware sources only.
3. `static_permission_risk_vnext` (or successor run-aware table/view) is the
   target for scientific permission-risk attribution.

## Reader Inventory

| Reader Type | File | Current State | Target State |
| --- | --- | --- | --- |
| SQL view | `scytaledroid/Database/db_queries/views.py` | vNext | vNext |
| Canonical schema query | `scytaledroid/Database/db_queries/canonical/schema.py` | vNext | vNext |
| Health/status menu hints | `scytaledroid/Database/db_utils/menus/health_checks.py` | dual (migration hint) | vNext label |
| Static reset utility | `scytaledroid/Database/db_utils/reset_static.py` | dual (legacy+vNext cleanup) | dual until legacy table removed |
| Schema gate checks | `scytaledroid/Database/db_utils/schema_gate.py` | vNext required | vNext required |
| Audit pack docs | `docs/database/queries/AUDIT.md` | legacy listed | update to run-aware table set |
| Persistence tests | `tests/integration/test_persist_run_summary.py` | legacy assertions | dual, then vNext assertions |
| Permission risk tests | `tests/persistence/test_permission_risk.py` | legacy + vNext gate tests | keep overwrite proof + vNext authoritative tests |

## Cutover States

1. `legacy`
   - Reader uses legacy table directly.
2. `dual`
   - Reader supports both legacy and vNext/run-aware shape.
3. `vNext`
   - Reader uses only run-aware permission-risk source.

## Exit Rule

Cutover is complete only when all rows above are in `vNext` state and CI
contains a grep guard preventing new runtime references to
`static_permission_risk` from non-migration modules.
