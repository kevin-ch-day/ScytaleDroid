# Legacy Prune Batch 1 (Low-Risk Script Removal)

Date: 2026-02-16

## Scope

Removed legacy publication scripts that had no in-repo runtime call sites and
were outside the core menu/service workflow.

Deleted files:

1. `scripts/publication/contract_gate.py`
2. `scripts/publication/publication_lint.py`
3. `scripts/publication/migrate_output_layout_v2.py`
4. `scripts/publication/make_table_4_compact.py`

Additional dead-code prune:

1. Removed unused `handle_utils()` from `main.py` (not reachable from main menu).

## Reachability Proof

Reference scan run before deletion:

```bash
rg -n "contract_gate|publication_lint|migrate_output_layout_v2|scripts/publication/<name>.py" .
```

Result: no call sites found outside the script files themselves.

## Impact

1. Core CLI/menu flows: no behavior change.
2. Static/dynamic persistence: no behavior change.
3. Publication manifest gate path (`scripts/publication/export_manifest_gate.py`): unchanged.

## Rollback

If external operators rely on removed scripts, restore by reverting this prune
commit or restoring the three deleted files.

## Validation

Run at minimum:

```bash
pytest -q tests/publication/test_legacy_publication_isolation.py \
         tests/publication/test_export_manifest_gate.py \
         tests/publication/test_export_manifest_gate_script.py
pytest -q
```
