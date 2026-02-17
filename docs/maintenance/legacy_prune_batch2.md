# Legacy Prune Batch 2

Date: 2026-02-17

## Removed

1. `scripts/publication/regression_gate_freeze.py`
2. `scripts/operational/write_phase_f1_closure.py`

## Why safe

1. `regression_gate_freeze.py` had a single in-repo caller:
   `scripts/operational/write_phase_f1_closure.py`.
2. `write_phase_f1_closure.py` was not referenced by runtime menu paths and had
   no test/runtime reachability in core static/device workflows.

## Behavior impact

1. Removes obsolete Phase-F1 closure automation path.
2. No changes to core menu-driven analysis workflows.

## Rollback

Restore deleted scripts from git history if Phase-F1 closure artifact workflow
is required again.
