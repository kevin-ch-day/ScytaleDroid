# Determinism Comparator Contract

This contract defines the comparator artifact and pass/fail semantics for
determinism gates.

## Compare Types

Current:

1. `inventory_guard`
2. `static_analysis`

Planned (same schema):

1. additional comparator modules beyond inventory/static

## Pass/Fail Rule

1. Strict equality for compared payloads.
2. Only explicitly allowed diff fields may vary.
3. Any disallowed diff -> `FAIL`.
4. Any validation issue (missing required key fields, duplicate key rows) -> `FAIL`.

## Required JSON Artifact Fields

Top-level fields:

1. `tool_semver`
2. `git_commit`
3. `compare_type`
4. `left`
5. `right`
6. `allowed_diff_fields`
7. `result`
8. `diffs`

`result` object:

1. `pass` (boolean)
2. `degraded` (boolean)
3. `degraded_reasons` (list)
4. `fail_reason` (nullable string)
5. `validation_issues` (list)
6. `diff_counts.total`
7. `diff_counts.allowed`
8. `diff_counts.disallowed`

`diffs[]` item:

1. `path`
2. `left`
3. `right`
4. `allowed`

## Artifact Location

Default local output:

`output/audit/comparators/<compare_type>/<timestamp>/diff.json`

## Notes

1. Comparator must be key-based, not row-order based.
2. Degraded mode is interactive-only and not enabled by default.
