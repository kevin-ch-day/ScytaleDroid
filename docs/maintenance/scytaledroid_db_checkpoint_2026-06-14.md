# ScytaleDroid DB Checkpoint (2026-06-14)

This checkpoint reconciles the current repo and live DB state before any new
Phase B schema work.

Scope of this checkpoint:

- read-only DB verification
- no new `ALTER TABLE`
- no new prune action
- no Permission Intel changes

## Current artifact_registry state

Live counts from:

- `PYTHONPATH=. python scripts/db/report_artifact_registry_typed_linkage_audit.py`
- `PYTHONPATH=. python scripts/db/report_artifact_registry_dynamic_dangling.py`

Current state:

- total `artifact_registry` rows: `22351`
- static linked rows: `10432`
- static dangling rows: `8810`
- dynamic linked rows: `3109`
- dynamic dangling rows: `0`
- fallback-needed rows: `0`
- legacy-vs-typed parity: exact

Interpretation:

- the detached dynamic prune is already applied and closed
- no further dynamic dangling prune should run in the current state
- remaining registry debt is static dangling debt, not dynamic detached debt

## Dynamic prune status

Status: `applied already`

Evidence:

- live `dynamic dangling rows = 0`
- prior prune receipts exist under:
  - `data/state/artifact_registry_dynamic_prune/artifact_registry_dynamic_prune_20260614T072110Z.json`
  - `data/state/artifact_registry_dynamic_prune/artifact_registry_dynamic_prune_20260614T072124Z.json`
  - matching `.csv`, `.sql`, and `_run_ids_*.txt` files in the same directory

This means the repo already contains both:

- the implementation for detached dynamic prune
- the completed operational outcome of that prune

## schema_migrations status

Live report from:

- `PYTHONPATH=. python scripts/db/report_schema_migrations.py`

Current state:

- live schema version: `0.3.3-typed-backfill`
- registered migration count: `3`
- applied row count: `3`
- missing migrations: none
- duplicate registry ids: none
- registry chain issue count: `0`
- checksum mismatch count: `0`
- applied statuses: `applied=3`

Interpretation:

- Phase A migration governance is active
- the current migration chain is internally consistent

## Phase A typed-read parity status

Live report from:

- `PYTHONPATH=. python scripts/db/report_phase_a_typed_read_parity.py`

Current state:

- parity clean: `True`
- `dynamic_sessions_total`: `143`
- `static_link_state_mismatch_rows`: `0`
- `started_at_parity_mismatch_rows`: `0`
- `dynamic_run_uuid_parity_mismatch_rows`: `0`

Current parity receipt:

- `data/state/schema_migrations/phase_a_typed_read_parity_20260614T160807Z.json`

Interpretation:

- typed replacement fields are populated
- typed-preferred reads currently agree with legacy-compatible fallback reads
- Phase B2 should be a read-cutover/specification pass, not a rescue pass

## Current repo-owned schema references

Primary repo-specific sources now present:

- canonical schema map:
  - [scytaledroid_canonical_schema_map_2026-06-14.md](./scytaledroid_canonical_schema_map_2026-06-14.md)
- canonical schema map output bundle:
  - `output/audit/canonical_schema_map/20260614T154650Z/`
- broader external schema research memo:
  - [scytaledroid_external_schema_research_2026-06-14.md](./scytaledroid_external_schema_research_2026-06-14.md)
- narrower MariaDB-focused upgrade note:
  - [database_schema_upgrade_research_2026-06-14.md](./database_schema_upgrade_research_2026-06-14.md)

Recommended authority order for future schema work:

1. `scytaledroid_canonical_schema_map_2026-06-14.md`
2. `scytaledroid_external_schema_research_2026-06-14.md`
3. `database_schema_upgrade_research_2026-06-14.md`

Practical interpretation:

- the external schema research memo is the primary outside-context design memo
- the MariaDB-focused note should be treated as a narrower implementation appendix
- Phase B should build on these files rather than generating another broad research memo

## Tests run for this checkpoint

Targeted DB/migration slice:

```bash
pytest tests/db/test_schema_migration_governance.py \
       tests/db/test_report_canonical_schema_map.py \
       tests/db/test_phase_a_typed_read_parity.py \
       tests/db/test_artifact_registry_typed_linkage.py \
       tests/db/test_report_artifact_registry_integrity.py \
       tests/db/test_report_artifact_registry_dynamic_dangling.py \
       tests/db/test_artifact_registry_dynamic_prune.py \
       -q
```

Result:

- `31 passed`

Broader sanity sweep:

```bash
pytest tests/database/test_schema_manifest_static_handoff_view.py \
       tests/database/test_static_session_operator_audit.py \
       tests/unit/test_analysis_integrity_summary.py \
       tests/static_analysis/test_report_json_storage.py \
       tests/static_analysis/test_run_health.py \
       -q
```

Result:

- `34 passed`

## Current git status checkpoint

At this checkpoint the repo is already dirty from prior DB/static work. This is
expected.

The important state conclusion is:

- DB cleanup and Phase A typed-linkage work are already operationally real
- next work should be bounded Phase B1/B2 specification and then additive
  implementation
- do not reopen dynamic detached prune work
