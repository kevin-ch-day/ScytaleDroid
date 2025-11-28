# Legacy audit checklist (ScytaleDroid)

Short list to guide staged deprecation (keep → warn → remove). Update as items are addressed.

## Inventory
- `SCYTALEDROID_LOAD_LEGACY_INVENTORY` flag: warn on use; remove after v2 snapshot/delta path is fully trusted.
- Legacy boxed summary output: migrate callers to formatter-based views.
- Compat loader in `DeviceAnalysis/inventory/__init__.py`: mark/remove once all callers use `run_full_sync`.

## Harvest
- `pull_mode="legacy"` defaults (common.py, runner.py, summary.py): deprecate in favor of explicit modes (`quick`, `full`, `test`).
- `quick_harvest.py`: marked LEGACY; hide/remove once planner+runner flow is validated across scopes.
- Standardize skip-reason vocabulary and feed it into formatter-based summaries.

## Static analysis
- Decide canonical evidence tables for PhD build: `runs`, `static_findings`, `static_findings_summary`, `static_permission_risk`, `permission_audit_*`.
- Mark legacy provider/snapshot schemas and avoid in new reports.
- Apply formatter RUN START/SUMMARY everywhere; retire box-style summaries.

## DB utilities / scripts
- Label legacy table/menu entries (e.g., `static_provider_acl`, `static_fileproviders`, `findings (legacy table)`).
- Audit scripts that assume old schema or old text output; update or mark as legacy.

## Formatting / output
- Grep for box-drawing characters and convert remaining “card” outputs to `[RUN]/[RESULT]/[EVIDENCE]` formatter style.
- Add snapshot tests for formatter outputs to prevent regressions to old text paths.

## Env flags
- List and classify `SCYTALEDROID_*` flags (keep vs deprecate), especially inventory/static toggles.
