# Table Ownership (Phase-1 Draft)

Purpose: avoid write collisions as the web app comes online by documenting which components should own or primarily write to each table group.

## Shared core
- `schema_version` — shared (bootstrap writes, both sides read)
- `runs` / `static_analysis_runs` — shared metadata; writers must coordinate

## CLI-owned (primary writer)
- Inventory: `inventory_*` tables (device/package snapshots, diagnostics)
- Static analysis outputs:
  - `static_findings_summary`, `static_findings`
  - `static_permission_risk`
  - `static_string_summary`, `static_string_samples`, `static_string_match_cache`, `static_doc_hosts`
- Harvest/scopes: `harvest_*`, permission cohort tables
- Behavior (new): behavior session outputs if/when persisted

## Web-owned (planned)
- User/session/auth tables (when introduced)
- UI preferences, saved filters, annotations/commentary
  - Proposed: `web_user_prefs`, `web_annotations`
- Any web-side task queues or background job metadata

## Shared / background
- Reference data reused by both (e.g., permission catalogs, mappings)
- Future background worker state (if added)

Guidance:
- Phase-1 changes must be additive and schema_version bumped.
- If web needs to write to a CLI-owned table, coordinate and document expected fields first.
- Prefer new additive columns over destructive changes; migrations are deferred until a formal framework is adopted.
