# Dynamic DB Table Assessment (2026-06-15)

Scope: live `scytaledroid_core_prod` dynamic-analysis tables and the adjacent DB-backed research cohort layer.

This is a read-first schema assessment, not a migration plan.

## Current dynamic tables

### Canonical run header

`dynamic_sessions`

- Role: canonical per-run session header.
- Carries:
  - run identity
  - package/device/operator protocol tags
  - static handoff linkage
  - PCAP validity/header fields
  - dataset verdict fields
  - coarse QA summary fields
- Current live row count: `153`
- Recommendation:
  - keep as the canonical dynamic run header
  - do not keep widening it for every new derived metric
  - treat it as the stable run spine that other tables reference

### Canonical issue / QA detail

`dynamic_session_issues`

- Role: per-run structured issue ledger.
- Current live row count: `129`
- Recommendation:
  - keep as the first-class issue/event ledger
  - use this instead of overloading `dynamic_sessions.status`

### Canonical telemetry facts

`dynamic_telemetry_process`

- Role: append-only process telemetry fact table.
- Grain: one process sample row.
- Current live row count: `19,892`

`dynamic_telemetry_network`

- Role: append-only network telemetry fact table.
- Grain: one network sample row.
- Current live row count: `8,723`

Recommendation:

- keep both as narrow fact tables
- do not fold them into `dynamic_sessions`
- future performance work should focus on indexes, retention policy, and summary views, not denormalization into the header table

### Derived / rebuildable runtime marts

`dynamic_network_indicators`

- Role: rebuildable extracted indicators such as top DNS/SNI/domain observations.
- Current live row count: `811`

`dynamic_network_features`

- Role: rebuildable per-run feature mart for ML/reporting.
- Current live row count: `48`

`dynamic_domain_observations`

- Role: rebuildable per-run classified domain observation mart.
- Current live row count: `220`

Recommendation:

- keep these explicitly rebuildable from evidence packs
- do not treat them as the primary source of truth
- if a row can be regenerated from `run_manifest.json`, `pcap_report.json`, `pcap_features.json`, or other evidence-pack artifacts, it belongs in this layer

### Reference / dimension-style tables

`dynamic_domain_reference`

- Role: DB-backed classification seed/reference table for runtime domains.
- Current live row count: `37`
- Recommendation:
  - keep small and curated
  - use it as a dimension/reference layer, not as a catch-all observation table
  - if this grows materially, split exact-match and suffix/root-family catalogs rather than pushing more logic into reports

`dynamic_service_catalog`

- Role: curated provider/service dimension for runtime network interpretation.
- Current live row count: `18`
- Recommendation:
  - keep this as the named service/provider source of truth
  - use it for ownership, service-category, and primary-use-case labeling
  - keep it small, reviewed, and evidence-oriented rather than auto-populating it from observations

`dynamic_service_domain_map`

- Role: curated domain-to-service mapping table sitting between raw observed domains and the service catalog.
- Current live row count: `29`
- Recommendation:
  - use package-scoped overrides where first-party behavior matters
  - use global suffix/exact rules for stable third-party infrastructure
  - treat it as additive context, not as a replacement for `dynamic_domain_reference`

`dynamic_signal_catalog`

- Role: curated analyst-facing privacy/security/context signal taxonomy.
- Current live row count: `10`
- Recommendation:
  - keep this stable and semantically conservative
  - use it to explain what a resolved service implies for analysis, not to assign canonical numeric risk

`dynamic_service_signal_map`

- Role: many-to-many map from services to analyst-facing dynamic signals.
- Current live row count: `20`
- Recommendation:
  - keep this as the DB-backed interpretation layer above provider identification
  - prefer signals like attribution, advertising, audience profiling, analytics, or engagement over vague “risk” labels

### Research cohort control layer

`research_cohorts`

- Role: reusable DB-backed research dataset definition.
- Current live row count: `2`

`research_cohort_members`

- Role: flattened app membership for cohort definitions.
- Current live row count: `30`

Recommendation:

- keep this separate from dynamic evidence tables
- this is operational/research-control metadata, not dynamic runtime evidence

### Legacy / adjacent tables

`analysis_cohorts`
`analysis_cohort_runs`

- Role: older derived/frozen cohort registry surfaces.
- Recommendation:
  - keep for compatibility
  - do not reuse as the canonical research dataset definition layer

`runs`

- Role: legacy compatibility table.
- Recommendation:
  - do not add new dynamic semantics here
  - keep legacy-only

## What is structurally good now

1. Dynamic evidence is no longer forced into one table.
2. Telemetry facts are already separated from the session header.
3. Rebuildable marts exist for indicators, features, and domain context.
4. DB-backed research cohorts are separated from `apps.profile_key`.
5. Dynamic domain context now has:
   - a curated reference layer
   - an observation layer
   - live reindex support from evidence packs
6. Dynamic service context now has:
   - a provider/service dimension
   - a domain-to-service mapping layer
   - a read-only service-context audit over live dynamic observations
7. Dynamic service interpretation now has:
   - a signal taxonomy
   - a service-to-signal bridge
   - a read-only signal audit over live dynamic observations
8. Dynamic runtime analysis now has a repo-owned SQL context surface:
   - `v_dynamic_run_context_v1`
   - normalized effective run profile / interaction fields
   - typed static linkage state
   - run-level domain/service/signal rollups for analyst queries

## Main pain points

### 1. `dynamic_sessions` is carrying too many semantic classes

It currently mixes:

- identity
- operator protocol
- dataset verdict
- QA summaries
- artifact header fields
- some derived convenience fields

That is still acceptable operationally, but it is the clearest place where future widening will become debt.

### 2. Derived tables need clearer “mart vs source” discipline

`dynamic_network_features`, `dynamic_network_indicators`, and `dynamic_domain_observations` are useful, but they must remain rebuildable and versioned by derivation logic. They should not quietly become alternate sources of truth.

The mitigation now is to keep analyst queries pointed at a repo-owned read model (`v_dynamic_run_context_v1`) instead of encouraging direct ad hoc joins across the raw derived tables.

### 3. Domain, service, and signal context still need curated growth discipline

The current `dynamic_domain_reference` plus `dynamic_service_catalog` / `dynamic_service_domain_map` / `dynamic_signal_catalog` design is materially better than a single flat list, but it still needs curation discipline. The remaining unresolved rows show that:

- ad-tech and measurement ecosystems expand quickly
- first-party variants still need package-scoped overrides
- some providers are safe to curate from official documentation, while others should remain unresolved until attribution confidence is high

The next split, if needed later, should be:

- root/family catalog
- optional package-scoped overrides
- optional ownership/role evidence notes
- service/provider dimension rows that stay stable even when domain patterns change
- signal taxonomy rows that stay stable even when provider mappings expand

### 4. Legacy dynamic rows still exist with incomplete verdict truth

Some historical `dynamic_sessions` rows still have `valid_dataset_run IS NULL` because their local evidence/manifests do not support full reconstruction. That is legacy evidence debt, not a current writer-path defect.

## Recommended next DB moves

These are the highest-value next schema directions if dynamic work continues after the paper deadline.

### A. Keep `dynamic_sessions` as the run spine, but stop widening it

If more verdict/quality metadata is needed, add a companion table such as:

- `dynamic_run_quality`

Possible contents:

- technical validity
- protocol compliance
- cohort eligibility
- paper eligibility
- exclusion reason codes
- low-signal flags
- quality version / derivation version

Reason:

- it keeps the run header stable
- it gives verdict logic its own contract
- it makes historical backfill and audit easier

### B. Keep telemetry as fact tables and add summary views, not more summary columns

If query cost becomes a problem, add:

- repo-owned `v_dynamic_run_summary_*` views
- optional periodic summary tables

Do not copy large sets of telemetry-derived metrics into `dynamic_sessions`.

### C. Treat domain + service + signal context as a small star schema

If domain context expands, the clean next split is:

- `dynamic_domain_reference` for curated classification rules
- `dynamic_service_catalog` for named provider/service rows
- `dynamic_service_domain_map` for domain-to-service bindings
- `dynamic_signal_catalog` for analyst-facing interpretation signals
- `dynamic_service_signal_map` for service-to-signal bindings
- optional `dynamic_domain_catalog` for normalized root-domain family rows
- `dynamic_domain_observations` for per-run observed facts

That follows the same “dimension + fact” pattern used in analytics systems and fits the actual query shapes better than a single overloaded table.

### D. Keep cohorts out of evidence tables

`research_cohorts` and `research_cohort_members` should continue to drive:

- app selection
- readiness scoping
- export scoping

They should not be merged into evidence or telemetry tables.

## Outside-context guidance that aligns with this design

Two outside references are especially relevant:

1. The Android dynamic-analysis SLR emphasizes runtime monitoring, network monitoring, code-coverage constraints, and non-determinism as core realities of Android dynamic security research. That supports ScytaleDroid’s separation between:
   - evidence packs
   - canonical run/session headers
   - rebuildable derived marts

Source:
- https://orbilu.uni.lu/bitstream/10993/62528/1/Dynamic_Security_Analysis_on_Android_A_Systematic_Literature_Review.pdf

2. Dimensional/fact-table modeling guidance consistently favors:
   - narrow, high-row-count fact tables
   - separate dimension/reference tables
   - summary marts/views for common query patterns

That aligns with keeping:

- `dynamic_telemetry_process`
- `dynamic_telemetry_network`
- `dynamic_domain_reference`
- `dynamic_domain_observations`

as distinct layers instead of collapsing them into a single wide dynamic table.

Source:
- https://learn.microsoft.com/en-us/fabric/data-warehouse/dimensional-modeling-fact-tables

Additional privacy-traffic context:

- Lumen’s Android traffic-analysis work shows the value of preserving app/process-linked network observations at the device vantage point, which supports keeping per-run/per-observation dynamic facts queryable rather than only exporting CSV snapshots.

Source:
- https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_05B-3_Razaghpanah_paper.pdf

## Bottom line

The dynamic DB is no longer missing a backbone. The next useful changes are not a broad rewrite.

The right shape is:

1. `dynamic_sessions` = canonical run spine
2. `dynamic_session_issues` = structured run QA/issues ledger
3. `dynamic_telemetry_*` = append-only fact tables
4. `dynamic_network_*` and `dynamic_domain_observations` = rebuildable marts
5. `dynamic_domain_reference` = curated reference dimension
6. `research_cohorts` / `research_cohort_members` = research-control layer

If more splitting happens later, split verdict/quality metadata out of `dynamic_sessions` first.
