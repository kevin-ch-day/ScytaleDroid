# Permission Split Execution Phases

Date: 2026-04-27

This document breaks the permission-intelligence split into explicit execution
phases with CLI, DB, and Web checkpoints.

It is intentionally operational. This file answers: in what order should we do the work without breaking the CLI
or `/var/www/html/ScytaleDroid-Web`?

## Current phase status

Status as of 2026-04-29:

- `Phase 0`: completed
- `Phase 1`: completed
- `Phase 2`: completed
- `Phase 2A`: completed
- `Phase 2B`: completed
- `Phase 3`: completed
- `Phase 4A`: completed
- `Phase 4B`: completed
- `Phase 4C`: completed
- `Phase 5A`: completed
- `Phase 5B`: completed
- `Phase 5C`: in progress
- `Phase 6`: not started
- `Phase 7`: not started

Interpretation:

- the acceptance baseline is now locked
- the documentation and ownership artifacts exist
- the permission-intel application seam is implemented against the dedicated
  `android_permission_intel` DB
- the basic operator stabilization lane is closed for the current demo/review
  cycle
- the shared permission DB has been provisioned and validated for the current project environment
- the full Phase 4 lane is now closed on current code
- the active implementation lane is now Phase 5C database/table cleanup and
  read-model hardening work

## Phase 4 roadmap

Phase 4 is now intentionally split into three sub-stages so execution order is
clear:

- `Phase 4A`: stabilize long-running static workflows, persistence timing,
  operator trust, and data hygiene
- `Phase 4B`: redirect ScytaleDroid permission-reference reads through the
  permission-intel seam
- `Phase 4C`: clean up reporting/read-model dependencies after the 4B cutover

The practical order is strict:

1. `4A` is now complete: batch behavior, persistence, and identity contracts
   have been proven on a closeout validation run
2. `4B` is now complete: permission-reference reads have been redirected behind
   the seam in app-facing code
3. `4C` is now complete: reporting/read-model cleanup and session/data-state
   hardening were proven on current code and fresh runs
4. `5C` is now the active implementation lane after the high-ROI 5B bridge
   isolation/prune work

Phase 4A itself now has three practical workstreams:

- `4A.1` run lifecycle and persistence trust
- `4A.2` operator UX, rerun safety, and interruption handling
- `4A.3` data quality, identity hygiene, and reconciliation

Phase 5 is now also intentionally split:

- `Phase 5A`: bridge parity, collation cleanup, and reader inventory freeze
- `Phase 5B`: bridge write isolation and canonical-first reader migration
- `Phase 5C`: narrow freeze/deprecation of low-risk legacy bridge surfaces

Current Phase 5B closeout on current code:

- dedicated permission-intel runtime cutover is complete
- duplicate permission-intel managed tables were frozen out of
  `scytaledroid_db_dev`
- operational schema bootstrap no longer recreates those duplicate tables
- canonical default DB/operator surfaces no longer normalize bridge-first
  workflow
- the `compat_writer.py` wrapper has been removed and bridge writes now route
  directly through the explicit compatibility writer module,
  `Persistence/db_writer.py`
- package-level DB/persistence re-export shims have been reduced
- the legacy `correlations` bridge writer has been removed
- DB maintenance/reporting paths have been pruned so bridge-first detail is no
  longer the normal operator experience

Remaining work now belongs to Phase 5C:

- continue pruning bridge-heavy DB maintenance actions
- narrow `static_reconcile.py` further toward parity-only responsibilities
- apply freeze/deprecation posture to the remaining bridge tables one surface
  at a time

## Current audit snapshot

Audit date: 2026-04-29

Current repo/testing state:

- recent stabilization and observability changes are committed across:
  - static lifecycle logging
  - rerun/reset safety
  - archive-grade report retention
  - post-run diagnostics cleanup
  - runtime-mode cleanup
  - strict `error.log`
- Phase 4 closeout suite currently passes:
  - `53 passed`
- current prune / bridge-isolation suites also pass after the latest removal
  passes:
  - `49 passed, 2 skipped`
  - `40 passed, 3 skipped`

Current DB reality:

- the latest closeout validation batch is `phase4a-closeout-smoke`
- that session proved the post-fix lifecycle on current code:
  - `10` canonical run rows
  - `10` completed
  - `10` `static_session_run_links`
  - `10` `risk_scores`
  - `10` `static_findings_summary`
  - `10` `static_string_summary`
  - `1` permission snapshot header
  - `10` `permission_audit_apps` child rows
  - `run_map.json` and `execution.json` present
- the structured lifecycle for that run is now coherent:
  - `run.start`
  - `run.phase scan`
  - `run.phase persist_summary`
  - `persist.start`
  - `persist.app`
  - `run.phase postprocess`
  - `run.phase refresh_views`
  - `persist.end`
  - `run.phase completed`
  - `run.end`

Important implication:

- Phase 4A no longer depends on another large all-app batch for trust proof
- Phase 4 closeout is now additionally proven on the full batch
  `20260429-all-full`
- the full closeout run produced:
  - `120` analyzed apps
  - `459/459` artifacts
  - `120` canonical runs finalized
  - `3872` normalized findings
  - `120` `permission_audit_apps` child rows
  - permission snapshot parity:
    `checked=120 changed=3 skipped=117 errors=0`
  - DB verification:
    `OK (group scope) static_run_id=1338`
- the smoke closeout run exercises the exact seam that was previously broken:
  session finalization, permission snapshot refresh, and end-of-run lifecycle
  ordering

Current Phase 4B state:

- governance snapshot count, row count, and latest loaded-at reads now route
  through the permission-intel seam
- AOSP permission catalog and dictionary reads now route through the seam
- OEM/vendor permission dictionary reads and write-side queue/unknown helpers
  now route through the seam
- signal catalog reads/updates now route through the seam
- permission-intel managed table inventory is now centralized in the seam and
  reused by schema/reset/migration helpers
- app-facing direct `permission_intel.run_sql(...)` usage has been removed from
  the current permission helper and static permission reader paths

Current Phase 5A / 5B state:

- runtime permission-intel reads and writes now target the dedicated
  `android_permission_intel` DB
- duplicate managed permission-intel tables have been archived from
  `scytaledroid_db_dev` under `__legacy_20260429`
- operational bootstrap no longer recreates those tables
- DB health/config tooling now exposes the dedicated permission-intel target and
  duplicate-table state
- Query Runner, Recent Runs Dashboard, and default DB health screens now lead
  with canonical surfaces instead of bridge-first workflow
- bridge wrapper/delegation shims have been reduced:
  - `StaticAnalysis/cli/core/run_persistence.py` removed
  - `Persistence/compat_writer.py` removed
  - package-level shim exports in DB/persistence packages reduced to plain
    package markers

Recently completed baseline and stabilization work:

- inventory/harvest core validated as `CORE_KEEP`
- static landing flow redesigned around operator scope
- `Analyze one app` now enters real scan flow
- version diff now selects distinct analyzed versions/builds
- APK Library now resolves the real device serial instead of `unknown`
- static `View previous runs` now opens a canonical run-history browser instead
  of a diagnostics trap
- canonical + legacy package lineage browsing now leads with
  `static_analysis_runs` and treats `runs` as bridge context
- CLI prompts are EOF-safe instead of crashing under exhausted stdin
- static reset cancel now aborts the run cleanly
- auto-suffixed session labels refresh the active run context correctly
- cross-analysis reporting is compact and readable in-terminal
- interrupted static runs now skip run-map linkage, permission refresh, and the
  old post-run verification digest path

## Current web dependency reality

The Web app is not only using the newer `v_web_*` read models. It still has
direct read dependencies in:

- `/var/www/html/ScytaleDroid-Web/database/db_lib/db_queries.php`
- `/var/www/html/ScytaleDroid-Web/database/README.md`

Current direct/static-summary Web dependencies include:

- `v_web_app_directory`
- `permission_audit_apps`
- `permission_audit_snapshots`
- `static_findings_summary`
- `static_findings`
- `static_permission_matrix`
- `static_string_summary`
- `static_string_selected_samples`

Current runtime/cross-analysis Web dependencies include:

- `v_web_runtime_run_index`
- `v_web_runtime_run_detail`
- `dynamic_sessions`
- `dynamic_network_features`
- `dynamic_network_indicators`
- `dynamic_session_issues`
- `analysis_cohorts`
- `analysis_ml_app_phase_model_metrics`
- `analysis_risk_regime_summary`

Important implication:

- the permission-intel split does **not** directly require immediate Web
  rewrites if permission-reference reads stay behind compatibility surfaces
- however, static summary cleanup **does** require a staged Web migration
  because the Web app still reads `permission_audit_*` and
  `static_findings_summary` directly

## Phase 0. Freeze the current acceptance baseline

Goal:

- stop moving targets before the split

Required state:

- inventory/harvest core remains locked
- static menu scope-first behavior remains the operator baseline
- the three fixed operator bugs remain treated as regression targets
- `v_web_static_dynamic_app_summary` remains the preferred new package-level
  cross-analysis read model

Acceptance checks:

- `Analyze one app` reaches scan flow
- version diff uses distinct builds
- APK library shows `ZY22JK89DR`
- Web app still loads Apps Directory and app detail pages

## Phase 1. Document and map all read/write contracts

Goal:

- make the split and the static/web migration readable to reviewers and
  implementers

Deliverables:

- `docs/maintenance/operator_acceptance_matrix.md`
- `docs/maintenance/workflow_entrypoint_map.md`
- `docs/database/ownership_matrix_v1_3.csv`

Required outputs:

- explicit split of shared permission meaning vs ScytaleDroid run outputs
- explicit note that Web still directly reads `permission_audit_*` and
  `static_findings_summary`

Do not:

- migrate schema
- cut over Web reads
- drop anything

## Phase 2. Introduce the permission-intel application seam

Goal:

- add the internal abstraction before moving data

Implementation target:

- add a second logical DB target: `permission_intel`
- add separate env/config keys for permission-intel
- create a dedicated permission-intel query/access layer

First callers to move:

- permission catalog reads from
  `scytaledroid/StaticAnalysis/modules/permissions/catalog.py`
- governance readiness/status reads from
  `scytaledroid/Utils/System/governance_inputs.py`
- governance import path from
  `scytaledroid/Database/tools/permission_governance_import.py`

Acceptance checks:

- with no permission-intel config, system falls back to current operational DB
- with permission-intel config present, lookups route through the new boundary
- static run outputs still record `governance_version` and `governance_sha256`

Do not:

- switch Web to a new DB directly
- change `permission_audit_*` output tables
- drop source tables

### Phase 2A. Compatibility seam implementation

Status:

- completed

Completed implementation:

- dedicated permission-intel DB helper added under
  `scytaledroid/Database/db_core/permission_intel.py`
- `SCYTALEDROID_PERMISSION_INTEL_DB_*` config resolution added
- `DatabaseEngine` can now run with an explicit config override
- first-wave callers moved onto the seam in:
  - permission catalog reads
  - permission dictionary/meta helpers
  - governance readiness/status reads
  - governance import path
  - static governance gating and verification helpers

Current behavior:

- if permission-intel DB config is absent, the app falls back to the current
  operational DB in compatibility mode
- if permission-intel DB config is present, first-wave permission-reference
  readers route through the new seam

Validation status:

- targeted tests passed
- no destructive schema changes were required

### Phase 2B. Operator stabilization and legacy-reader containment

Status:

- completed

Why this phase was inserted:

- live testing found real operator-facing bugs and reporting/read-model seams
- those bugs were important enough to fix before Phase 3 DB provisioning

Completed in this phase:

- static history/review flow now exposes canonical run history
- package-run browsing now shows canonical run IDs, legacy bridge IDs, and
  status in one operator surface
- aborted static runs no longer continue into run-map linkage, permission
  refresh, or the old deferred verification digest path
- static re-analyze/reset flows are now consistent and cancellable
- current scope-first static menu wording is the live operator baseline
- Web package/detail fixes are committed in `ScytaleDroid-Web` at `3b831ac`
- final smoke on ScytaleDroid `b01b530` confirmed:
  - main menu opens
  - device inventory summary opens
  - APK Library browse-by-device shows `ZY22JK89DR`
  - Analyze one app reaches run mode
  - Compare two versions shows `167501 → 168201`
  - Reporting menu opens
  - Database Tools menu opens
- tracked `.env` leakage removed; `.env` now remains local-only and ignored

Deferred out of this phase:

- interrupted runs still print a long partial summary before the final failed
  footer; this is smaller than before but still verbose
- some static/database helper screens still expose bridge-era semantics that are
  technically correct but not yet polished
- broad package-level reporting against `v_web_static_dynamic_app_summary`
  remains expensive

Exit criteria:

- static history/review surfaces are operator-stable
- aborted runs return to the menu without extra diagnostic detours
- no primary static CLI path depends on the legacy `runs/findings` bridge as
  its first-class read model

Result:

- exit criteria satisfied for the current phase boundary

## Phase 3. Provision and validate `android_permission_intel`

Goal:

- create the new shared DB and prove copied reference data is equivalent

Execution:

1. create `android_permission_intel`
2. copy schema for moved tables
3. copy data
4. validate:
   - row counts
   - distinct-key counts
   - governance snapshot identity
   - null/required field expectations

Tables in scope:

- `android_permission_dict_aosp`
- `android_permission_dict_oem`
- `android_permission_dict_unknown`
- `android_permission_dict_queue`
- `android_permission_meta_oem_prefix`
- `android_permission_meta_oem_vendor`
- `permission_governance_snapshots`
- `permission_governance_snapshot_rows`
- `permission_signal_catalog`
- `permission_signal_mappings`
- `permission_cohort_expectations`

Acceptance checks:

- permission-intel DB returns the same lookup semantics as the current DB
- ScytaleDroid can point the permission-intel abstraction at the new DB without
  changing operator-visible behavior

Implementation helpers now prepared for this phase:

- `scytaledroid/Database/tools/permission_intel_phase1_copy.py`
- `scytaledroid/Database/tools/permission_intel_phase1_validate.py`

Do not:

- delete or freeze original source tables yet

Status:

- completed

Completed evidence:

- `android_permission_intel` created and validated for the current project environment
- Phase 1 tables copied successfully
- source and target row counts match
- source and target table checksums match
- governance snapshot identity matches:
  - version `erebus_gov_v0_20260206_01`
  - sha256 `425a54d797750dfc86a6206fcd1835e8ca0445b752aebf59f137f14ebb0f944a`
  - rows `1828`
- fallback-mode tests pass
- dedicated external-DB-mode reads resolve successfully against
  `android_permission_intel`

## Phase 4A. Data and workflow stabilization

Goal:

- stabilize live multi-app static execution, inventory/harvest trust signals,
  and catalog/package hygiene before broader permission read cutover

Status:

- completed

What has now been proven:

- the full all-app run `20260428-all-full` completed successfully
- the pipeline can scan `120` harvested apps / `459` artifacts and reach final
  DB persistence
- deferred persistence timing is real and expected in the current design:
  report artifacts and canonical `STARTED` rows appear during scan, while
  findings/risk/summary rows finalize in post-processing
- canonical rows, bridge rows, and Web-facing latest-session surfaces can
  reconcile for a completed all-app batch

Why this phase exists:

- Phase 3 proved the shared permission DB can be provisioned safely for the current project environment
- live inventory/harvest checks exposed operator-trust issues in status wording
  and count semantics
- the active multi-app batch `20260428-all-full` exposed a more important
  timing question: report artifacts and canonical `STARTED` run headers appear
  during the scan loop, but findings/risk/summary surfaces do not appear
  incrementally in the same session

What Phase 4A has already fixed:

1. run lifecycle observability
   - static logging now emits:
     - `run.phase`
     - `report.saved`
     - `persist.start`
     - `persist.app`
     - `persist.end`
     - `run.abort_requested`
   - logger category aliases now route static events into the correct subsystem
     logs
   - `error.log` is now strict error-only
2. post-processing and persistence audit quality
   - persistence audit output is now stronger and records canonical/bridge
     reconciliation state
   - report retention now preserves session archive JSON/HTML output in
     addition to `latest`
   - the all-app run proved canonical DB, bridge DB, and Web freshness can
     agree after completion
3. operator-run safety and UX
   - large all-app scan output is quieter and more structured
   - post-run diagnostics are menu-based instead of dumping every table by
     default
   - rerun/session-label collision handling now checks DB-backed history, not
     just local metadata
   - launch/reset preflight now explains session strategy and reset scope more
     clearly
   - `Ctrl+C` / `SIGINT` now enters a lifecycle-aware safe-stop path on newer
     runs
4. permission/governance persistence correctness
   - the `proposed_bucket` queue-parameter bug has been fixed
   - the impact was constrained to permission-governance queueing, not core
     permission matrix/risk outputs
5. report and identity artifacts
   - report payloads now retain:
     - `normalized_package_name`
     - `manifest_package_name`
     - `package_case_mismatch`

Current interpretation from code:

- `scan_flow.py` creates the canonical `STARTED` ledger row early via
  `create_static_run_ledger(...)`
- the scan loop then writes per-artifact report JSON/HTML output and emits the
  `[COPY] static_app_done ...` line
- per-app DB persistence does **not** happen inside that scan loop
- persistence happens later in `results.py` via `persist_run_summary(...)`
- `persist_run_summary(...)` calls `execute_persistence_transaction(...)`, which
  writes canonical findings, permission outputs, static sections, and bridge
  rows, and only then finalizes status
- for a large all-app run, this means “reports exist but findings/risk rows are
  still zero” is currently expected timing until the run crosses into the
  results/post-processing phase

What the completed run changed in our interpretation:

- the earlier “empty DB during scan” concern is no longer treated as evidence
  of a hung detector pipeline
- it is now understood as a scan-first / persist-later architecture
- Phase 4A is therefore less about “does it finalize at all?” and more about:
  - making the persistence boundary visible and trustworthy
  - making reruns and interruptions safe
  - reducing operator confusion
  - tightening identity and replay/reconcile contracts

What the latest DB audit added:

- a full all-app scan can still end in a partial post-processing state if a
  first-app persistence exception occurs
- the latest structured log currently allows `run.end status=completed` while
  also recording `failure_codes=[PERSISTENCE_ERROR]`
- Web and cache surfaces can therefore lag or present partial-session bleed even
  when the scanner itself completed
- this makes `run end status coherence` an explicit Phase 4A blocker

Current transaction and recovery boundary:

- the scan loop returns a full `RunOutcome` containing `outcome.results`
- that means multi-app runs currently hold per-app results in memory until scan
  completion
- only after the full scan returns does `run_dispatch.py` enter summary
  rendering and post-processing
- inside that later phase, `results.py` calls `persist_run_summary(...)` once
  per app
- `persist_run_summary(...)` then calls `execute_persistence_transaction(...)`
  for that app
- current tests confirm the canonical run row creation and legacy bridge run
  creation happen inside the same persistence transaction boundary
- if that per-app persistence transaction fails, the run is marked failed and
  post-processing aborts

Current interruption/recovery posture:

- if the process dies during the scan loop, report artifacts and `STARTED` rows
  can exist without findings/risk/summary rows
- later startup can mark abandoned `STARTED` rows `FAILED`
- stale partial sessions should be treated as purge-and-rerun candidates, not
  reconstructed in place
- operator recovery should prefer:
  - session-scoped delete of stale DB rows
  - purge of archived session artifacts/audits/evidence
  - fresh rerun on current code
- post-processing still depends on the full `RunOutcome` being carried through
  to later persistence rather than writing canonical rows incrementally

Current report retention semantics:

- `reports/latest` is a convenience latest-output location
- historical reports are also preserved in session archive paths
- this means stale sessions can be audited before purge, but the preferred
  recovery model is still delete-and-rerun rather than backfill

Current known weak contracts still inside 4A:

- package-name case drift still exists across some report and DB surfaces
- persistence-stage timing is still thinner than desired inside the
  per-app transaction boundary
- interrupted-run output is better, but not yet minimal enough for every
  operator path
- the large all-app pipeline still holds per-app results in memory until
  post-processing rather than persisting canonical outputs incrementally

Expected DB state by phase:

1. Before scan starts
   - no session rows yet for the new session label
   - no report JSON/HTML yet
2. During scan loop
   - report JSON/HTML begins appearing under `reports/latest` and session
     archive paths
   - `static_analysis_runs` rows appear in `STARTED`
   - findings/risk/summary/bridge rows may still be zero for the session
3. After each app scan, before full scan completion
   - per-app report artifacts exist
   - the app's canonical run header exists in `STARTED`
   - findings/risk/bridge rows may still be absent
4. After scan loop completes, before post-processing
   - the full selected batch may have report artifacts plus `STARTED` headers
   - `static_analysis_findings`, `static_permission_matrix`,
     `static_permission_risk_vnext`, `static_findings_summary`,
     `static_string_summary`, `runs`, and `risk_scores` may still be zero
5. During post-processing
   - `results.py` enters the `persist_run_summary(...)` loop
   - canonical findings, permission outputs, string/provider sections, and
     bridge rows should begin appearing
   - `static_analysis_runs.status` should begin transitioning away from
     `STARTED`
6. After successful completion
   - canonical rows are populated for completed apps
   - compatibility/bridge rows are populated where expected
   - no lingering `STARTED` rows remain for the finished session
7. After failure/interruption
   - current known risk: report artifacts and `STARTED` rows may exist without
     downstream findings/risk rows
   - stale-row cleanup can later mark abandoned `STARTED` rows `FAILED`
   - operator recovery should purge the stale session label and re-run on
     current code instead of attempting in-place rebuild

Phase 4A closeout evidence:

1. `4A.1` lifecycle and persistence
   - `run.end` now lands after post-processing, view refresh, and `persist.end`
   - the post-run navigation choice no longer suppresses required finalization
   - the closeout batch `phase4a-closeout-smoke` produced:
     - `10/10` completed canonical runs
     - `10/10` session links
     - `10/10` permission-audit child rows
     - `run_map.json`
     - `execution.json`
2. `4A.2` operator UX and recovery
   - smoke/persistence-test runs now use clearer session-label defaults
   - compact batch output, diagnostics, and rerun prompts were tightened around
     actual operator use
   - stale sessions remain purge-and-rerun only
3. `4A.3` data hygiene and reconciliation
   - session reconcile/purge tooling exists and was exercised during the phase
   - active package identity/linkage paths are normalized enough for closeout
   - the closeout batch proved permission snapshot refresh and finalization on a
     current-code validation run

Acceptance checks:

- a full all-app run completes and reconciles across:
  - report artifacts
  - canonical DB rows
  - bridge rows
  - Web latest-state surfaces
- stale pre-fix or partial-failure sessions can be purged cleanly by session
  label before re-run
- canonical vs bridge write timing is documented with current behavior, not
  assumed from older expectations
- no lingering `STARTED` rows remain after a successful all-app run
- archive-grade report retention works for fresh sessions
- session-label reuse, reset, and abort behavior are operator-safe
- the permission-governance queue bug remains fixed on fresh runs
- package identity drift is either repaired or explicitly quarantined
- `run.end` status and DB persistence outcome agree on fresh failure and
  success runs
- Web latest-session and cache surfaces refresh coherently after a fresh all-app
  run
- operator counts/messages match their actual data sources

Closeout note:

- the final trust proof for this phase is the current-code validation session
  `phase4a-closeout-smoke`
- that run exercises the previously broken seam without requiring another full
  `120`-app batch
- follow-on enhancements to timing detail or incremental persistence belong to
  later phases, not to keeping `4A` open

Do not:

- begin broader permission read redirection yet
- fold the static legacy bridge containment track into this phase

## Phase 4B. Redirect ScytaleDroid permission-reference reads

Goal:

- make ScytaleDroid consume permission meaning from the new seam, not direct
  operational DB tables

Status:

- completed

Preconditions:

- Phase 4A run lifecycle and reconciliation behavior are trusted enough that
  new permission-reader work will not hide active static batch defects
- the permission-intel provisioning/validation evidence remains green
- runtime-mode / environment behavior is stable enough for future validation
  runs to be repeatable

Execution order:

1. governance/read-only dictionary lookups
2. signal mapping/cohort expectation lookups
3. remaining permission reference reads

Completed implementation so far:

- governance/readiness status reads use seam helpers
- governance latest-loaded-at lookup uses the seam
- AOSP permission catalog and lookup helpers use the seam
- OEM/vendor permission dictionary helpers use the seam
- signal catalog read/update helpers use the seam
- shared permission-intel managed-table inventory is seam-owned and reused by:
  - schema gate
  - static reset protection
  - full reset protection
  - Phase 3 validation tooling
  - governance import tooling

Closeout interpretation:

- app-facing permission-reference reads now route through the seam
- governance, dictionary, vendor/meta, and signal-catalog reader families are
  cut over
- managed-table ownership is centralized in the seam and reused by tooling
- the remaining work is Phase 4C and later reporting/read-model cleanup, not
  first-wave permission-reference cutover

Keep local in ScytaleDroid DB:

- `permission_signal_observations`
- `permission_audit_snapshots`
- `permission_audit_apps`
- `static_permission_matrix`
- `static_permission_risk_vnext`

Acceptance checks:

- static runs still produce the same permission audit outputs
- governance/readiness screens still report the active snapshot cleanly
- no operator workflow exposes the new cross-database plumbing
- no new package-level or run-level regressions appear in permission-governance
  queueing or scoring outputs

## Phase 4C. Read-model and reporting cutover cleanup

Goal:

- finish the Phase 4 transition by cleaning up the read-model surfaces that sit
  between the permission-intel seam and later bridge-retirement work

Execution order:

1. move Web/reporting/static summary readers onto the intended stable views
2. reduce direct dependencies on compatibility-era static summary joins
3. document the remaining bridge-only compatibility surfaces before freeze work
4. keep cache freshness and report/export provenance aligned with the current
   latest completed session model

Current surfaces to stabilize:

- `v_web_app_directory`
- `v_web_static_dynamic_app_summary`
- direct latest-state reads over `permission_audit_apps`
- direct latest-state reads over `permission_audit_snapshots`
- direct latest-state reads over `static_findings_summary`

Acceptance checks:

- Apps Directory remains stable
- app overview/static findings/permissions tabs remain stable
- latest-state views stay correct after new static runs
- query performance remains acceptable for broad app listing and package detail
- no new reporting surface lands directly on legacy bridge tables without an
  explicit compatibility reason
- exported/static-report table paths remain clear and operator-usable
- cache refresh reflects the latest completed run without stale session bleed

Current closeout status:

- acceptance checks are satisfied on current code
- app/session summary surfaces now use stable Web-facing views
- latest usable completed session behavior is in place across app-level pages
- findings/components/permissions/strings surfaces have been moved behind
  stable `v_web_*` readers or equivalent centralized query helpers
- no new first-class reporting surface was added directly on legacy bridge
  tables during the closeout slice
- closeout evidence:
  - full static run `20260429-all-full`
  - closeout suite: `53 passed`

Phase 4 closeout note:

- `4A`, `4B`, and `4C` are complete
- remaining work belongs to the active Phase 5 lane, not to keeping Phase 4
  open

## Phase 5A. Bridge parity, collation cleanup, and reader inventory freeze

Goal:

- make the bridge landscape measurable and safe before any freeze or
  deprecation begins

This phase should begin only after:

- Phase 4A closes with trusted reconciliation/recovery behavior
- Phase 4B moves permission-reference reads behind the seam
- Phase 4C stabilizes the reporting/read-model layer

Work:

- stop new legacy reads first
- inventory all first-class readers still using:
  - `runs`
  - `findings`
  - `risk_scores`
  - `metrics`
  - `buckets`
  - `contributors`
  - `correlations`
  - `masvs_control_coverage`
- classify each as:
  - primary reader
  - compatibility-only reader
  - debug/ops-only reader
  - obsolete
- continue collation normalization for package identity joins on active bridge
  tables and views
- add parity checks for canonical vs bridge surfaces on fresh static sessions
- define the minimal replay/reconcile tooling required before any bridge freeze

Acceptance checks:

- every remaining bridge reader is explicitly classified
- active collation blockers for package joins are documented and prioritized
- canonical/bridge parity checks exist for fresh sessions
- no bridge freeze starts before replay/reconcile minimum tooling exists

Current status:

- complete
- closeout artifact:
  - reader/writer cleanup is now reflected in the active `Phase 5C` docs
- closeout evidence:
  - fresh-session parity proof on `20260429-all-full`
  - focused closeout suite `53 passed`
- explicit compatibility boundaries now in place:
  - `scytaledroid/Database/db_utils/static_reconcile.py`
  - `scytaledroid/Persistence/db_writer.py`

## Phase 5B. Bridge write isolation and canonical-first reader migration

Goal:

- reduce bridge dependence without breaking operators, Web, or debugging paths
- keep canonical tables and approved read models as the primary contracts

Work:

- migrate existing readers to canonical tables/views
- isolate remaining bridge writes in one narrow compatibility surface
- remove direct incidental reads of bridge tables from new CLI/reporting work
- prove session-level reporting can function without using bridge rows as the
  first-class source
- continue pruning bridge-first DB tool actions and wrapper/shim modules
- keep shrinking database-table sprawl by:
  - freezing duplicate authority
  - pruning stale sessions/artifacts
  - removing migration-era maintenance paths once no longer needed

Acceptance checks:

- no new first-class reader lands on bridge tables
- primary CLI/reporting flows are canonical-first
- bridge writes are isolated enough that freeze candidates can be assessed one
  surface at a time
- permission-intel shared/reference ownership is stable in the dedicated DB
- default DB operator surfaces no longer normalize bridge-first workflow

Phase 5B closeout readout:

- dedicated `android_permission_intel` cutover is complete
- duplicate managed permission-intel tables are frozen out of
  `scytaledroid_db_dev`
- `Persistence/compat_writer.py` has been removed
- `StaticAnalysis/cli/core/run_persistence.py` has been removed
- Query Runner, Recent Runs Dashboard, and default DB health paths now lead
  with canonical surfaces
- package-level DB/persistence shim exports have been reduced
- legacy `correlations` bridge write support has been removed

Phase 5B exit criteria are now satisfied:

- no new first-class reader lands on bridge tables
- primary CLI/reporting flows are canonical-first
- bridge writes are isolated enough that freeze candidates can be assessed one
  surface at a time
- permission-intel shared/reference ownership is stable in the dedicated DB
- default DB operator surfaces no longer normalize bridge-first workflow

Remaining work moves to Phase 5C:

- prune more bridge-heavy maintenance actions in `menu_actions.py`
- narrow `static_reconcile.py` toward parity-only output
- keep reducing database pain caused by mixed table roles and duplicate
  authority

Current bridge-table posture map:

| Table | Posture | Current intent |
| --- | --- | --- |
| `runs` | `compat_only_keep` | keep as compatibility linkage surface for now |
| `findings` | `compat_mirror_review` | retain as mirror while canonical finding readers continue to tighten |
| `metrics` | `compat_mirror_review` | retain as bridge mirror for scoring/backfill during transition |
| `buckets` | `compat_mirror_review` | retain as bridge-era risk bucket mirror during transition |
| `contributors` | `compat_mirror_review` | retain as bridge-era contributor mirror during transition |
| `risk_scores` | `derived_review` | still used operationally, but treat as derived rather than canonical truth |
| `correlations` | `freeze_candidate` | legacy bridge writer removed; best first narrow freeze/drop candidate |

This posture is now encoded in:

- `scytaledroid/Database/db_utils/bridge_posture.py`

## Phase 5C. Narrow freeze and deprecation prep

Goal:

- begin retiring low-risk bridge surfaces in a controlled order after 5B
  proves parity and reader safety
- clean up remaining database/table debt that still blocks simpler contracts

First freeze candidates:

- `correlations`
- `masvs_control_coverage`

Do not target first:

- `runs`
- `findings`
- `metrics`
- `buckets`
- `risk_scores`

Acceptance checks:

- narrow freeze candidates are proven unused or compatibility-only
- bridge timing and canonical/legacy parity are documented well enough for
  later freeze planning
- replay/reconcile tooling exists for sessions whose report artifacts outlive
  partial DB state
- frozen bridge surfaces can be disabled without breaking normal operator paths

Likely 5C database work:

- freeze/prune remaining empty or low-owner tables after dependency review
- keep reducing bridge-specific maintenance utilities
- tighten score lineage and snapshot linkage
- simplify mixed-role table ownership where the same meaning still exists in
  more than one place
- ensure Web-facing `v_web_*` surfaces cover the remaining analyst pages so
  direct internal joins continue to shrink

## Phase 6. Research Surface Maturity On Stable Contracts

Goal:

- use the stabilized canonical/read-model/database contracts to build cleaner
  research and analysis surfaces
- stop Phase 6 from inheriting Phase 5 database confusion

Preconditions:

- ScytaleDroid permission-reference reads use the dedicated permission-intel DB
- major analyst-facing pages have stable session/data-state/read-model behavior
- Phase 5 bridge/debt cleanup is far enough along that Phase 6 work does not
  need to preserve old bridge assumptions
- migration validation and soak are complete

Planned order:

1. Research Dashboard
2. Findings Explorer maturity
3. Component Exposure maturity
4. Permission Intelligence maturity
5. Static/Dynamic comparison with match quality
6. Version/drift analysis

Phase 6 focus areas:

- recurring platform/security pattern discovery across real device app fleets
- better component exposure analysis
- clearer permission intelligence and capability clusters
- trustworthy static/dynamic comparison with explicit match quality
- longitudinal drift/version analysis once session/version lineage is stable

This phase is explicitly not part of the current milestone.

## Phase 7. Post-cutover hardening and retirement

Goal:

- complete the cleanup after the bridge/read-model transition is proven stable

Examples:

- remove obsolete compatibility-only helpers
- narrow old mirrors/views further
- finalize operator/runtime docs around the post-cutover state
- retire remaining transitional assumptions once proven unused
- reduce temporary audit/reporting scaffolding that existed only to shepherd
  the Phase 4 and Phase 5 transition

## Big issues still governing the plan

These are the major open issues that can still force plan adjustments:

1. Database table role sprawl
   - the main DB still mixes:
     - canonical run outputs
     - derived/reporting tables
     - Web read models
     - compatibility bridge tables
     - legacy/empty artifacts
   - this is now one of the biggest sources of complexity and pain

2. Package-name collation drift
   - core tables still span `utf8mb4_unicode_ci`, `utf8mb4_general_ci`, and
     some legacy `latin1_swedish_ci`
   - this is still a schema hazard for new joins and views

3. Static compatibility bridge is still active
   - `runs`, `findings`, `metrics`, `buckets`, `contributors`,
     `correlations`, and `masvs_control_coverage` are still being dual-written
   - reader migration is progressing, but the bridge is not retired
   - current all-app timing is now understood, but the bridge is still active
     and must not be retired before replay/reconcile and read-model cleanup are
     stronger

4. Dynamic evidence retention is weak in the current workspace
   - local evidence was cleaned locally, so feature rebuildability is poor
   - dynamic run history exists in DB, but many runs cannot currently be
     reindexed from disk here

5. Cross-analysis view performance
   - broad scans on `v_web_static_dynamic_app_summary` still rely on derived
     tables, temp tables, and filesorts
   - this is acceptable for filtered/package-level use, but still risky for
     broad dashboard-style reads

6. Interrupted-run UX still needs one more tightening pass
   - the worst trailing output is gone
   - but the partial static summary itself is still longer than ideal for an
     interrupted run

7. Static package identity still has edge-case drift
   - package case mismatches still exist in some report/DB surfaces
   - this remains a correctness and provenance risk for replay, joins, and
     audit tools

8. The pipeline is still scan-first and memory-heavy for large batches
   - the current design has now been proven to work
   - but incremental canonical persistence may still be the safer future model

## Recommended execution order now

1. finish the highest-ROI `5B` prune/isolation work
   - bridge-heavy DB actions
   - `static_reconcile.py` narrowing
   - bridge table posture map
2. use `5C` for database/table cleanup that reduces mixed ownership and stale
   support burden
3. keep hardening Web read models and score/session/data-state contracts while
   `5B/5C` land
4. only start major Phase 6 research-surface work after the DB/read-model
   picture is stable enough that new pages do not inherit old bridge debt
5. treat Phase 6 as research capability work, not as a place to hide unresolved
   database cleanup

## Hard rules

- do not drop permission tables from `scytaledroid_db_dev` this week
- do not require the Web app to understand two databases this week
- do not expand legacy static bridge writes
- do not treat `permission_audit_*` or `static_findings_summary` removal as a
  prerequisite for the permission-intel split
- do not assume per-app findings/risk rows should appear during the scan loop
  of a large all-app batch until Phase 4A documents the actual timing boundary
