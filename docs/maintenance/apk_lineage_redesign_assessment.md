# APK Lineage Redesign Assessment

**Status:** design assessment from the exact-hash static workflow investigation  
**Date:** 2026-05-13  
**Scope:** APK identity, split install sets, byte availability, harvest provenance, static/dynamic coverage

## Summary

The exact-hash workflow failure on `com.whatsapp` / `apk_id=2578` is not a static-analysis failure. It exposed a model gap:

- The database knows many package/version/hash identities.
- The current canonical store only has a subset of the corresponding APK bytes.
- Historical `local_rel_path` values point at missing or legacy roots.
- `apk_split_groups` is package-level grouping, not an exact install-set identity.
- Static and dynamic rows already carry `base_apk_sha256` and `artifact_set_hash`, but there is no durable `apk_set` / `install_set` table to make that identity first-class.

The better long-term organizing model is:

```text
application package
  -> app version / build identity
  -> APK content hash / split install set hash
  -> observations from harvests/devices
  -> byte availability
  -> static analyses
  -> dynamic sessions
  -> coverage and drift comparisons over time
```

Harvest runs and device paths remain important provenance. They should not be the primary identity.

## Evidence From The Current Catalog

Observed in `scytaledroid_core_prod` on 2026-05-13:

| Surface | Current state |
| --- | --- |
| `apps` | 570 package rows; good package identity start. |
| `app_versions` | 662 version rows; useful but incomplete linkage from APK observations. |
| `android_apk_repository` | 2693 rows; unique `sha256`, but also mixes observation fields such as `device_serial`, `harvested_at`, and split group id. |
| `apk_split_groups` | 115 rows; `package_name` is unique, so this is package-level grouping, not an exact base+split install set. |
| `harvest_artifact_paths` | 2693 rows; one path per `apk_id`, but many paths are stale or rooted in missing legacy directories. |
| `static_analysis_runs` | Already has `base_apk_sha256`, `artifact_set_hash`, `run_signature`, `identity_valid`, `static_handoff_hash`. |
| `dynamic_sessions` | Already has `base_apk_sha256`, `artifact_set_hash`, version fields, and `static_handoff_hash`. |

The package/version/hash availability report currently shows:

```text
packages: 118
hashes_seen: 632
bytes_available: 118
missing_bytes: 514
static_covered_hashes: 250
dynamic_covered_hashes: 32
exact_dynamic_static_gaps: 31
app_version_missing_pairs: 102
```

For `com.whatsapp`:

```text
versions=10
hashes=10
bytes=1/10
static=3/10
dynamic=2/10
exact_dynamic_static_gaps=2
recommended_action=restore_artifacts
```

The exact target `a4979001dd3bbe1dee1e21590e374c4d423200161d1565b85738ebe2996b62da` is known by the DB and dynamic sessions, but neither its recorded file nor canonical SHA-store file is present. The safe recommendation is `restore_artifacts` or explicit reharvest, not static analysis.

## Current Design Gap

The current model is close, but it has a split-brain identity problem:

```text
android_apk_repository
  acts partly like content identity
  acts partly like harvest observation
  acts partly like split grouping
  acts partly like storage path lookup
```

That overloading causes operator ambiguity:

- A row may exist even when bytes are gone.
- A package may have split rows without a reliable exact install-set row.
- A stale `local_rel_path` can look actionable until byte verification fails.
- Static queueing can accidentally sound like "needs analysis" when it actually needs "restore bytes first."

## Target Model

Use the naming already drafted in `docs/design/v1_evidence_catalog_verification.md` and reconcile it with `docs/storage_contract_v2.md`.

### `apks`

One row per unique APK file content.

```text
apk_id
sha256
sha1
md5
file_size
artifact_kind          base | split | config | unknown
canonical_relpath
first_seen_at
last_seen_at
availability_state     available | missing | archived | external
```

Same bytes must resolve to the same `apk_id`. Paths are storage metadata, not identity.

### `app_versions`

One row per package/version identity.

```text
app_version_id
app_id
package_name
version_code
version_name
min_sdk
target_sdk
signer_fingerprint
first_seen_at
last_seen_at
```

The existing table is usable, but the ingest path should make version linkage complete and deterministic.

### `apk_sets`

One row per observed install set: base APK plus the split APK members that define the installed app.

```text
apk_set_id
app_version_id
package_name
version_code
version_name
base_apk_id
base_apk_sha256
artifact_set_hash
artifact_set_hash_version
member_count
split_count
completeness_state      complete | base_only | partial | unavailable
first_seen_at
last_seen_at
```

This is the missing durable identity surface.

### `apk_set_members`

One row per base/split member in an install set.

```text
apk_set_id
apk_id
role                    base | split
split_name
sha256
source_path
member_status           pulled | missing | skipped | failed | unavailable
ordinal
```

Static and dynamic analysis should eventually point at `apk_set_id`, not only free-text package/version/hash columns.

### `harvest_sessions`

One row per harvest event.

```text
harvest_session_id
session_label
device_serial
inventory_snapshot_id
started_at
ended_at
status
```

This preserves the run folder as provenance.

### `harvest_apk_observations`

One row per package/member observation or pull attempt in a harvest session.

```text
observation_id
harvest_session_id
apk_set_id              nullable until set is complete enough to resolve
apk_id                  nullable when bytes were not pulled
package_name
version_code
version_name
role
split_name
source_path
recorded_local_relpath
canonical_relpath
pull_status             pulled | missing | skipped | failed
error_code
```

This separates "we saw or attempted this" from "we possess bytes for this content hash."

## Artifact Set Hash Contract

The current static identity helper computes `artifact_set_hash` from:

```text
base APK first
then split APK hashes sorted by split_name
payload = JSON list of sha256 values
artifact_set_hash = sha256(payload)
run_signature_version = v1
```

Keep this as compatibility `artifact_set_hash_version='v1'` because static and dynamic rows already use it.

For a future `v2`, include split names and roles in the hash payload:

```json
[
  {"role": "base", "split_name": "base", "sha256": "..."},
  {"role": "split", "split_name": "config.arm64_v8a", "sha256": "..."}
]
```

The v2 form is more self-describing and avoids two different split-name layouts collapsing to the same list of hashes.

## What Can Be Deleted Or Rebuilt

Deletion should still be staged with receipts, but the project can be more aggressive if the goal is to rebuild a cleaner dev catalog.

### Safe To Rebuild After Snapshot

These are derived or index-like and can be regenerated if raw bytes/evidence remain:

- availability cache tables or reports
- package/version/hash coverage reports
- static queue rows
- exact-target readiness receipts from failed preflights
- stale harvest path rows after replacement observations exist
- stale `dynamic_sessions.static_run_id` links, if recomputed by exact hash and receipt

### Rebuildable But Expensive

These can be deleted and rerun, but only after an export/receipt because rerunning costs time and may not reproduce the exact app build:

- `static_analysis_runs` and child static tables
- static JSON/HTML outputs
- static handoff artifacts
- dynamic/static link fields

### Do Not Delete Blindly

These are primary evidence or irreplaceable local bytes:

- APK payloads under `data/store/apk/sha256`
- current harvest APK payloads under `data/device_apks/.../runs`
- dynamic evidence packs under `data/evidence/dynamic`
- raw PCAPs, logs, run events
- finding evidence payloads
- harvest receipts and package manifests

If the user chooses a full dev reset, take DB and filesystem receipts first, then rebuild from current canonical bytes and reharvest current installed versions. Historical missing hashes cannot be recreated unless the old APK bytes are restored from backup or re-downloaded exactly.

## Recommended Migration Path

### Phase 0: Read-Only Clarity

Already started:

- exact-target resolver verifies local bytes and refuses fallback
- exact-target readiness distinguishes `needs static analysis` from `needs artifact restore/reharvest`
- package/version/hash lineage report groups by package first

Next read-only additions:

- Add a menu entry for the package lineage report under APK Library or Database Tools.
- Add JSON output suitable for a future package dashboard.
- Add an explicit "current bytes available" column wherever exact static worklists are displayed.

### Phase 1: Add Install-Set Schema Additively

Create new tables without deleting existing rows:

```text
apks or apk_blobs
apk_sets
apk_set_members
harvest_sessions
harvest_apk_observations
```

If renaming `android_apk_repository` is too disruptive, keep it as a compatibility view or bridge while new writes target the clearer tables.

### Phase 2: Backfill From Existing Evidence

Backfill in this order:

1. Canonical store files: hash bytes into `apks`.
2. Harvest receipts/manifests: create observations and install-set members.
3. Existing `android_apk_repository`: import historical identities, marking missing bytes as unavailable.
4. Static runs: link by `base_apk_sha256` and `artifact_set_hash`.
5. Dynamic sessions: link by `base_apk_sha256` and `artifact_set_hash` where exact.

Missing payloads should remain visible as `availability_state=missing`, not silently dropped, until a deliberate reset removes historical unavailable identities.

### Phase 3: Queue Static By Hash/Set

Static queueing should become:

```text
for each apk_set:
  if bytes unavailable:
    recommended_action = restore_artifacts / reharvest
  elif no completed canonical static run for apk_set_id or exact base hash:
    recommended_action = run_static
  elif dynamic sessions exist without exact static link:
    recommended_action = link_repair_preview
  else:
    recommended_action = covered
```

Do not queue by package name alone.

### Phase 4: Dynamic/Static Link Repair Receipts

When exact static runs exist, repair should be receipt-first:

```text
dynamic_run_id
package_name
base_apk_sha256
artifact_set_hash
candidate_static_run_id
candidate_static_handoff_hash
match_basis
decision
reason
created_at
```

Apply only when there is exactly one safe candidate.

### Phase 5: Reset/Prune Legacy Path Debt

After the additive model is populated and verified:

1. Export old `android_apk_repository`, path tables, and split groups.
2. Run lineage and availability reports before cleanup.
3. Delete or archive stale path-only rows whose payloads are unavailable and whose identity is represented in the new model.
4. Keep historical missing identities only if they still matter for longitudinal research.
5. Reharvest current app builds to repopulate available byte coverage.

## Operator-Facing North Star

The operator should be able to start from a package:

```text
Show me com.whatsapp.
  versions observed
  base hashes observed
  split install sets observed
  which bytes are available
  which have static analysis
  which have dynamic evidence
  which exact hashes need analysis
  which exact hashes need restore/reharvest first
```

The dated harvest run should be one drilldown column, not the primary menu.

## Immediate Recommendation

Do not batch the remaining exact-hash static worklist yet. The readiness audit shows the current blocker is byte availability, not static execution.

The next implementation step should be either:

1. Add the package/version/hash lineage report to an operator menu, then use it to guide restore/reharvest decisions.
2. Add additive `apk_sets` / `apk_set_members` schema and backfill from current receipts/canonical store.

If the goal is to make the tool cleaner quickly on this development system, prefer additive schema plus controlled reset over more repair scripts against stale path rows.

## Implementation Status

First additive slice implemented on 2026-05-13:

```text
harvest_sessions
apk_sets
apk_set_members
harvest_apk_observations
v_apk_set_coverage_v1
```

Backfill source:

```text
data/receipts/harvest/*/*.json
```

Backfill rule:

```text
Use receipt-backed observed_artifacts only.
Require exactly one base member.
Require SHA-256 for every member.
Compute artifact_set_hash with current static identity v1.
Do not infer exact split membership from package-level apk_split_groups.
```

Current local DB result after applying `scripts/db/backfill_apk_sets_from_receipts.py --apply`:

```text
harvest_sessions = 2
apk_sets = 144
apk_set_members = 531
harvest_apk_observations = 1062
complete apk_sets = 144
```

Receipt processing saw 288 package receipts with observed artifacts. Those collapsed into 144 unique install sets because both harvest sessions observed the same set identities for many packages. This is expected and confirms the install-set hash is deduplicating package identity across harvest sessions.

`v_apk_set_coverage_v1` currently reports:

```text
apk_sets = 144
sets_with_canonical_static = 144
sets_with_dynamic = 1
exact_dynamic_static_gaps = 0
```

That does not contradict the base-hash dynamic/static worklist. The 31 exact dynamic/static gaps are older dynamic base hashes whose bytes are missing from local storage, so they are not yet represented as receipt-backed available `apk_sets`.

Second additive slice implemented on 2026-05-13:

```text
static_analysis_runs.apk_set_id
dynamic_sessions.apk_set_id
scripts/db/backfill_apk_set_links.py
```

Backfill rule:

```text
Only fill apk_set_id when artifact_set_hash has exactly one apk_sets match.
Do not update dynamic_sessions.static_run_id.
Do not infer links by package name, version code, or newest capture.
```

Current local DB result:

```text
static_analysis_runs linked to apk_sets = 861
dynamic_sessions linked to apk_sets = 2
v_static_handoff_v1 rows with apk_set_id = 800
ambiguous artifact_set_hash matches = 0
dynamic/static link repair still not applied
```

Third additive slice implemented on 2026-05-13:

```text
scytaledroid.Database.db_func.harvest.install_sets
harvest runner direct dual-write to install-set spine
APK Library menu action for package lineage / byte-static-dynamic coverage
```

New harvest behavior:

```text
Filesystem harvest remains primary.
Existing android_apk_repository / path mirror writes remain intact.
When DB writes are enabled, completed package pulls also upsert:
  harvest_sessions
  apk_sets
  apk_set_members
  harvest_apk_observations
Install-set write failures are logged as optional mirror warnings and do not
downgrade the existing harvest package result.
```

Operator access:

```text
Main Menu -> APK library -> Package lineage and byte/static/dynamic coverage
```

Fourth additive slice implemented on 2026-05-13:

```text
scripts/db/report_apk_lineage_availability.py --design-checks
```

This is a read-only package-first report. It keeps harvest folders as
provenance and summarizes each package by observed versions, base hashes,
receipt-backed install sets, byte availability, exact static coverage, dynamic
coverage, and recommended action.

Current local DB result:

```text
packages = 118
hashes_seen = 632
install_sets_seen = 118
bytes_available = 118
missing_bytes = 514
static_covered_hashes = 250
dynamic_sessions = 142
dynamic_exact_static_linked = 2
exact_dynamic_static_gaps = 31
```

Example package drilldown:

```text
com.whatsapp
  versions = 10
  base hashes = 10
  receipt-backed install sets = 1
  bytes = 1/10
  static = 3/10
  dynamic sessions = 13
  exact dynamic/static gaps = 2
  action = restore_artifacts
```

## Current Design Answers

1. `apk_sets` now represents exact receipt-backed install-set identity for the
   captures that can be reconstructed from harvest receipts. It does not yet
   represent every historical repository row, especially missing old bytes.
2. `artifact_set_hash` is stable for the v1 rule currently in use: base SHA-256
   first, then split SHA-256 values in deterministic split/member order. Keep
   `artifact_set_hash_version='v1'` for compatibility.
3. `static_analysis_runs.apk_set_id` is partially populated from exact
   `artifact_set_hash` matches. In the current local DB, `861/1294` static rows
   have `apk_set_id`. `dynamic_sessions.apk_set_id` is populated only where the
   dynamic row already matches a receipt-backed set; currently `2/142`.
4. Same package/versionCode with different base hash is detectable and currently
   present. The report exposes this as `same_version_hash_changed_review`.
5. Same base hash with different split-set hash is detectable through `apk_sets`;
   the current local DB reports no such cases.
6. Historical `android_apk_repository` identities are intentionally retained
   even when bytes are missing. Missing bytes are an availability state, not DB
   corruption by themselves.
7. The canonical SHA store is the intended stable byte source going forward.
   Harvest paths are provenance and recovery hints.

Fifth additive slice implemented on 2026-05-13:

```text
scripts/db/report_dynamic_static_recovery_plan.py
scripts/db/report_apk_lineage_availability.py --drift-details
```

This is a read-only recovery/reharvest planner for the exact dynamic/static
gaps. It starts from the dynamic worklist, then classifies each exact hash by
byte availability and recovery action. Missing bytes remain an availability
state, not DB corruption.

Current local DB result:

```text
exact_gap_hashes = 31
dynamic_sessions_affected = 140
restore_old_root = 30 hashes / 139 dynamic sessions
explicit_reharvest_needed = 1 hash / 1 dynamic session
analyze_exact_static_available = 0
```

The old-root restore bucket points at:

```text
/home/secadmin/Documents/CARS2025/Dev/ScytaleDroid/data/device_apks
```

The one explicit reharvest row points at the current repo root but the exact
recorded APK bytes are missing there as well:

```text
com.google.android.apps.messaging
base_apk_sha256 = a43fd1b306818c2d48baa3f9fbba216dcdb16e701ac868271f930376be83b519
```

Same-version/different-base-hash review is now exposed as a report detail. The
current local DB has 12 version-code/name buckets with more than one base hash.
These are review signals, not automatic failures; staged rollouts, rebuilds,
system app variants, and metadata quality can all produce legitimate cases.

Sixth additive slice implemented on 2026-05-13:

```text
scripts/db/report_static_analysis_targets.py
APK Library -> Static analysis target queue (read-only)
```

This is the first queue-like operator read model over package lineage. It does
not create a writable queue table. It derives target rows from known
package/version/base-hash identities and annotates each with:

```text
reason
byte_status
split_status
priority
target_status
operator_action
```

Current local DB result with `--only-actionable`:

```text
targets = 524
dynamic_sessions_on_targets = 140

blocked_missing_bytes = 285
needs_reharvest = 229
review = 10

dynamic_static_gap = 31
new_hash_seen = 336
same_version_hash_drift_review = 26
```

For `com.whatsapp`, the queue makes the operator distinction explicit:

```text
a497...  dynamic=10  static=0  bytes=missing_old_root
  status=blocked_missing_bytes
  reason=dynamic_static_gap
  action=Restore old root

da81...  dynamic=0  static=5  bytes=available_recorded_and_canonical
  status=covered
  action=No action needed
```

`apk_set_id` is treated as the preferred spine when present, while
`base_apk_sha256` remains the historical fallback for rows that cannot yet be
linked to a receipt-backed install set.

Seventh additive slice implemented on 2026-05-14:

```text
scripts/db/report_package_lineage_workbench.py
APK Library -> Package lineage workbench
```

This is the first package-first operator workbench. It consolidates the package
lineage, byte availability, static coverage, dynamic coverage, pairing, and
action semantics into one read-only package view.

For `com.whatsapp`, the current local DB result is:

```text
versions_seen = 10
base_hashes_seen = 10
install_sets_seen = 1
bytes_available = 1
static_covered = 3
dynamic_covered = 2
dynamic_sessions = 13
dynamic_exact_static_links = 0
exact_static_dynamic_gaps = 2
recommended_next_action = restore_artifacts
```

The workbench deliberately keeps these states separate:

```text
known APK identity
available APK bytes
static analyzed
dynamic captured
static/dynamic paired by exact identity
```

Rows can therefore show, for example, `static=covered` but
`bytes=no:missing_current_root_file`, which means the historical analysis exists
but the artifact lifecycle still needs reharvest/restore attention.

Eighth additive slice implemented on 2026-05-14:

```text
new static run writes propagate apk_set_id when artifact_set_hash uniquely
matches apk_sets
dynamic plans include apk_set_id in run_identity
new dynamic session writes persist apk_set_id when the selected handoff carries it
evidence-pack reindex preserves apk_set_id from static_dynamic_plan.json
```

This strengthens `apk_set_id` as the exact install-set spine for new evidence
without forcing historical backfills or dynamic link repair. The matching rule is
intentionally conservative:

```text
artifact_set_hash must match exactly one apk_sets row
ambiguous or missing matches write NULL
no package-name, version-code, or newest-capture fallback
```

Historical rows still rely on `base_apk_sha256` / `artifact_set_hash` fallback
until explicit preview/apply backfills are run.

Ninth additive slice implemented on 2026-05-14:

```text
scripts/db/report_dynamic_static_recovery_plan.py --write-receipt
APK Library -> Write artifact recovery plan receipt
data/receipts/artifact_recovery_plans/<timestamp>_all.json
```

This writes a non-destructive artifact recovery plan receipt for exact
dynamic/static gaps. The receipt records the current package/hash recovery
classification and keeps the decision explicit:

```text
decision = plan_only_no_apply
no DB updates
no APK moves/deletes
no static runs
no dynamic link repair
```

Current generated receipt:

```text
data/receipts/artifact_recovery_plans/20260514T065329_all.json
exact_gap_hashes = 31
dynamic_sessions_affected = 140
restore_old_root = 30 hashes / 139 dynamic sessions
explicit_reharvest_needed = 1 hash / 1 dynamic session
```

Tenth additive slice implemented on 2026-05-14:

```text
Package lineage workbench and static target queue now distinguish:
  static missing + bytes missing -> static/recovery target
  static covered + bytes missing -> artifact_lifecycle_gap
```

This prevents static-covered rows from being presented as static-analysis gaps
just because their local APK bytes are missing. For example, WhatsApp now shows
older covered hashes with:

```text
static=covered(...) bytes=no:missing_current_root_file
action=restore_artifacts
reason=artifact_lifecycle_gap
```

Eleventh additive slice implemented on 2026-05-14:

```text
scripts/db/report_dynamic_static_recovery_plan.py --old-root-policy restore
scripts/db/report_dynamic_static_recovery_plan.py --old-root-policy unrecoverable
APK Library -> Write artifact recovery plan receipt
```

The artifact recovery plan now has root-level grouping and an explicit policy
switch for missing legacy roots:

```text
default restore policy:
  exact_gap_hashes = 31
  restore_old_root = 30 hashes / 139 dynamic sessions
  explicit_reharvest = 1 hash / 1 dynamic session
  ready_for_exact_static_analysis = 0

unrecoverable policy:
  exact_gap_hashes = 31
  unrecoverable_without_external_archive = 30 hashes / 139 dynamic sessions
  explicit_reharvest = 1 hash / 1 dynamic session
  ready_for_exact_static_analysis = 0
```

This keeps the next operator decision explicit:

```text
restore/mount old root if available
otherwise treat exact historical builds as unavailable unless an external
archive can supply the exact bytes
```

Twelfth additive slice implemented on 2026-05-14:

```text
scripts/db/report_package_lineage_workbench.py
  --only-actionable
  --hash-limit N
  --show-paths
```

The package lineage workbench now separates full package coverage from the
visible row set. Package-level counts always describe the whole package, while
visible action/availability summaries describe the current filtered view.

For `com.whatsapp --only-actionable`, the current local result is:

```text
Coverage Summary:
  versions_seen = 10
  base_hashes_seen = 10
  bytes_available = 1/10
  static_covered = 3/10
  row_filter = actionable (9/10)

Visible Action Summary:
  restore_artifacts = 8
  reharvest_required = 1
```

This makes the workbench more usable as the operator front door for
package/version/hash/install-set lineage without changing DB state.

## Next Heavy Lifts

1. **Artifact restore decision.** Decide whether the old root can be mounted or
   copied back. If yes, restore and rerun the recovery plan; if no, decide which
   historical identities should remain as missing lineage versus be reset from
   a dev-system cleanup plan.
2. **Package dashboard/menu surface.** The current menu launches a report. The
   next UI pass should make package -> versions -> hashes/install sets -> action
   a navigable operator flow.
3. **Receipt-first dynamic link preview.** After exact static coverage exists,
   repair can require exact base hash and, where present, exact `apk_set_id` /
   `artifact_set_hash`; apply remains a later explicit step.
4. **Controlled reset/prune.** After new writes and coverage reports are stable,
   stale path-only rows can be archived or deleted from the dev DB with a
   receipt-backed export. Do not drop historical missing identities until deciding
   whether longitudinal absence is useful.
