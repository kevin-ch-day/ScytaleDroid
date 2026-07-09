# Inventory Contract Matrix

Repo scope:
- `scytaledroid/DeviceAnalysis/inventory/package_collection.py`
- `scytaledroid/DeviceAnalysis/package_info.py`
- `scytaledroid/DeviceAnalysis/inventory/adb_bulk.py`
- `scytaledroid/DeviceAnalysis/inventory/adb_client.py`
- `scytaledroid/DeviceAnalysis/inventory/normalizer.py`
- `scytaledroid/DeviceAnalysis/inventory/runner.py`
- `scytaledroid/DeviceAnalysis/inventory/models.py`
- `scytaledroid/DeviceAnalysis/inventory/snapshot_io.py`
- `scytaledroid/DeviceAnalysis/inventory/db_sync.py`
- `scytaledroid/DeviceAnalysis/harvest/models.py`
- `scytaledroid/DeviceAnalysis/harvest/scope.py`
- `scytaledroid/DeviceAnalysis/harvest/scope_context.py`
- `scytaledroid/DeviceAnalysis/harvest/planner.py`
- `scytaledroid/DeviceAnalysis/device_menu/inventory_guard/**`
- `scytaledroid/DeviceAnalysis/apk/delta.py`

Purpose:
- Freeze the effective inventory row contract before optimizing collection strategy.
- Separate identity fields from planning, policy, display, and diagnostic fields.
- Define the first safe optimization boundary: all packages vs harvest/static-relevant packages.

## Key findings

1. Full-device inventory cost is dominated by per-package `pm path` and `pm dump` calls in `package_collection.collect_inventory()`. Snapshot persistence and DB sync are cheap.
2. The persisted row contract is defined by `normalizer.compose_inventory_entry()`, not by raw ADB output.
3. Harvest execution narrows that contract again through `harvest.scope_context.build_inventory_rows()` into `harvest.models.InventoryRow`.
4. Freshness-by-age is independent from package drift.
5. Package drift is driven primarily by normalized `package_name` plus `version_code`.
6. `version_name` is best-effort metadata today. It is not required for drift identity, but it is used in display and delta summaries.
7. `apk_paths` and `split_count` are operationally critical for harvest/static-relevant packages, but no evidence was found that every policy-blocked system/OEM package must have full split fidelity during a fast inventory mode.

## Effective row schema

Primary persisted package keys produced by `normalizer.py`:
- `package_name`
- `app_label`
- `version_name`
- `version_code`
- `installer`
- `first_install`
- `last_update`
- `primary_path`
- `category`
- `category_name`
- `category_id`
- `partition`
- `source`
- `profile_key`
- `profile_id`
- `profile_name`
- `publisher_key`
- `publisher_name`
- `category_source`
- `profile_source`
- `publisher_source`
- `split_flag`
- `apk_paths`
- `apk_dirs`
- `review_needed`
- `inferred_category`
- `inferred_profile`
- `owner_role`
- `split_count`

Top-level snapshot keys persisted by `snapshot_io.py`:
- `generated_at`
- `device_serial`
- `snapshot_id`
- `snapshot_type`
- `snapshot_variant`
- `scope_hash`
- `package_count`
- `package_hash`
- `package_list_hash`
- `package_signature_hash`
- `build_fingerprint`
- `duration_seconds`
- `collection_mode`
- `identity_source`
- `identity_quality`
- `path_enriched_packages`
- `bulk_identity_only_packages`
- `packages`

## Contract matrix

| Field | Snapshot schema key? | Current source | Candidate fast-path source | Downstream consumers | Contract level | Needed during inventory vs eventually | Required for all packages vs relevant only | Fast-mode behavior | Full diagnostic behavior | Risk if changed | Existing tests | Missing tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `package_name` | Yes; `packages[*].package_name`, `package_list_hash`, guard/delta readback | bulk list or per-package list, normalized in `package_collection`/`snapshot_io` | `pm list packages --show-versioncode` or `-f -i -U --show-versioncode` | snapshot delta, freshness drift, harvest planning, DB `apps` sync, APK library reload, static scope selection, dynamic handoff | identity-critical | needed during inventory and later | all packages | must be populated for all packages | same | Breaks joins, hashes, delta, harvest, static, dynamic | `tests/inventory/test_package_collection_normalizer.py`, `tests/device_analysis/test_inventory_guard_metadata_loader.py` | add persistence round-trip test for normalized names |
| `version_code` | Yes; `packages[*].version_code`, `package_hash`, guard identity compare | `pm list packages --show-versioncode`; copied into normalized row | bulk `pm list ... --show-versioncode` | snapshot delta, freshness drift, harvest filename/capture naming, static/dynamic identity | identity-critical | needed during inventory and later | all packages, especially relevant packages | must be populated for all packages where available; fallback nullable only when device truly cannot provide | same | Wrong APK identity, wrong drift detection, wrong dynamic freeze joins | harvest runner tests, static/dynamic suites rely on version code widely | add explicit loader test that version-code change flips `packages_changed` |
| `version_name` | Yes; `packages[*].version_name`, `package_hash` | `pm dump` best-effort | nullable/best-effort, previous snapshot fallback, APK/static analysis later | display/UI, delta summary text, artifact directory naming | display-only with snapshot-compat weight | not needed during inventory for correctness; useful later | all packages optional, relevant packages helpful | may be null | still populate in full diagnostic mode from `pm dump` | Mostly affects display and path names, not core identity | static reporting tests indirectly, no direct inventory contract test | add test that version-name-only change does not set `packages_changed` |
| `primary_path` | Yes; `packages[*].primary_path`, `package_hash` | `pm path` first element; fallback `pm list packages -f` only when `pm path` fails | `pm list packages -f --show-versioncode` base path for all packages, targeted `pm path` for relevant packages | user/system classification, policy filtering, harvest row narrowing, default scope, APK library | planning-critical, policy-critical | needed during inventory for scope/policy; later for harvest | all packages should have a base path; full split fidelity mainly relevant packages | must be populated for all packages if possible | `pm path` remains canonical in full mode | Misclassifies user/system apps, breaks scope math and harvest eligibility | `tests/harvest/test_scope_context.py`, dashboard/scope tests indirect | add fast-mode fallback test using only base path |
| `apk_paths` | Yes; `packages[*].apk_paths` | `pm path` | targeted `pm path` for harvest/static-relevant packages; nullable/degraded for blocked packages only if consumers allow | harvest planning, path policy filtering, split capture fidelity, static exact-target prep | planning-critical | needed during inventory for relevant packages; not proven necessary for every blocked package | harvest/static-relevant packages | requires targeted enrichment | full mode must populate via `pm path` | Missing split members causes wrong artifact counts and incomplete harvests | `tests/device_analysis/test_harvest_runner.py`, `tests/harvest/test_scope_context.py` | add test for consumers tolerating sparse `apk_paths` on blocked packages |
| `split_count` | Yes; `packages[*].split_count` | derived from `len(apk_paths)` | derived from targeted `pm path`; fallback `1` only when no split data | harvest planning, static menus, UI estimates | planning-critical | needed during inventory for relevant packages; later for harvest/static | relevant packages | requires targeted enrichment | full mode from `pm path` | Wrong artifact estimate and incomplete static/harvest selection | static/harvest tests indirect | add explicit split-count contract tests |
| `apk_dirs` | Yes; `packages[*].apk_dirs` | derived in `normalizer.py` from `apk_paths` | derived internally after targeted path enrichment | diagnostic/UI only | diagnostic-only | eventual only | relevant packages optional | may be null or deferred | populate in full mode if `apk_paths` known | Low operational risk | no direct tests found | add none initially |
| `path_fidelity` | Yes; `packages[*].path_fidelity` | derived in `normalizer.py` from collection metadata | derived internally (`pm_path` vs `bulk_base_only`) | dashboard/logging/debuggability, future fast-mode-aware consumers | diagnostic-only, snapshot compatibility field | inventory only, but useful later for interpretation | all packages | should be populated in fast mode | full mode should emit `pm_path` | Without it, lower-fidelity bulk rows can be mistaken for split-complete rows | `tests/inventory/test_package_collection_normalizer.py` | add dashboard/guard wording tests only if UI starts surfacing this field |
| `collection_mode` | Yes; top-level snapshot key and meta | runner/collector mode selection | derived internally from selected sync mode (`baseline`, `bulk`, etc.) | dashboard, guard formatting, operator reasoning, future policy forks | snapshot compatibility field | inventory and later | all snapshots | must be populated so `FRESH` snapshots can be interpreted correctly | same | Fast snapshots can be mistaken for full diagnostic snapshots | `tests/inventory/test_inventory_runner.py`, `tests/device_analysis/test_device_dashboard.py` | add persistence round-trip test through `InventoryMeta` |
| `installer` | Yes; `packages[*].installer` | `pm dump` | `pm list packages -i` bulk, nullable fallback | default scope, Play/user filters, app sync display | planning-critical for some scopes | useful during inventory; later for scope | all packages helpful, most important for user/Play scope | should be populated when bulk source available; may be null | full mode from `pm dump` or bulk `-i` | Scope selection can widen/narrow incorrectly | harvest scope tests indirect | add bulk-installer parser tests |
| `app_label` | Yes; `packages[*].app_label` | `pm dump`, DB canonical metadata fallback in `normalizer.py` | DB canonical metadata, previous snapshot fallback, nullable/best-effort | UI, harvest display name, DB app sync label | display-only with sync value | not required during inventory correctness | all packages optional | may be null or fallback | full mode from `pm dump`/DB | Mostly UI degradation | `test_harvest_runner.py`, `test_inventory_state.py` indirect | add label fallback precedence test |
| `first_install` | Yes; `packages[*].first_install` | `pm dump` | nullable/best-effort, possibly `dump-package` later | diagnostic, evidence/publication only | diagnostic-only | eventual only | none | may be null | full mode from `pm dump` | Low immediate risk | none | none initially |
| `last_update` | Yes; `packages[*].last_update` | `pm dump` | nullable/best-effort, possibly `dump-package` later | diagnostic, evidence/publication only | diagnostic-only | eventual only | none | may be null | full mode from `pm dump` | Low immediate risk | none | none initially |
| `category` / `category_name` | Yes | DB canonical metadata or partition fallback in `normalizer.py` | DB canonical metadata, derived fallback | static scope selection, reporting, UI | snapshot-compat field, display-only operationally | not needed for raw inventory correctness; needed later for analyst workflows | relevant to static/reporting, not harvest identity | may be derived/fallback | same | Mostly affects grouping and reporting | static analysis suites indirect | add matrix-backed test later if fast mode changes category fill rate |
| `profile_key` / `profile_id` | Yes | DB canonical metadata or heuristic in `normalizer.py` | DB canonical metadata, heuristic fallback, previous snapshot fallback | harvest profile scope, static profile scope, profile-v3 tooling | planning-critical for scoped workflows | eventually needed; not needed for raw package identity | profile/watchlist/research-scope packages | may use fallback for all packages; must be meaningful for scoped packages | same | Breaks profile scope boundaries | `tests/scripts/test_profile_v3_tools.py`, harvest scope tests indirect | add scoped fast-mode contract test |
| `publisher_key` | Yes | DB canonical metadata or fallback in `normalizer.py` | DB canonical metadata or fallback | reporting/readiness only | display-only | eventual only | none | may be null/fallback | same | Low operational risk | none direct | none initially |
| `owner_role` / `partition` / user-system classification | Yes | derived from `primary_path` in `normalizer.py` | derived from base path | policy filtering, default scope, UI | policy-critical | needed during inventory | all packages | must be populated for all packages if base path known | same | Breaks non-root policy semantics | harvest scope tests, dashboard tests indirect | add explicit classification test from bulk base path |
| `source` | Yes | derived from category + installer in `normalizer.py` | derived internally | UI/display only | display-only | eventual only | none | may be null/fallback | same | Low operational risk | none direct | none initially |
| `review_needed` | Yes | derived in `normalizer.py` when canonical metadata incomplete/heuristic | derived internally | diagnostic/governance only | diagnostic-only | eventual only | none | may be null/fallback | same | Low operational risk | none direct | none initially |
| `package_hash` | Yes; top-level snapshot key | `snapshot_io.hash_rows()` over `package_name`,`version_name`,`version_code`,`primary_path` | derived internally | determinism diagnostics, snapshot compatibility | snapshot compatibility field | inventory only | all snapshots | keep schema stable; semantics should not change lightly | same | Affects determinism/readback tools | `tests/inventory/test_inventory_determinism.py` | add note if fast mode changes row completeness |
| `package_list_hash` | Yes; top-level and meta | derived from normalized names | derived internally from bulk identity | freshness fallback, determinism | identity-critical for fallback | inventory only | all packages | must be populated | same | Weakens fallback drift detection | `tests/inventory/test_package_collection_normalizer.py` | add snapshot_io persistence round-trip test |
| `package_signature_hash` | Yes; top-level and meta | derived from package signatures in inventory meta helpers | derived internally from `(package_name, version_code, version_name?)` source list | freshness metadata, determinism | snapshot compatibility field | inventory only | all packages | should be populated | same | Weakens diagnostics and some guard comparisons | existing diagnostics tests indirect | add dedicated hash field test |
| `path_enriched_packages` / `bulk_identity_only_packages` | Yes; top-level snapshot keys and meta | derived from normalized rows / collection stats | derived internally from `path_fidelity` counts | dashboard, operator summaries, fast-mode auditability | diagnostic-only with operator value | inventory and later | all snapshots | should be populated in fast mode; may be zero in full mode | full mode should converge to enriched=all, bulk-only=0 | Operators lose visibility into how much of the inventory is split-complete vs base-path-only | `tests/device_analysis/test_device_dashboard.py`, `tests/device_analysis/test_inventory_guard_metadata_loader.py`, `tests/inventory/test_inventory_views.py` | add direct `InventoryMeta` round-trip test |
| `build_fingerprint` | Yes; top-level/meta | device properties | direct property query | freshness guard, dashboard, state drift | diagnostic-only with guard value | inventory and later | all snapshots | should be populated | same | Fingerprint drift signal lost | `test_inventory_guard_metadata_loader.py` indirect | add fingerprint-change guard test |
| `device_serial` | Yes; top-level snapshot key | runtime | runtime | snapshot lookup, static result linkage | snapshot compatibility field | inventory and later | all snapshots | must be populated | same | Breaks snapshot ownership | broad workflow tests indirect | none initially |
| `snapshot_id` | Yes after DB persist | DB snapshot row id | unchanged | static results view, UI/readiness | snapshot compatibility field | later after persistence | all snapshots | keep stable | same | Breaks readback joins and operator references | `tests/inventory/test_inventory_views.py`, static results code indirect | none initially |

## Delta, freshness, and mismatch behavior

### Stale inventory

Age staleness is driven by:
- `captured_at` from `inventory_meta`
- `INVENTORY_STALE_SECONDS`

Code paths:
- `inventory.progress.render_snapshot_block()`
- `device_menu.inventory_guard.ensure_recent_inventory()`
- `device_menu.dashboard.render_inventory_status()`

### Package added / removed / changed

Canonical full-sync delta in `inventory.runner.run_full_sync()` compares:
- normalized `package_name`
- `version_code`

It does not compare:
- `version_name`
- `primary_path`
- `apk_paths`
- `split_count`
- installer
- labels

The runner computes:
- `new_count` from package-name set difference
- `removed_count` from package-name set difference
- `updated_count` from `version_code` difference on shared package names

### Freshness drift in guard metadata

`device_menu.inventory_guard.metadata.loader.get_latest_inventory_metadata()` uses:
- live device normalized `package_name`
- live device `version_code`
- snapshot package list or `package_list_hash`
- `build_fingerprint`
- `scope_hash`

`packages_changed` is driven by:
- equality of `(package_name, version_code)` identity sets when snapshot packages are available
- otherwise `package_list_hash`
- otherwise package-count fallback

`version_name` is not used to determine `packages_changed`.

### Inventory mismatch logic

Current mismatch-like behavior exists in:
- `device_menu.inventory_guard.metadata.loader`
- `device_menu.dashboard`
- `device_menu.inventory_guard.ensure_recent_inventory`

After the recent fix, `inventory.progress.render_snapshot_block()` no longer performs live ADB comparison. That banner now reports persisted snapshot state only.

### Does any code assume `apk_paths` is populated for every package?

Confirmed hard dependency:
- harvest planning and policy filtering for packages entering harvest/static-relevant workflows

Not yet proven as a hard dependency for every package:
- freshness/delta logic
- DB app-definition sync
- top-level snapshot persistence

This is the main safe optimization seam.

### Does any code assume `split_count` is correct for every package?

Hard dependency:
- harvest/static-relevant packages
- artifact estimation and split-aware displays

Not proven necessary for:
- policy-blocked packages outside active scope

## Identity-critical fields

- `package_name`
- `version_code`
- `package_list_hash`
- `device_serial`
- `snapshot_id` after persistence

## Planning-critical fields

- `primary_path`
- `apk_paths`
- `split_count`
- installer
- partition / owner-role classification
- `profile_key` for scoped/profile workflows

## Display-only or diagnostic-only fields

- `version_name`
- `app_label`
- `apk_dirs`
- `first_install`
- `last_update`
- `publisher_key`
- `source`
- `review_needed`

## Fields required for all packages

- `package_name`
- `version_code` when obtainable
- base path or enough path data to preserve user/system policy semantics
- partition/owner-role classification derived from base path
- `package_list_hash`
- `package_signature_hash`
- `build_fingerprint`

## Fields required only for harvest/static-relevant packages

- full `apk_paths`
- exact `split_count`
- stable `primary_path`
- scope-meaningful `profile_key`
- any split-aware artifact naming inputs

## Fields that can be nullable or deferred in fast mode

- `version_name`
- `app_label`
- `first_install`
- `last_update`
- `apk_dirs`
- `publisher_key`
- `source`
- `review_needed`

## Fields requiring targeted `pm path`

- `apk_paths`
- `split_count`
- canonical `primary_path` when bulk base path is insufficient
- any harvest/static-relevant package entering artifact planning

## Fields requiring `pm dump`, `dump-package`, APK/static fallback, or previous-snapshot fallback

- `version_name`: `pm dump` today; may fall back to previous snapshot or static analysis later
- `app_label`: `pm dump`, DB canonical metadata, previous snapshot fallback
- `first_install` / `last_update`: `pm dump` today
- profile/publisher/category enrichment: DB canonical metadata and `normalizer.py`

`pm dump-package` is still only a candidate. The repo currently extracts fields from `pm dump`, so parity must be proven before switching.

## Snapshot-compatibility fields

Keep stable initially even if they are not operationally critical:
- `package_hash`
- `package_list_hash`
- `package_signature_hash`
- `identity_source`
- `identity_quality`
- `snapshot_type`
- `scope_hash`
- `snapshot_variant`

## Existing tests that protect the contract

- `tests/inventory/test_package_collection_normalizer.py`
- `tests/inventory/test_inventory_determinism.py`
- `tests/inventory/test_models_diagnostics.py`
- `tests/device_analysis/test_inventory_state.py`
- `tests/device_analysis/test_inventory_sync_menu.py`
- `tests/device_analysis/test_device_dashboard.py`
- `tests/device_analysis/test_inventory_guard_metadata_loader.py`
- `tests/device_analysis/test_harvest_runner.py`
- `tests/harvest/test_scope_context.py`
- `tests/harvest/test_scope_context.py`
- `tests/scripts/test_profile_v3_tools.py`

## Missing tests to add before behavior changes

1. Guard metadata test: `version_code` change must set `packages_changed`.
2. Guard metadata test: `version_name`-only change must not set `packages_changed`.
3. Snapshot persistence round-trip test for normalized names and top-level hash fields.
4. Bulk parser tests for `-f -i -U --show-versioncode` output shapes.
5. Fast-mode tolerance test proving policy-blocked packages may have sparse `apk_paths` without breaking freshness/delta logic.
6. Harvest/static-relevant scope test proving targeted `pm path` enrichment restores full split fidelity before planning.

## Smallest safe patch proposal

1. Freeze the contract with the missing tests above.
2. Expand bulk parsing to retain:
   - `package_name`
   - base path
   - UID
   - installer
   - `version_code`
3. Keep snapshot schema unchanged.
4. Keep `version_name` best-effort and stop treating `--show-versionname` as a portability assumption.
5. Preserve full `pm path` enrichment for:
   - pullable packages
   - profile/watchlist/research-scope packages
   - static-analysis candidates
   - any package entering exact harvest/static planning
6. Leave full diagnostic mode intact for now; do not remove `pm dump` until field parity is proven.
