# APK Inventory Model Transition

Status: working map after the hot/cold APK byte-store pass.

## A. Run-Directory Dependency Map

`data/device_apks/<serial>/runs/<session>` is still used in several roles:

| Area | Files | Current role | Primary assumption | Risk | Migration approach |
| --- | --- | --- | --- | --- | --- |
| Harvest write path | `scytaledroid/DeviceAnalysis/apk/workflow.py`, `DeviceAnalysis/harvest/package_execution.py`, `DeviceAnalysis/services/artifact_store.py` | Creates session root, package folders, manifests, receipts | Session directory is the harvest materialization root | High | Keep session root for logs/manifests, but route APK bytes through APK library and canonical store only. |
| APK library bridge | `DeviceAnalysis/services/apk_library_service.py` | Registers package/version/split-set entries from harvest results or legacy receipts | Receipts bridge run paths to canonical paths | Medium | Promote this to the primary read model; observations append to `harvest_history.csv`. |
| Static selection/linkage | `scripts/static_analysis/run_artifact_map.py`, `StaticAnalysis/cli/flows/selection.py` | Resolves receipts and legacy harvest paths for selected APKs | Harvest paths may still be needed for sidecars/provenance | High | Prefer logical `data/store/apk/sha256/...` paths and APK library groups; retain run paths only as provenance. |
| Dynamic guided capture | `DynamicAnalysis/controllers/guided_run_capture.py` | Finds harvest manifests for package context | Latest matching run manifest is a useful lookup source | Medium | Replace with package/version inventory lookup plus observation history. |
| Device dashboard/UI | `DeviceAnalysis/device_menu/dashboard.py` | Shows latest harvest/session state and artifacts root | Operator status is session-centered | Medium | Add package/version byte availability and last-seen inventory sections. |
| Verification | `DeviceAnalysis/evidence_verify/*` | Scans legacy manifests/receipts and hashes declared artifacts | Legacy manifests are verification input | Medium | Continue supporting legacy verification; add APK library verification mode. |
| Storage pressure/thinning | `DeviceAnalysis/services/storage_pressure.py`, `scripts/device_analysis/thin_harvest_session_apks.py` | Audits and thins run-tree APK payloads | Run trees are storage pressure source | Low after thinning | Keep as legacy retirement tooling. |
| DB backfill/audit | `scripts/db/backfill_apk_sets_from_receipts.py`, `scripts/db/report_harvest_path_stale_audit.py`, `Database/db_queries/harvest/install_sets.py` | Builds harvest/session/apk-set lineage from receipts | Receipts are bridge from filesystem to DB lineage | Medium | Backfill from APK library and observation history; avoid raw path identity. |
| Tests | `tests/device_analysis/*harvest*`, `test_storage_pressure.py`, `test_evidence_verify_*`, `test_harvest_destination.py` | Lock current run layout and compatibility | Run tree remains observable behavior | Medium | Add new inventory tests before changing existing layout contracts. |

## B. Proposed APK Inventory Model

Primary logical units:

- Device inventory observation: device serial, timestamp, package, version code/name, PackageManager paths, installer, profile/cohort, observation/session id, known/unknown decision, pull outcome.
- APK library entry: package, version code/name, planned split-set hash, content split-set hash, artifact roles, split names, SHA-256 values, first/last seen, devices seen, observation history.
- APK byte location: logical canonical path `data/store/apk/sha256/<prefix>/<sha>.apk`; backing byte status may be hot local, cold Mercury symlink, missing, or metadata-only.
- Legacy run folder: provenance/receipt/materialization history only.

Questions the model must answer:

- Installed now: from inventory snapshot/current device scan.
- Ever seen: from `data/android_apks/packages/*/*/split_sets/*`.
- Byte availability: from canonical store checker over hot/cold paths.
- Static/dynamic coverage: from DB/read-model lineage; filesystem report currently marks this as not connected.
- Need pull/re-harvest: unknown package/version/split-set, missing canonical blobs, or metadata-only split set.

## C. Read-Only Reports

Added:

- `scripts/device_analysis/report_apk_inventory_model.py`
- `scripts/device_analysis/report_legacy_harvest_run_retirement.py`
- `scripts/device_analysis/report_apk_transition_debt.py`
- `scripts/device_analysis/repair_regular_legacy_apks.py`
- `scripts/device_analysis/verify_apk_library_integrity.py`
- `scripts/device_analysis/repair_apk_library_logical_paths.py`

Outputs:

```text
output/audit/apk_inventory_model/<timestamp>/
  summary.json
  package_versions.csv
  split_sets.csv
  legacy_run_dependencies.csv
  seed_candidates.csv
  partial_artifacts.csv
  content_variant_collisions.csv
  blocked.csv

output/audit/legacy_harvest_run_retirement/<timestamp>/
  summary.json
  legacy_runs.csv
  db_references.csv
  archive_candidates.csv
  blocked.csv

output/audit/apk_transition_debt/<timestamp>/
  summary.json
  issues.csv
  content_variant_groups.csv
  regular_legacy_apks.csv
  unindexed_canonical_blobs.csv

output/audit/apk_library_integrity/<timestamp>/
  summary.json
  artifacts.csv
  findings.csv

output/audit/apk_library_logical_path_repair/<timestamp>/
  summary.json
  actions.csv
  blocked.csv
```

These reports are read-only and do not mutate APK bytes, legacy folders, or DB rows. The transition-debt
CLI skips full canonical byte hashing by default for fast iteration; use `--verify-sha256` for a slower
full hash pass.

The logical-path repair is metadata-only and dry-run by default. It rewrites historical
`artifacts[].canonical_path` values and APK-library `artifacts.csv` `canonical_path` fields from
resolved Mercury cold paths back to logical `data/store/apk/sha256/<prefix>/<sha>.apk` paths only
when both paths resolve to the same APK blob.

## D. Legacy Run-Folder Retirement Meaning

`safe_to_archive_later=yes` means the session passed storage and DB/read-model reference checks available
to the report:

- no regular APK payloads remain in that session folder,
- no broken APK symlinks,
- observed APK hashes are indexed in the APK library or no pullable artifacts were observed,
- observed bytes are available through hot/cold canonical paths,
- static/dynamic/paper/current research reference checks are clear when the DB is reachable.

It does not mean delete now. Unknown DB/reference state remains blocking and is reported as
`BLOCKED_UNKNOWN_DB_REFERENCE`.

Regular APK files that still remain in legacy run folders are reported separately. The transition-debt
report distinguishes bytes that are canonicalized and represented in the APK library or partial-artifact
index from bytes that still lack representation. Represented regular files are provenance copies and
should stay in place until an explicit thinning/archive apply pass is approved.

## E. Future Harvest Flow

Future desired flow:

1. Capture or load device inventory snapshot.
2. Build package/version/planned split-set identity from package name, version code/name, and PackageManager-reported APK paths/roles.
3. Look up exact package/version/planned split-set in APK library.
4. If known and all canonical bytes are available, skip pull and append observation history.
5. If unknown, byte-missing, or known to have content variants for the same planned split-set, pull into the
   hot canonical store and append observation history.
6. Register or update the package/version/split-set entry.
7. Write session output as receipts, logs, observation manifests, and references only.

Split-set identity before pull:

- Planned split-set hash can be known before pull from package/version plus PackageManager path/file-role data.
- Content split-set hash requires SHA-256 of pulled or already-known bytes.
- "Known enough to skip pull" requires planned split-set match plus complete artifact role/name match plus byte availability for every expected member.
- A planned split-set with multiple observed content hashes is not safe for a blind library hit. Harvest
  deliberately emits `harvest.package.apk_library_content_variant_pull_required` and falls back to pulling
  until a device-side content verification step exists.

Minimum observation record:

- session label, device serial, inventory snapshot id/timestamp, package, version, planned split-set hash, PackageManager paths, decision (`library_hit`, `pulled`, `skipped`, `blocked`), and linked APK library entry when available.

## F. UI / Reporting Changes

Add inventory-centered views to:

- Device Inventory & Harvest: installed-now packages, known/unknown split sets, pull-needed status.
- APK library: package/version history, hot/cold/missing status, multiple-version comparison readiness.
- Evidence & Workspace: legacy session folders as provenance and retirement candidates.
- Reporting & Exports: current/paper/dynamic protected versions and static/dynamic coverage.

Avoid presenting harvest runs as the primary APK identity surface.

## G. Risks And Next Pass

Risks:

- Static and dynamic tools may still expect session-path sidecars or manifests.
- Some legacy receipts are metadata-only or policy-skipped and cannot seed APK library entries.
- The Mercury cold root must remain mounted for cold symlinked canonical paths.
- Content-variant planned split-sets are indexed, but installed bytes cannot be inferred from planned identity alone.

Next implementation pass:

1. Add optional device-side content hash verification for content-variant planned split-sets; if unavailable,
   continue forcing pulls.
2. Change harvest receipts to write observation-only session records on library hits.
3. Add menu/read-model summaries for package/version byte availability.
