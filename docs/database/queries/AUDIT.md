# APK → MySQL Write Path Audit

This note captures the current database write surface used during APK harvests. No schema or code changes were made while collecting this information.

## Primary writers

| Location | Function | Purpose |
| --- | --- | --- |
| `scytaledroid/Database/db_func/harvest/apk_repository.py` | `ensure_app_definition(package_name, app_name, ..., context=None)` | Upserts a row in `android_app_definitions` and optionally updates `category_id`, `profile_id`, `profile_name`. Requires `package_name`. |
| `scytaledroid/Database/db_func/harvest/apk_repository.py` | `upsert_apk_record(ApkRecord, context=None)` | Inserts or updates a row in `android_apk_repository` for each harvested artifact, keyed by `sha256`. |
| `scytaledroid/Database/db_func/harvest/apk_repository.py` | `ensure_split_group(package_name, context=None)` / `mark_split_members(group_id, apk_ids)` | Create and maintain `apk_split_groups` records when a package has multiple split APKs. |
| `scytaledroid/Database/db_func/harvest/apk_repository.py` | `ensure_storage_root(host_name, data_root, context=None)` | Registers the ingest host and data root in `harvest_storage_roots` (unique per host/path). |
| `scytaledroid/Database/db_func/harvest/apk_repository.py` | `upsert_artifact_path(apk_id, storage_root_id, ..., context=None)` | Stores device + local path metadata for each artifact in `harvest_artifact_paths`. |
| `scytaledroid/DeviceAnalysis/harvest/runner.py` | `_execute_package_plan(...)` | Calls the helpers above for the legacy/standard harvest path (default). |
| `scytaledroid/DeviceAnalysis/harvest/quick_harvest.py` | `quick_harvest(...)` | Mirrors the legacy path but honours `HARVEST_WRITE_DB` (can disable DB writes for quick pulls). |

## Fields written today

The `ApkRecord` dataclass (same file) enforces the minimum payload. During a successful harvest, the following keys are populated in `android_apk_repository`:

* **Required**: `package_name`, `sha256`
* **Derived / optional but typically present**:
  * `app_id` (from `ensure_app_definition`)
  * `file_name`, `file_size`
  * `is_system` (boolean → stored as 0/1)
  * `installer`
  * `version_name`, `version_code`
  * `md5`, `sha1`, `sha256`
  * `device_serial`
  * `harvested_at` (UTC datetime)
  * `is_split_member`, `split_group_id`
  * `signer_fingerprint` (currently unused – left `None` unless populated elsewhere)
* Path metadata moves to `harvest_artifact_paths` with:
  * `apk_id` (FK into `android_apk_repository`)
  * `storage_root_id` (FK into `harvest_storage_roots`)
  * `source_path` (per-artifact device path)
  * `local_rel_path` (path relative to the ingest host’s `data/apks/` root)
* `harvest_storage_roots` records the ingest environment:
  * `host_name`, `data_root` (`/abs/path/to/data/apks`), timestamps

`ensure_app_definition` still records:

* `package_name` (lowercased), optional `app_name`
* Optional linking to `android_app_categories` via `category_id`
* Optional profile metadata (`profile_id`, `profile_name`) when the schema provides those columns.

## When DB writes are skipped

* Both legacy and quick harvests resolve `HarvestOptions` via `harvest/common.py::load_options`. The flag `HARVEST_WRITE_DB` (default `True`) controls whether any of the writes above occur.
* The quick-harvest path (`harvest/quick_harvest.py`) respects the same flag. When `HARVEST_WRITE_DB = False`:
  * APKs are still pulled to `data/apks/device_apks/<serial>/<timestamp>/...`
  * Metadata sidecars are written if `HARVEST_WRITE_META` remains `True`
  * No MySQL calls occur (results stay on disk only).
* When `HARVEST_WRITE_DB = True` but a per-package error occurs (e.g., app definition upsert fails), the package is skipped and tagged with `app_definition_failed` in the summary, leaving existing rows untouched.

## What is **not** persisted yet

* Run-level manifests (timestamp, guard decision, etc.) live only in sidecar JSON files.
* Guard decisions / package delta summaries are tracked in-memory and surfaced in CLI summaries, but no table records consume them today.
* Absolute filesystem paths are no longer stored directly; reconstruct them via `harvest_storage_roots.data_root || '/' || harvest_artifact_paths.local_rel_path` when needed.
* Static-analysis results, pipeline traces, and reproducibility bundles stay in `data/static_analysis/reports/` for now—no writer touches SQL yet. Future schema work (`static_analysis_runs`) should accept `apk_id`, `sha256`, `pipeline_trace`, and `repro_bundle` hashes captured during analysis.

## Pointers for future docs

* Table/column names originate from the SQL strings in `db_queries/harvest/apk_repository.py`.
* Any PHP/MySQL UI should rely on the documented fields above; no other tables are written by the harvest code paths reviewed.
