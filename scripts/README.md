# Scripts Directory

`scripts/` contains operator wrappers, migration helpers, report generators, and
CI gates. It is intentionally not the main application surface; routine work
should start from `./run.sh` unless a runbook names a script directly.

## Stable Entry Points

Keep these paths stable unless a separate migration plan updates docs, tests,
and operator workflows:

- `scripts/db/check_permission_intel.py`
- `scripts/db/recreate_web_consumer_views.py`
- `scripts/db/refresh_static_analysis_sessions.py`
- `scripts/db/verify_static_session_id_rollout.py`
- `scripts/db/prune_artifact_registry_dangling.py`
- `scripts/db/report_app_label_hygiene.py`
- `scripts/db/audit_static_session.py`
- `scripts/db/report_static_session_grain_integrity.py`
- `scripts/db/report_package_lineage_workbench.py`
- `scripts/db/report_static_analysis_targets.py`
- `scripts/db/report_dynamic_static_recovery_plan.py`
- `scripts/db/smoke_web_db.sh`
- `scripts/device_analysis/check_external_apk_store_mount.py`
- `scripts/device_analysis/audit_apk_cold_promotion.py`
- `scripts/device_analysis/promote_apk_blobs_to_cold_store.py`
- `scripts/db/report_dynamic_paper_freeze_readiness.py`
- `scripts/db/report_paper3_writing_package.py`
- `scripts/operator/report_system_migration_readiness.py` (read-only new-system transfer preflight)

See `docs/supported_entrypoints.md` for the broader supported wrapper list.

## Current Cleanup Policy

- Generated cache directories such as `__pycache__/` are removable.
- Do not delete tracked scripts solely because they have no in-repo caller; many
  are deliberate standalone maintenance commands.
- Archive one-time migration/backfill helpers only after the active rollout is
  complete and references have been updated.
- Keep APK hot/cold storage scripts while the Mercury-backed storage transition
  remains active.
- Keep repair scripts until the corresponding evidence or DB repair work is no
  longer part of active Paper 3 maintenance.

## Archive Candidates

These are the first candidates for future archiving, not immediate deletion:

- `scripts/dynamic/run_idle.sh`
- `scripts/dynamic/run_scripted_interaction.sh`
- historical DB migration helpers matching `scripts/db/backfill_*`
- historical DB normalization helpers matching `scripts/db/normalize_*`
- `scripts/db/phase_b1_join_key_normalization.py`
- `scripts/db/phase_b1_session_stamp_backlog.py`
- `scripts/db/schema_version_width_hotfix.py`

Before moving any of these, grep docs/tests/automation, add an archive README
with replacement commands, then run `pytest tests/gates/test_scripts_help_contract.py -q`.
