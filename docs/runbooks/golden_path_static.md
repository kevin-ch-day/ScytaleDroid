# Golden Path (Static APK Analysis → DB → Report) — Design/Checklist

Goal: a boring, repeatable static analysis demo on MariaDB DEV, rerunnable without duplicates or partial commits.

## Preconditions
- `.env` points to MariaDB DEV (`scytaledroid_droid_intel_db_dev`) via `scytale_cli`.
- Schema version: 0.2.0 (Fedora) until PM applies 0.3.0.
- Use a known, small APK fixture (e.g., under `data/apks/device_apks/...`), not a live-harvested APK.
- Ensure the APK path is readable; no network access required.

## Suggested steps (scriptable)
1) Optional: `python -m scytaledroid.Database.tools.db_status` (confirm backend=mysql, schema_version, connection OK).
2) Run static analysis (replace `<APK_PATH>`):
   ```bash
   ./run_mariadb.sh static --apk <APK_PATH> --scope DEMO --session demo-1
   ```
   If a dedicated static CLI entry differs, adjust accordingly (goal: deterministic run_id/session).
3) Re-run the same command with a new session id (e.g., `demo-2`) to verify rerun safety.

## Expected DB touches (high-level)
- Inserts a new `static_analysis_runs` row (new `run_id`) per session.
- Writes static findings / permissions / strings summaries for that run_id.
- Should NOT:
  - duplicate prior rows for the same run_id,
  - leave partial data if a later step fails.

## Validation checks
- Each run creates exactly one `static_analysis_runs` row with the given session.
- Findings/summary tables reference the correct run_id; no cross-run bleed.
- Running twice yields two distinct run_ids; no duplicate explosions for the same session_id if reused.
- Reports/evidence for each run are scoped to its run_id/session.
- No silent failures in logs; failures should abort cleanly without partial commits.

## Idempotency / rerun guidance
- Prefer unique session IDs per demo run to keep semantics clear.
- If a session ID is reused, ensure code either updates deterministically or errors loudly (no duplicate storms).

## Deliverable
- A small script (e.g., `scripts/fedora/run_static_demo.sh`) that:
  - accepts `<APK_PATH>`
  - runs two sessions back-to-back
  - summarizes which tables changed and where outputs live.

Status: design/checklist only until PM green-lights running on Fedora.
