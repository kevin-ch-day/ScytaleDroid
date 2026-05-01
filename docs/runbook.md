# Static Analysis Persistence Runbook

This runbook captures the end-to-end operator flow for static-analysis sessions:
running scanners, persisting results, and verifying database coverage. It assumes
`requirements.txt` has been installed (via `./setup.sh`) and that you have
credentials for the canonical database target.

Historical paper/export notes were removed during doc cleanup. Use the current
contracts and workflow docs referenced below instead.

## Supported runtime flags

Use only the currently supported `SCYTALEDROID_*` flags in active operator
flows:

- static metadata:
  - `SCYTALEDROID_PIPELINE_VERSION`
  - `SCYTALEDROID_CATALOG_VERSIONS`
  - `SCYTALEDROID_CONFIG_HASH`
  - `SCYTALEDROID_STUDY_TAG`
- static CLI controls:
  - `SCYTALEDROID_STATIC_SHOW_TIMINGS`
  - `SCYTALEDROID_STATIC_FINDING_LIMIT`
  - `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT`
  - `SCYTALEDROID_STATIC_QUIET`
  - `SCYTALEDROID_STATIC_SHOW_FINDINGS`
  - `SCYTALEDROID_STATIC_SHOW_PIPELINE`
- string-analysis knobs:
  - `SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK`
  - `SCYTALEDROID_STRINGS_DEBUG`
- inventory:
  - `SCYTALEDROID_INVENTORY_STALE_SECONDS`
- dynamic operator UX:
  - `SCYTALEDROID_OBSERVER_PROMPTS`
- integrations/secrets:
  - `SCYTALEDROID_PCAPDROID_API_KEY`

If you find an older env var outside the active keep list above, treat it as
unsupported for current operator/research runs.

## 1. Prepare the session

1. **Bootstrap dependencies** – `./setup.sh` (or install the packages listed in
   `requirements.txt`).
  - Reporting menu defaults to core workflows; legacy publication/export actions are opt-in.
2. **Ensure schema helpers** – prime the canonical helpers once per shell
   session (idempotent):
   ```bash
   python - <<'PY'
   from datetime import datetime
   from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest

   session = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
   canonical_ingest.ensure_provider_plumbing()
   canonical_ingest.upsert_base002_for_session(session)
   print(f"Canonical helpers ready for session {session}")
   PY
   ```
   The CLI also performs these steps automatically when a run starts; use the
   snippet above if you need to prep a session before launching the menu.
3. **Collect APKs** – harvest devices with the Device Analysis menu as usual, or
   drop standalone APKs into the working directory.

## 2. Run static analysis

Launch the CLI and choose the **Static analysis** path:
```bash
./run.sh static --apk /path/to/app.apk --profile full --session $(date +%Y%m%d-%H%M%S)
```
Key prompts:
- The main menu banner now shows session, scope, and DB status immediately.
- Progress output uses severity-aware icons; look for highlight ribbons calling
  out suppressed secrets, NSC guards, or unguarded providers while the scan runs.
- You can cancel at any prompt; completed apps are already persisted.

> **Permission refresh defaults to ON.** The CLI now enables the post-run
> permission snapshot refresh automatically so `permission_audit_*` tables and
> the `static_permission_matrix` table stay in sync with each scan. Snapshot
> headers + app rows are persisted atomically (single transaction). Disable it
> only when you explicitly need a matrix-free run (set
> `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=0` before launching or toggle
> the option in Advanced).

Useful helpers:

- `python scripts/operator/ensure_permission_matrix.py` – ensures the matrix table exists
  and prints the latest run + row count (also hints if the refresh was skipped).
- `python scripts/dev/get_latest_run.py` – quick summary of the most recent run for
  downstream SQL lookups.

## 3. Persistence behaviour

Persistence happens automatically at the end of each run:
- canonical tables receive the full payload: `static_analysis_runs`,
  `static_analysis_findings`, `static_findings_summary`, `static_string_summary`,
  `static_string_samples`, `metrics`, `buckets`, `contributors`, and the
  permission audit tables. These are the sources that dashboards should
  consume—no need to parse the JSON artefacts under `output/`.
- Legacy summaries (`static_findings_summary`, `static_string_summary`) are
  keyed by `static_run_id` when available. `runs.run_id` is compatibility only
  and may be `NULL` when a static run ID exists.
- The CLI pipeline backing these inserts now lives under
  `scytaledroid/StaticAnalysis/cli/persistence/`; see `docs/persistence.md` for
  a breakdown of the new modules if you are reviewing code or debugging a
  run.
- Analytics payloads (severity/category matrices, novelty indicators, workload
  profiles) are stored alongside detector metrics in the run row.
- Provider exposures are normalised into BASE-002 findings. The dedicated
  storage-surface tables are now left untouched; the canonical findings contain
  the authoritative data set. To re-run the promotion step manually execute:
  ```bash
  python - <<'PY'
  from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
  canonical_ingest.upsert_base002_for_session("<existing-session>")
  PY
  ```

To simulate a run without touching the database use the CLI dry-run flag:
```bash
python -m scytaledroid static --apk /path/to/app.apk --profile full --dry-run
```
This still exercises detector output and summary cards but skips all INSERTs.

Each completed run prints a short reconciliation footer so you can confirm the
canonical counts without opening a SQL client, for example:

```
ℹ findings (normalized): 911
ℹ static_findings (baseline): 8
ℹ String samples persisted: 27398 (cap=2 per bucket; entropy ≥ 4.80)
```

The same terminology now appears in the verification digest so operators see a
consistent vocabulary (`Findings (runtime)`, `findings (normalized)`,
`static_findings (baseline)`), and the string disclosure reminds you of the
sampling cap that the CLI applies per bucket.

> Tip: The CLI no longer re-runs the permission-only detector pass after a full
> analysis by default. Set `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1`
> before launching the menu if you need the legacy behaviour.

Device inventory snapshots captured via the **Device analysis → Inventory & database sync** menu
are now persisted to the relational tables `device_inventory_snapshots` (snapshot headers) and
`device_inventory` (per-package rows) in addition to the JSON copies under
`data/state/<serial>/inventory/`. Use these tables for dashboards and joins instead of
parsing the filesystem artefacts.

## 4. Validate the ingestion

After each session run the SQL below (adjust `:session` as needed):

```sql
-- Provider exposures promoted into canonical findings
SELECT av.package_name,
       saf.rule_id,
       COUNT(*) AS findings
FROM static_analysis_findings AS saf
JOIN static_analysis_runs AS sar ON saf.run_id = sar.id
JOIN app_versions AS av ON sar.app_version_id = av.id
WHERE sar.session_stamp = ':session'
  AND saf.rule_id = 'BASE-002'
GROUP BY av.package_name, saf.rule_id;

-- Session-scoped string samples (no DB views required)
SELECT COUNT(*) AS samples
FROM static_string_samples
WHERE session_stamp = ':session';

-- NSC-aware cleartext suppression evidence
SELECT av.package_name,
       saf.rule_id,
       saf.severity,
       saf.evidence
FROM static_analysis_findings AS saf
JOIN static_analysis_runs AS sar ON saf.run_id = sar.id
JOIN app_versions AS av ON sar.app_version_id = av.id
WHERE sar.session_stamp = ':session'
  AND saf.rule_id = 'BASE-CLR-001';

-- Secrets confidence & validators
SELECT saf.rule_id,
       JSON_EXTRACT(saf.evidence, '$.confidence') AS confidence,
       JSON_EXTRACT(saf.evidence, '$.validator_hits') AS validators
FROM static_analysis_findings AS saf
JOIN static_analysis_runs AS sar ON saf.run_id = sar.id
WHERE sar.session_stamp = ':session'
  AND saf.rule_id LIKE 'STR-%'
ORDER BY confidence DESC;
```

The CLI also prints a summary of promoted BASE-002 rows and available string
samples after each run so you can confirm the counts without opening a SQL
client.

## 5. Troubleshooting

| Symptom | Likely cause | Next steps |
| --- | --- | --- |
| Manual ensure script reports `Failed to ensure canonical schema` | DB credentials missing or insufficient privileges | Confirm environment variables / DSN and re-run once grants are fixed. |
| `static_string_samples` returns 0 despite active findings | Legacy string samples missing timestamps or session association | Re-run the scan for the session and confirm the string sampling cap/logs. |
| BASE-002 findings missing from `static_analysis_findings` | Promotion step skipped (dry-run) or schema not ensured | Re-run the manual promotion snippet or check the application logs (`logs/app.log` or `logs/app.jsonl`) for INSERT errors. |
| Secrets still show placeholder examples | Validators suppressed them; confidence is `"low"` | Use `validator_hits` in the evidence JSON to confirm suppression rationale. |
| Diff views compare unrelated versions | Older runs lack version metadata | Ensure the APK metadata tables are populated; rerun analysis so `app_versions` captures versionName/versionCode for lineage-aware diffing. |

## 6. Useful commands

* Quick canonical inventory snapshot (counts + samples):
  ```bash
  python scripts/db_inventory.py --limit 5 --width 120
  ```
  Use `--only static_analysis_findings static_analysis_runs` to focus on a
  subset when hunting for redundant tables.
* **Smoke test (scan → persist → digest)**
  ```bash
  SESSION=$(date +%Y%m%d-%H%M%S)
  ./run.sh static --apk /path/to/app.apk --profile lightweight --session "$SESSION"
  python - <<'PY'
  from scytaledroid.Database.db_utils.menus import query_runner
  query_runner.render_session_digest("$SESSION")
  PY
  ```
  This runs the lightweight detector set against the current workspace, then
  prints the verification digest with the same labels used in the CLI summary
  (`findings (normalized)`, `static_findings (baseline)`, string sample totals).
* Re-run canonical migrations & promotions:
  ```bash
  python - <<'PY'
  from datetime import datetime
  from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest

  session = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
  canonical_ingest.ensure_provider_plumbing()
  canonical_ingest.upsert_base002_for_session(session)
  PY
  ```
* Inspect latest run summaries: `SELECT * FROM static_analysis_runs ORDER BY id DESC LIMIT 5;`
* Run persistence tests: `pytest tests/test_static_ingest.py`

## 7. Related docs

* [Static analysis data model](static_analysis/static_analysis_data_model.md)
* [Static workflow entrypoint map](maintenance/workflow_entrypoint_map.md)
* [Static analysis contract](static_analysis_contract.md)
