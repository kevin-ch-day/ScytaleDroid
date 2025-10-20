# Static Analysis Persistence Runbook

This runbook captures the end-to-end operator flow for static-analysis sessions:
running scanners, persisting results, and verifying database coverage. It assumes
`requirements.txt` has been installed (via `./setup.sh`) and that you have
credentials for the canonical database target.

## 1. Prepare the session

1. **Bootstrap dependencies** – `./setup.sh` (or install the packages listed in
   `requirements.txt`).
2. **Ensure schema + views** – prime the canonical helpers once per shell
   session (idempotent):
   ```bash
   python - <<'PY'
   from datetime import datetime
   from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest

   session = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
   canonical_ingest.ensure_provider_plumbing()
   canonical_ingest.upsert_base002_for_session(session)
   canonical_ingest.build_session_string_view(session)
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
./run.sh static --profile full --scope QA --session $(date +%Y%m%d-%H%M%S)
```
Key prompts:
- The main menu banner now shows session, scope, and DB status immediately.
- Progress output uses severity-aware icons; look for highlight ribbons calling
  out suppressed secrets, NSC guards, or unguarded providers while the scan runs.
- You can cancel at any prompt; completed apps are already persisted.

## 3. Persistence behaviour

Persistence happens automatically at the end of each run:
- `ingest_baseline_payload` writes the run to `static_analysis_runs`,
  `static_analysis_findings`, `static_fileproviders`, and `static_provider_acl`.
- Analytics payloads (severity/category matrices, novelty indicators, workload
  profiles) are stored alongside detector metrics in the run row.
- Provider exposures are normalised into BASE-002 findings. To re-run the
  promotion step manually execute:
  ```bash
  python - <<'PY'
  from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
  canonical_ingest.upsert_base002_for_session("<existing-session>")
  PY
  ```

To simulate a run without touching the database use the CLI dry-run flag:
```bash
python -m scytaledroid.StaticAnalysis.cli.run --profile full --dry-run
```
This still exercises detector output and summary cards but skips all INSERTs.

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

-- Session-scoped string view returns samples even without session_stamp
SELECT COUNT(*) AS samples
FROM v_session_string_samples
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
| `v_session_string_samples` returns 0 despite active findings | Legacy string samples missing timestamps | Re-run the manual ensure snippet with the desired session stamp to rebuild the view with fallback matching. |
| BASE-002 findings missing from `static_analysis_findings` | Promotion step skipped (dry-run) or schema not ensured | Re-run the manual promotion snippet or check application logs for INSERT errors. |
| Secrets still show placeholder examples | Validators suppressed them; confidence is `"low"` | Use `validator_hits` in the evidence JSON to confirm suppression rationale. |
| Diff views compare unrelated versions | Older runs lack version metadata | Ensure the APK metadata tables are populated; rerun analysis so `app_versions` captures versionName/versionCode for lineage-aware diffing. |

## 6. Useful commands

* Quick canonical inventory snapshot (counts + samples):
  ```bash
  python scripts/db_inventory.py --limit 5 --width 120
  ```
  Use `--only static_analysis_findings static_analysis_runs` to focus on a
  subset when hunting for redundant tables.
* Re-run canonical migrations & promotions:
  ```bash
  python - <<'PY'
  from datetime import datetime
  from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest

  session = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
  canonical_ingest.ensure_provider_plumbing()
  canonical_ingest.upsert_base002_for_session(session)
  canonical_ingest.build_session_string_view(session)
  PY
  ```
* Inspect latest run summaries: `SELECT * FROM static_analysis_runs ORDER BY id DESC LIMIT 5;`
* Run persistence tests: `pytest tests/test_static_ingest.py`

## 7. Related docs

* [Static analysis data model](static_analysis/static_analysis_data_model.md)
* [Static analysis analytics extensions](static_analysis_analytics.md)
* [Static analysis improvement plan](static_analysis_improvement_plan.md)
