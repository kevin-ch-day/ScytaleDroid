# Static Analysis Persistence Runbook

This runbook captures the end-to-end operator flow for static-analysis sessions: running scanners, persisting results, and verifying database coverage. It assumes the schema migrations in [`scripts/migrate.sql`](../scripts/migrate.sql) have been applied.

## 1. Scan
1. Ensure the workspace is configured (`./setup.sh`).
2. Launch a static-analysis session:
   ```bash
   ./run.sh static --profile default --scope QA --session $(date +%Y%m%d-%H%M%S)
   ```
3. When prompted, review detector output. The CLI can be cancelled safely; partial scans are skipped during persistence.

## 2. Persist
Persistence is executed automatically at the end of `run.sh static`. To re-run manually or to test without mutating the database, use the CLI dry-run flag:
```bash
python -m scytaledroid.StaticAnalysis.cli.run --profile default --scope QA --session 20240101-010101 --dry-run
```
The dry-run path logs what would have been written (run profiles, finding counts, rule coverage, evidence coverage, and CVSS coverage) without touching the database.

## 3. Verify
Run the queries in [`scripts/static_analysis_health.sql`](../scripts/static_analysis_health.sql) against the static-analysis database after each session. They report rule coverage, evidence completeness, CVSS coverage, and MASVS status for the most recent runs.

Expect ≥95% rule coverage and ≥95% CVSS BTE coverage. Evidence path and preview counts should be near zero.

## 4. Troubleshooting
| Symptom | Likely cause | Next steps |
| --- | --- | --- |
| Rule coverage < 95% | Detector phrasing drifted or missing `rule_id_hint` | Update detector output or extend [`scytaledroid/StaticAnalysis/cli/rule_mapping.py`](../scytaledroid/StaticAnalysis/cli/rule_mapping.py). |
| Evidence path/preview missing | Detector evidence lacks `detail`/`path` | Ensure detectors emit structured evidence and call `normalize_evidence` helpers. |
| MASVS matrix empty | `masvs_control_coverage` table absent | Apply migrations and re-run persistence. |
| CVSS scores missing | Rule vector missing or calculator failed | Extend `config/cvss_v4_map.yaml` or update [`cvss_v4.score_vector`](../scytaledroid/StaticAnalysis/cli/cvss_v4.py). |

## 5. Useful Commands
* Re-apply schema migrations (idempotent, including metrics deduplication when needed): `mysql < scripts/migrate.sql`
* Run persistence tests: `pytest tests/test_persist_counts.py`
* Inspect latest run summary: `SELECT * FROM v_run_overview ORDER BY run_id DESC LIMIT 5;`

### Metrics table repair (automatic fallback)
`scripts/migrate.sql` now runs the metrics deduplication flow only when the unique constraint is missing **and** duplicate
rows exist. You should no longer need to run the block manually. If the migration output still reports a duplicate-key error,
the following statements mirror the automated repair and can be executed as a last resort:

```sql
DROP TABLE IF EXISTS metrics_tmp;

CREATE TABLE metrics_tmp (
  run_id      BIGINT UNSIGNED NOT NULL,
  feature_key VARCHAR(191)    NOT NULL,
  value_num   DECIMAL(12,4)   NULL,
  value_text  VARCHAR(512)    NULL,
  module_id   VARCHAR(64)     NULL,
  UNIQUE KEY uq_metrics_run_key (run_id, feature_key),
  KEY ix_metrics_run (run_id),
  KEY ix_metrics_feature (feature_key),
  KEY ix_metrics_run_feature (run_id, feature_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO metrics_tmp (run_id, feature_key, value_num, value_text, module_id)
SELECT
  run_id,
  feature_key,
  MAX(value_num) AS value_num,
  SUBSTRING_INDEX(
    GROUP_CONCAT(COALESCE(value_text,'') ORDER BY LENGTH(value_text) DESC SEPARATOR '\x1D'),
    '\x1D', 1
  ) AS value_text,
  SUBSTRING_INDEX(
    GROUP_CONCAT(COALESCE(module_id,'') ORDER BY LENGTH(module_id) DESC SEPARATOR '\x1D'),
    '\x1D', 1
  ) AS module_id
FROM metrics
GROUP BY run_id, feature_key;

RENAME TABLE metrics TO metrics_backup_tmp, metrics_tmp TO metrics;

DROP TABLE IF EXISTS metrics_backup_tmp;
```

This logic matches the automated fallback used by the application when the unique key is missing.
