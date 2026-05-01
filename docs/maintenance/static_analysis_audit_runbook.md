# Static analysis audit runbook (filesystem + logs)

Operator checklist after one or more APK static runs. This complements DB row
reconciliation and does not replace schema or contract docs (see
`documentation_authority_index.md`).

## 1. What to capture at run time

- Session stamp (e.g. `20260501-rda-full`)
- Scope (single app, profile cohort, all)
- Whether persistence was enabled and any red `ERROR` / `WARN` lines on stdout

## 2. Concurrent runs and the filesystem lock

Static analysis uses a single-machine lock file:

`data/locks/static_analysis.lock` (relative to configured `DATA_DIR`).

- If a run **crashes** or is killed so `finally` cannot run, the lock can remain and block the next run (**“Another static analysis run is already active”**).
- On **Unix**, the CLI now **removes the lock automatically** when the recorded **PID is not running**.
- If another scan **is** truly running, stop it or wait; as a last resort, delete the lock file only when you are sure no Python static worker is active.

The error line may show a **different** `session_label` than your new `session_stamp`; the lock is global, not per session.

## 3. Log files (human + errors)

Under configured `LOGS_DIR` (default repo-relative `logs/`):

| File | Role |
|------|------|
| `static_analysis.log` | Category `static` / `static_analysis` pipeline and persistence messages |
| `static_analysis.jsonl` | Same events, structured (optional `jq` workflows) |
| `error.log` | Mirrored `log.error` / critical, including static-related failures |
| `third_party/*.log` | Androguard and other libraries (resource/APK parse noise) |

Menu path: system utilities that show resolved paths → `show_log_locations` in `util_actions.py`.

## 4. Persistence audit JSON

After a run, check:

`output/audit/persistence/<session_stamp>_persistence_audit.json`

If linkage failed early, you may see `<session_stamp>_missing_run_ids.json` instead.

## 5. Automated tail scan (this repo)

Filesystem-only (no DB required):

```bash
./scripts/static_analysis_audit_logs.sh --session 20260501-rda-full
# or
python -m scytaledroid.StaticAnalysis.audit --session 20260501-rda-full
```

Optional: `--tail-lines 15000`, `--max-hits 200`,
`--keyword substring` (repeatable).

## 6. MariaDB reconciliation

For authoritative table counts linked to `session_stamp` / `static_run_id`:

```bash
python -m scytaledroid.Database.db_scripts.static_run_audit --session <stamp>
```

## 7. Environment knobs for richer stdout (optional)

See `StaticAnalysis/cli/core/cli_options.py` — e.g. `SCYTALEDROID_STATIC_SHOW_PIPELINE`,
`SCYTALEDROID_STATIC_SHOW_TIMINGS`, and verbose/static menu options for fuller per-app sections.
