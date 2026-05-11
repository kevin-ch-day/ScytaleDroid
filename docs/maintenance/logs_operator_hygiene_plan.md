# Logs directory — operator hygiene plan (no redesign)

**Priority:** **P1 / P2** — operator clarity and disk hygiene; **not** a P0 architecture blocker.  
**Non-goals (this document):** logging framework redesign, retention policy changes, automatic deletion of log files, code changes (beyond doc corrections noted as completed here).

**Source of truth (code):** `scytaledroid/Utils/LoggingUtils/logging_engine.py` — `LOG_CONFIGS` and related helpers (`create_harvest_run_logger`, `configure_third_party_loggers`).  
**Mechanics:** `scytaledroid/Utils/LoggingUtils/logging_core.py` — `LOG_DIR`, `setup_logger`, rotating handlers, **gzip-on-rotate** (`.gz` siblings).

---

## 1. Source of truth

| What | Where |
| --- | --- |
| Category → filenames | `LOG_CONFIGS` in `logging_engine.py` |
| Root path | `app_config.LOGS_DIR` (default `logs/`) → `logging_core.LOG_DIR` |
| Rotation size / backup count | `_LoggerConfig` defaults: `max_bytes=10*1024*1024`, `backup_count=14` (per category unless overridden — currently **no** per-category override in `LOG_CONFIGS`) |
| Per-harvest run files | `create_harvest_run_logger` → `logs/harvest/<timestamp>_run-<slug>.jsonl` **and** paired `.log` |
| Third-party (androguard debug) | `configure_third_party_loggers` → `logs/third_party/androguard.<id>.log` (+ optional loguru sink to same path pattern) |
| Resolved path map | `list_log_files()` in `logging_engine.py` |

---

## 2–3. `LOG_CONFIGS` vs `housekeeping.md` (mismatches)

Compared **before** the doc-only fix in `housekeeping.md` (this plan records what was wrong):

| Issue | Code (`LOG_CONFIGS`) | Doc (`housekeeping.md` before fix) |
| --- | --- | --- |
| **Database human log** | `db.log` + `db.jsonl` | Stated **no** human file (`—`) — **wrong** |
| **Harvest per-run** | **Both** `.jsonl` and `.log` under `logs/harvest/` | Implied **only** JSONL — **incomplete** |
| **Rotation / gzip** | RotatingFileHandler + gzip namer → `*.gz` archives | **Not mentioned** — operators see unexplained siblings |
| **Default pairing** | Most categories: text + JSONL | Said “paired” globally — **true in spirit**; metrics is **JSONL-only** (correct in table) |
| **`list_log_files` “harvest_runs”** | Synthetic `LogTarget` pointing at **`logs/harvest/`** directory (both paths set to dir) | **Not documented** — name suggests a different tree than `harvest/` |

**After fix:** `housekeeping.md` table and harvest subsection aligned to code; rotation note added (short).

---

## 4. Naming collisions (operator confusion)

| Collision | Clarification |
| --- | --- |
| **`metrics.jsonl`** | **Logger category `metrics`** — structured telemetry stream; **not** the legacy SQL **`metrics`** table, **not** “detector metrics” dicts inside reports, **not** dynamic ML metrics English in UI copy. |
| **`harvest.log` / `harvest.jsonl`** vs **`logs/harvest/*`** | **Root** = global harvest channel for the process; **`logs/harvest/`** = **per-run** timestamped files (`*_run-<slug>.jsonl` + `.log`). Both are intentional; different granularity. |
| **`harvest_runs` in scripts** | `list_log_files()` exposes key **`harvest_runs`** as the **directory** `logs/harvest/`. Scripts such as `log_run_timeline.py` / `log_error_summary.py` glob `harvest_runs` **or** `harvest` — historical path vocabulary; treat **`logs/harvest/`** as canonical. |
| **`logs/third_party/`** | Androguard (and related) **debug** file sink; not the same as static/dynamic/db channels. Only populated in relevant debug modes. |

---

## 5. Minimal documentation-only fix (done in-repo)

- Update **`docs/maintenance/housekeeping.md`**: correct **Database** row; expand **Harvest** row for paired per-run `.log` + `.jsonl`; add **rotation / `.gz`** footnote; clarify **`metrics.jsonl`** vs other “metrics” meanings; mention **`logs/third_party/`** briefly.

---

## 6. Later optional read-only “logs health” command (spec only — no implementation)

**Intent:** read-only report for operators (and CI optional), **no deletes**, **no retention changes**.

Suggested outputs:

| Metric | How (conceptual) |
| --- | --- |
| **Total size** | `sum(file.size for file in tree under LOG_DIR)` |
| **Size by category** | Buckets: root files matching `LOG_CONFIGS` names; subdirs `harvest/`, `third_party/`; `*.gz` grouped with prefix or “archived” bucket |
| **Active vs rotated** | Active = non-`.gz` regular files matching known basenames; rotated = `*.gz` count |
| **Oldest rotated** | min(mtime) among `**/*.gz` |
| **Largest files** | Top N by size (active + gz) |
| **Stale over age** | Files (optional: only `.gz` or include active) with mtime **older than** `SCYTALEDROID_LOGS_STALE_DAYS` or CLI `--older-than-days` — **flag only**, no delete |

**Invocation sketch:** `PYTHONPATH=. python scripts/operator/logs_health.py` or Workspace menu item wrapping the same.

---

## 7–9. Constraints (unchanged)

- No logging redesign; no automatic log deletion; no retention behavior change without a separate RFC.

---

## Evidence model — how logs fit

**Legend:** *diagnostics* = helps debug live runs; *evidence* = supports audit/replay but not sole truth; *reconstruct* = needed if other artifacts missing; *cleanable* = safe after stronger artifacts exist.

| Stream / area | Role |
| --- | --- |
| **`error.log`** | **Diagnostics** — hard errors funnel; tail when something failed. |
| **`app.log` / `app.jsonl`** | **Diagnostics + light evidence** — env, lifecycle; useful for “what did the CLI do?” **Not** canonical run output. |
| **`static_analysis.log` / `.jsonl`** | **Evidence (supporting)** — `REPORT_SAVED`, persistence events, session stamps; **high value** for correlating DB + disk **when** JSON/audit files exist. **Not** canonical vs `static_analysis_runs` / archive JSON. |
| **`db.log` / `.jsonl`** | **Diagnostics** — SQL/DB tooling channel; separates DB noise from scanner narrative. |
| **`device_analysis` / `harvest` (root + per-run)** | **Evidence (supporting)** — harvest/pull debugging; per-run under `logs/harvest/` often **enough to reconstruct harvest-side issues** without re-pulling. **Not** a substitute for receipts/evidence packs. |
| **`dynamic_analysis.*`** | **Evidence (supporting)** — runtime runs; canonical dynamic truth still **DB + evidence packs** per contracts. |
| **`audit.log` / `.jsonl`** | **Evidence (supporting)** — audit trail channel; may overlap with `output/audit/` JSON — **correlate**, don’t duplicate as “truth.” |
| **`metrics.jsonl`** | **Diagnostics / telemetry** — not DB schema metrics; use for throughput/timing style analysis if emitted. |
| **`logs/third_party/*.log`** | **Diagnostics only** — parser noise / deep debug; **not** paper evidence. |

**Reconstructing a run (practical order):** DB canonical rows + `output/` / `data/` artifacts (reports, persistence audits, selection manifests) + **then** grep `static_analysis` / `db` logs by `session_stamp` / `static_run_id`. Logs **fill gaps** when artifacts are incomplete — they do **not** replace manifests or DB.

**Safe to clean (manual operator decision):** After **evidence packs**, **persistence audit JSON**, **archive JSON**, and **DB** (if retained) are copied/archived, **old rotated `.gz`** and **ancient per-harvest files** are usually **safe to delete** locally — still **operator-initiated**; no auto-delete from this plan.

---

## Backlog linkage

Tracked as **P1/P2 operator hygiene** in `documentation_authority_index.md` (maintenance cluster) and `workflow_entrypoint_map.md` (generated artifacts / validation notes). **Not** gated on static schema audit or DB overhaul P0 work.
