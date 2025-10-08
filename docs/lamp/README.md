# LAMP Integration Notes (Draft)

This folder captures early guidance for wiring ScytaleDroid’s database into a
Linux/Apache/MySQL/PHP stack.

## Overview

ScytaleDroid’s CLI populates MySQL tables (see `docs/database/queries/`) that a
PHP front‑end can consume. No schema migrations are required yet—focus on
read-only dashboards over the existing tables. The PHP layer is expected to
operate strictly as a reader: it does not call back into the CLI or attempt to
mutate repository state.

### Data flow at a glance

```
Android devices ──harvest──▶ CLI workers ──persist──▶ MySQL (read replica) ──SELECT──▶ PHP portal
```

* **Harvesters** push inventory and artifact metadata into MySQL through the
  Python tooling and persist static-analysis reports (`data/static_analysis/`)
  alongside reproducibility bundles per APK.
* **MySQL** acts as the single source of truth for the PHP tier; treat the
  schema as append-only from LAMP’s perspective.
* **PHP** renders dashboards and exports by issuing read queries only. Any
  enrichment or calculated metrics should remain in PHP or a cache layer, not in
  ad-hoc SQL writes.

## Suggested workflow

1. **Provision MySQL credentials** for the PHP app with read-only access to the
   ScytaleDroid schema.
2. **Reuse the query specs** in `../database/queries/` to build DAO classes or
   prepared statements inside the PHP layer.
3. **Expose artifacts via HTTP downloads** from `data/apks/device_apks/`
   (ensure Apache has read permission or proxy through PHP with access
   controls). Pair each artifact link with its latest static-analysis report
   located in `data/static_analysis/reports/<apk_sha256>.json` so analysts can
   jump from the portal to detector output.
4. **Cache inventory snapshots** in MySQL (import
   `data/state/<serial>/inventory/latest.json`) before driving device dashboards.
5. **Index reproducibility bundles** by `apk_id` so diff-friendly assets (manifest
   digest, network-security graph hash, string-index summary) can be surfaced in
   the portal for version-to-version comparisons.
6. **Add environment toggles** so LAMP can detect whether quick harvests skipped
   DB writes (inspect `HARVEST_WRITE_DB` flag if you expose it via config).

### Static-analysis artefacts in LAMP

| Asset | Location | Suggested UI usage |
| --- | --- | --- |
| Detector report | `data/static_analysis/reports/<sha256>.json` | Render badge counts, pipeline timings, and correlation findings. |
| Repro bundle | `metadata.repro_bundle` inside each JSON report | Provide manifest diff downloads and NSC policy graph visualisations. |
| Pipeline trace | `metadata.pipeline_trace` | Display detector durations to surface bottlenecks. |

### Operational considerations

* **Connection pooling:** Use `pdo_mysql` with persistent connections or an
  application pooler (e.g. ProxySQL) to avoid exhausting MySQL threads during
  dashboard bursts.
* **Secrets management:** Store database credentials in environment variables or
  a vault-backed config file. Never commit them to the repository.
* **Error reporting:** Surface SQL errors through a central logger so the data
  engineering team can trace failing queries back to their documentation entry.
* **Performance budgets:** Agree on acceptable response times per dashboard and
  monitor MySQL slow query logs for violations. Large static-analysis JSON
  payloads should be cached or streamed instead of loaded wholesale for every
  request.
* **Failover plan:** If the primary MySQL node is unavailable, serve a cached
  “last known good” dataset rather than attempting emergency writes.

## TODO

- Document Apache virtual host permissions for the artifact repository, including
  directory-level `.htaccess` requirements.
- Provide PHP examples (PDO prepared statements) mirroring the pseudo-SQL in the
  query docs.
- Add authentication/authorization strategy (JWT, Basic Auth, etc.) for analysts
  accessing the dashboards.
- Evaluate whether to mirror run manifests into SQL for easier consumption.
- Capture MySQL backup/restore runbooks so the PHP team can rehearse DR drills.

Keep this doc updated as the LAMP integration progresses.
