# Database Query Reference (Draft)

This folder documents the read-side queries the future PHP/MySQL portal will
need. The PHP application consumes data solely from the MySQL
repository—no direct integration with the Python CLI is required. Each
markdown file covers:

* **Purpose** – where the query is used in the UI
* **Inputs** – parameters the web layer must supply
* **Pseudo-SQL** – expressed against placeholder table names (discover the real names first!)
* **Result columns** – shape of the expected rows
* **Example payload** – JSON-like sketch of what the PHP app might render

Start with one of the introspection commands in [`TESTING.md`](TESTING.md) to
confirm actual table and column names in your environment before wiring these
queries into the app. Static-analysis reports currently land on disk; as soon as
the `static_analysis_runs` tables are provisioned, extend this folder with
matching read models that join `android_apk_repository` by `apk_id` or `sha256`.

## PHP consumption checklist

The query specs are intentionally framework-agnostic, but the PHP portal can
standardise on the following workflow when materialising them:

1. **Enforce read-only credentials.** Provision a dedicated database user with
   `SELECT` grants only. Reject any code reviews that introduce `INSERT`,
   `UPDATE`, or `DELETE` statements under the LAMP entry point.
2. **Mirror the pseudo-SQL with prepared statements.** Use PDO or your chosen
   abstraction to translate the query snippets into parameterised statements.
   Avoid string concatenation; every filter described in the docs should map to
   a bound parameter.
3. **Capture query provenance.** Wrap DAO methods with logging that records the
   query name (matching the markdown filename) and execution duration. This
   keeps parity between the documentation and the PHP implementation.
4. **Validate row shape.** Each markdown file lists the expected columns.
   Serialise rows into associative arrays and add unit tests that check the key
   set, so regressions surface quickly when the schema evolves.
5. **Prefer result caching at the PHP layer.** Dashboards that poll frequently
   should memoise results (APCu, Redis, or similar) with short TTLs rather than
   hammering MySQL.

> ℹ️  When you add a new query to the docs, create a matching DAO or repository
> class with the same name in PHP and link back to the markdown file in a
> docblock. This keeps cross-language references aligned.

## Contents

| Document | Focus |
| --- | --- |
| [`apps_by_category.md`](apps_by_category.md) | Category coverage + counts |
| [`uncategorized_apps.md`](uncategorized_apps.md) | Packages missing category assignments |
| [`latest_harvest_by_device.md`](latest_harvest_by_device.md) | Most recent pull per device |
| [`device_inventory_latest.md`](device_inventory_latest.md) | Current inventory view for a device |
| [`artifacts_for_app.md`](artifacts_for_app.md) | Artifact lineup for a single package |
| [`duplicate_artifacts.md`](duplicate_artifacts.md) | SHA-256 collisions and reuse |
| [`harvest_gaps.md`](harvest_gaps.md) | Installed apps without repository entries |
| [`harvest_paths.md`](harvest_paths.md) | DDL for path-related tables |
| [`recent_changes.md`](recent_changes.md) | Version deltas between snapshots |
| [`topline_kpi.md`](topline_kpi.md) | High-level rollup metrics |
| [`TESTING.md`](TESTING.md) | Manual verification checklist |
| [`AUDIT.md`](AUDIT.md) | Write-path audit notes |

> ⚠️ These files describe **read queries only**. Do not run them against
> production data without validating table names and access controls.
