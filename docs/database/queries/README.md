# Database Query Reference (Draft)

This folder documents the read-side queries the future PHP/MySQL portal will need. Each markdown file covers:

* **Purpose** – where the query is used in the UI
* **Inputs** – parameters the web layer must supply
* **Pseudo-SQL** – expressed against placeholder table names (discover the real names first!)
* **Result columns** – shape of the expected rows
* **Example payload** – JSON-like sketch of what the PHP app might render

Start with one of the introspection commands in [`TESTING.md`](TESTING.md) to confirm actual table and column names in your environment before wiring these queries into the app.

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

> ⚠️ These files describe **read queries only**. Do not run them against production data without validating table names and access controls.
