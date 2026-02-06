# Android Framework Permissions Catalog – Scope & Parser Notes

Note: This catalog supports permission guard-strength lookups during static
analysis. Paper-grade gating is governed separately by the governance snapshot
CSV import; the catalog remains a supplemental metadata source.

The framework permissions catalog now composes multiple documentation feeds
before seeding `android_framework_permissions`:

* The primary source remains `android/Manifest.permission` (SDK offline copy or
  live devsite HTML when the SDK asset is unavailable).
* Additional namespaces such as AdServices are fetched from their dedicated
  devsite pages (e.g., `android/adservices/common/AdServicesPermissions`).

Merging these feeds fills the `ACCESS_ADSERVICES_*` family and any other
off-page permissions that never appeared under the classic Manifest page. The
loader is resilient to optional sources—missing auxiliary pages no longer block
catalog refreshes, but any page that responds successfully is folded into the
final payload.

The parser also understands the newer documentation layouts that encode
protection levels as chips, definition lists, or bullet lists rather than a
simple inline string. That means permissions like `READ_PRECISE_PHONE_STATE`
and `MODIFY_PHONE_STATE` now carry their `signature|privileged` metadata in the
catalog and no longer surface as “framework with NULL protection” during
detector enrichment.

> **CLI fallback:** the static-analysis CLI now ships a minimal catalog at
> `config/framework_permissions.yaml`. When the database-backed catalog has not
> been seeded yet (fresh installs, air-gapped runs, unit tests), the permission
> classifier falls back to this file so dangerous/signature protections are
> still recognised. Once the canonical table is hydrated the fallback is
> bypassed automatically.

When you snapshot the catalog, the JSON metadata captures every upstream URL so
future diffs can trace which source introduced a new permission or token
change. Downstream enrichment jobs should continue to treat catalog membership
as the ground truth for “framework” classification to avoid hand-maintained
allow-lists.
