# Android Framework Permissions Catalog – Scope & Parser Notes

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

When you snapshot the catalog, the JSON metadata captures every upstream URL so
future diffs can trace which source introduced a new permission or token
change. Downstream enrichment jobs should continue to treat catalog membership
as the ground truth for “framework” classification to avoid hand-maintained
allow-lists.
