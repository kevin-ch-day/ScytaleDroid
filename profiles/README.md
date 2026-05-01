# Profiles

This directory contains profile-scoped, freeze-anchored configuration artifacts used by
publication/export tooling.

## Profile v3 app catalog

`profiles/profile_v3_app_catalog.json` is the canonical mapping:

`package_name` -> `{ "app": "...", "app_category": "..." }`

Do not guess package IDs. Populate missing packages by installing the apps on the
capture device and recording the exact package string.

Example commands:

```bash
adb shell pm list packages | rg -i \"drive|docs|sheets|dropbox|notion|acrobat|meet|zoom|discord\"
```

## APK freshness (recommended for paper-grade cohorts)

If you intend to make claims about "commercial app versions", ensure harvested APKs on disk
match what is installed on the capture device at the time of capture.

Recommended operator flow:

- Device Analysis → Sync inventory (fresh snapshot)
- Device Analysis → Pull APKs → Research Dataset Alpha (or v3 scope) → choose "Pull all packages in selected scope"
  (do not rely on delta-only pulls when assembling a paper-grade cohort)

If a package is not present in the catalog, profile v3 publication exports must fail
closed with a clear error.

## Helper scripts

- `scripts/profile_tools/profile_v3_manifest_build.py`
  - Build a self-contained `data/archive/profile_v3_manifest.json` from a base freeze and additional run IDs.
- `scripts/profile_tools/profile_v3_catalog_validate.py`
  - Validate that every included run's package is present in `profiles/profile_v3_app_catalog.json`.
  - Use `--emit-json-snippet` to print missing package keys as a JSON snippet for easy paste/fill.
- `scripts/profile_tools/profile_v3_scripted_coverage_audit.py`
  - Audit scripted/manual interaction coverage for runs imported from a base freeze.
