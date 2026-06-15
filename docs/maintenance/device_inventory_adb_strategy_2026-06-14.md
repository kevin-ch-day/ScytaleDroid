# Device Inventory ADB Strategy 2026-06-14

## Scope

This note records the validated ADB command strategy for ScytaleDroid device inventory on the physical research device and the compatibility rules now used by `DeviceAnalysis`.

This is a Device Inventory checkpoint only. It is intentionally separate from DB Phase B schema work.

## Tested Device

- Manufacturer: Motorola
- Model: `moto g 5G - 2024`
- Device: `fogo`
- Android release: `15`
- SDK: `35`
- Build fingerprint:
  `motorola/fogo_g/fogo:15/V1UFNS35H.193-20-12/66040b-a80b154:user/release-keys`

## Measured Command Timings

Observed on the attached physical device:

- `pm list packages -f -i -U --show-versioncode`: about `0.10s`
- `cmd package list packages -f -i -U --show-versioncode`: about `0.08s`
- `dumpsys package packages`: about `0.23s`
- `pm path <package>`: about `0.09s`
- `cmd package path <package>`: about `0.07s`
- `pm dump <package>`: about `0.93s` to `1.05s`
- `dumpsys package <package>`: about `0.08s`
- `cmd package dump-package <package>`: about `0.09s`

Measured cohort impact:

- 11-package cohort: `11.229s` -> `0.598s`
- 1-package cohort: about `1.03s–1.25s` -> `0.49s–0.53s`

## Selected Strategy

### 1. Bulk identity

Use package-manager list output as the portable identity source:

- preferred: `cmd package list packages ...`
- fallback: `pm list packages ...`

Identity contract:

- `package_name`
- `version_code`
- base path when `-f` is included
- installer when `-i` is included
- uid when `-U` is included

### 2. Bulk metadata preload

Use one bulk:

- `dumpsys package packages`

for baseline inventory metadata preload, even for tiny cohorts.

Reason:

- on the tested Android 15 device, one bulk preload is materially cheaper than per-package deep metadata calls, even for single-package and small-profile refreshes.
- this preserves fast collection without giving up path fidelity for the common `/data/` and ordinary system directory cases already handled by path reconstruction.

### 3. Split-path authority

Keep:

- `cmd package path`
- `pm path`

as the authoritative split-path source.

Reason:

- AOSP package-manager shell code exposes path output from `sourceDir` and `splitSourceDirs`.
- this remains the trustworthy source for exact per-split APK path lists.
- reconstructed paths from bulk `dumpsys package packages` are useful and fast, but they are still a derived convenience path, not the authoritative split-path contract.

### 4. Targeted fallback metadata

For rare targeted metadata fallback, prefer:

- `dumpsys package <package>`

then:

- `cmd package dump-package <package>`
- `pm dump <package>`

Reason:

- `dumpsys package <package>` and `cmd package dump-package <package>` are both much faster than `pm dump`.
- package-specific dump output is only used when bulk metadata is absent or insufficient.
- package-specific dump is not treated as the primary source for all inventory fields.

## Compatibility and Fallback Rules

The implementation now handles:

- `cmd package ...` unavailable or unsupported:
  fallback to `pm ...`
- explicit `--user` unsupported:
  retry the same command without `--user`
- `dumpsys package <package>` returning global/unhelpful output:
  parse result; if inventory-relevant fields are absent, continue to the next fallback
- package dump missing fields:
  continue through the fallback chain
- `installerPackageName=null`:
  normalize to `None`
- empty split path output:
  respect existing inventory fallback policy and optional `pm list packages -f` rescue path
- non-zero command exit:
  continue to the next compatible command
- older Android releases with different shell behavior:
  continue to older/unscoped variants before giving up

## User Scoping

Inventory-side package-manager commands now support a configurable package user id:

- env var: `SCYTALEDROID_ADB_PACKAGE_USER_ID`
- default: `0`
- disable explicit user scoping: set to `none`

This applies where supported:

- package-manager list commands
- package-manager path commands
- `dumpsys package <package>` primary probe

Why configurable instead of hardcoded:

- user `0` matches the current analyst-operated physical-device contract
- future multi-user analysis should be able to override the target user without changing code

## Important Limitation: Signer and Label Authority

Live testing showed that package-specific dump surfaces on this device do **not** reliably provide:

- full signer SHA-256 certificate digests
- application labels

Therefore:

- package-specific dump must **not** be treated as a solved signer-authority surface
- package-specific dump must **not** be treated as a solved label-authority surface
- signer identity and label enrichment should remain conservative and may still require other sources or best-effort fallback behavior

## Runtime Summary

Current command policy:

1. bulk package list via `cmd package list packages ...`, fallback to `pm list packages ...`
2. bulk metadata via `dumpsys package packages`
3. split-path authority via `cmd package path` / `pm path`
4. targeted metadata via `dumpsys package <package>`, fallback to `cmd package dump-package`, then `pm dump`

## Related Files

- `scytaledroid/DeviceAnalysis/inventory/adb_bulk.py`
- `scytaledroid/DeviceAnalysis/package_inventory.py`
- `scytaledroid/DeviceAnalysis/package_info.py`
- `scytaledroid/DeviceAnalysis/adb/package_manager.py`
- `.env.example`
