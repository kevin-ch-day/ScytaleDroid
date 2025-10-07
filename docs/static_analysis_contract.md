# Static Analysis Pipeline Contract

This document captures the agreed-upon contracts, execution order, and ownership boundaries for the Static Analysis pipeline and CLI. It is intended as a reference for future implementation work so that each component can be developed independently without ambiguity.

## 0. Cross-Cutting Rules

- **Timestamp format:** All rendered timestamps must use `M-D-YYYY h:mm AM/PM` (America/Chicago time zone).
- **Determinism:** Outputs must have fixed wording and deterministic ordering (sort lists before rendering).
- **Safety:** Never render raw secret values—only evidence pointers and short hashes.
- **Badges:** Valid status badges are `[OK]`, `[INFO]`, `[WARN]`, `[FAIL]`, and `[skipped]`.
- **Timing:** Every section returns a `duration_sec` (float) and renders it with one decimal place.
- **Evidence limit:** Renderers must display no more than `N` evidence entries (default `2`), appending `(+N more)` when additional entries are omitted.

## 1. Core Types

The following data classes (under `scytaledroid/StaticAnalysis/core/`) define the shared interfaces:

### `DetectorContext`
Read-only input passed to each detector.
- `apk_path: str`
- `app_label: Optional[str]`
- `package_name: str`
- `version_name: str`
- `version_code: str | int`
- `manifest_tree / manifest_xml`
- `dex_index`
- `resources_index`
- `sdk_min`, `sdk_target`, `sdk_compile: int`
- `flags` (debuggable, allowBackup, usesCleartextTraffic, requestLegacyExternalStorage, networkSecurityConfig, sharedUserId, etc.)
- `permissions_declared: set[str]`
- `clock: Callable[[], str]` – returns formatted timestamp

### `EvidencePointer`
- `location: str` (e.g., `AndroidManifest.xml:/manifest/application/provider[1]`)
- `hash_short: str` (e.g., `#h:77d5…`, derived from snippet hash; snippet is not stored)

### `Finding`
- `id: str` (stable identifier, e.g., `STORAGE_PLAINTEXT_PREFS`)
- `title: str`
- `severity_gate: Literal["P0", "P1", "P2"]`
- `category_masvs: Literal["NETWORK", "PLATFORM", "STORAGE", "PRIVACY", "CRYPTO", "RESILIENCE"]`
- `status: Badge`
- `because: str` (concise causal chain)
- `evidence: list[EvidencePointer]`
- `remediate: str` (single prescriptive sentence)
- `metrics: dict`
- `tags: set[str]`

### `DetectorResult`
- `section_key: str`
- `status: Badge`
- `metrics: dict[str, int | float | str]`
- `evidence: list[EvidencePointer]`
- `notes: list[str]`
- `duration_sec: float`
- `subitems: Optional[list[dict]]`
- `raw_debug: Optional[str]`

## 2. Directory Layout

```
scytaledroid/StaticAnalysis/
  cli/
    sections.py          # section renderers (uses section_utils)
    options.py           # CLI flags (verbosity, evidence limit, filtering)
    progress.py          # headers/footers for repo/group runs
  core/
    pipeline.py          # orchestrates detector execution
    repository.py        # repo/group rollups
  detectors/
    integrity.py
    permissions.py
    components.py
    provider_acl.py
    network.py
    domain_verification.py
    secrets.py
    storage.py
    webview.py
    crypto.py
    dynamic.py
    fileio.py
    interaction.py
    sdks.py
    native.py
    obfuscation.py
    correlation.py       # synthesizes P0/P1 findings
  modules/
    string_analysis/
      extractor.py, patterns.py, network.py, correlator.py
  persistence/
    reports.py           # save confirmations (no schema change)
  cli/
    section_utils.py     # shared formatting helpers

scytaledroid/Reporting/
  __init__.py
  menu.py                # interactive report selection (optional)
  generator.py           # orchestrates report rendering
  formats/
    markdown.py
    html.py
    json.py
  templates/
    markdown_template.md
    html_template.html
```

All report generation responsibilities live under the root-level `scytaledroid/Reporting/` package so that Static Analysis code
focuses solely on producing normalized results. The CLI should hand off completed detector output to the reporting module for any
export or persistence workflow.

## 3. Detector Execution Order

`pipeline.py` must invoke detectors in the following fixed order, forwarding each `DetectorResult` to the renderer in `cli/sections.py`:

1. `integrity.run(ctx)`
2. `components.run(ctx)`
3. `permissions.run(ctx)`
4. `components.run_ipc(ctx)`
5. `provider_acl.run(ctx)`
6. `network.run(ctx)`
7. `domain_verification.run(ctx)`
8. `secrets.run(ctx)`
9. `storage.run(ctx)`
10. `webview.run(ctx)`
11. `crypto.run(ctx)`
12. `dynamic.run(ctx)`
13. `fileio.run(ctx)`
14. `interaction.run(ctx)`
15. `sdks.run(ctx)`
16. `native.run(ctx)`
17. `obfuscation.run(ctx)`
18. `correlation.run(ctx, prior_results=[...])`

`cli/sections.py` must mirror this order to maintain deterministic rendering.

## 4. Detector Responsibilities and Contracts

Each detector owns a specific concern area and returns a `DetectorResult` meeting the cross-cutting rules.

- **integrity.py:** APK size, SDK targets, signing schemes (v2/v3/v4), debug certificate flag, hashes, multidex count, split awareness. Status defaults to `[OK]`; emit `[INFO]` when tooling missing.
- **permissions.py:** Declared permissions summary (dangerous counts, signature/custom, notable combos). Status `[INFO]`.
- **components.py:**
  - `run(ctx)`: Manifest hygiene (flags such as debuggable, allowBackup, usesCleartextTraffic, networkSecurityConfig, sharedUserId, component counts, foreground service types, taskAffinity anomalies). Status `[INFO]`.
  - `run_ipc(ctx)`: IPC exposure (exported activities/receivers/services, guards, intent filters). Status `[WARN]` when unguarded exports.
- **provider_acl.py:** Exported content providers, permission guards, `grantUriPermissions`, authorities, path-permissions. Status `[FAIL]` when user-data authority lacks guards; otherwise `[INFO]`.
- **network.py:** HTTP/HTTPS endpoint counts (string analysis), trust policy inspection, pinning detection, network security config overrides. Status `[OK]` or `[WARN]` on risky trust/pinning findings.
- **domain_verification.py:** `autoVerify` usage, verified domains, mismatches with intent filters. Status `[INFO]`.
- **secrets.py:** Detect secret types (Google API key, Firebase key, AWS access key, bearer token, etc.), suppress obvious test/local values, produce pointers with hashes, track filtered count. Status `[WARN]` when non-test secrets exist.
- **storage.py:** Plaintext secrets in SharedPreferences/files/DBs, external storage usage, backup interactions. Status `[WARN]` when plaintext with `allowBackup`; otherwise `[INFO]`.
- **webview.py:** WebView hardening (JavaScript enabled, `addJavascriptInterface`, universal file access, mixed content). Status `[OK]` or `[WARN]` based on risky combinations.
- **crypto.py:** Cipher mode usage, AES-ECB/static IV detection, weak digests, low PBKDF2 iterations. Provide worst-case evidence pointer. Status `[WARN]` on weak constructs.
- **dynamic.py:** Reflection hotspots, dynamic code loading (`DexClassLoader`, `PathClassLoader`), native loading, suspicious `WebView.loadUrl`, `Base64.decode` near reflection. Status `[WARN]` when combined with sensitive permissions/secrets.
- **fileio.py:** Sensitive file writes to world-readable locations, `Android/data/<pkg>/files`, lingering temp files. Status `[WARN]` if sensitive external exposure.
- **interaction.py:** User interaction risks (`ClipboardManager`, `SYSTEM_ALERT_WINDOW`, `AccessibilityService`, `MediaProjection`). Status escalates to `[WARN]` with dangerous permissions.
- **sdks.py:** Identify embedded SDKs, map related permissions, optional version hints. Status `[INFO]`.
- **native.py:** `.so` coverage, hardening flags (PIE, RELRO, NX, Canary), suspicious strings, 32/64-bit support. Status `[OK]`/`[INFO]`; `[WARN]` when missing critical hardening.
- **obfuscation.py:** Obfuscation score (low/med/high), packer signatures, anti-debug/emulator/root/hook checks. Status `[INFO]`, `[WARN]` for aggressive tamper defenses.
- **correlation.py:** Combine prior `DetectorResult`s into normalized P0/P1 `Finding` objects using deterministic rules:
  1. `P0_CLEARtext_VIABLE`: `usesCleartextTraffic` and ≥1 HTTP endpoint and `INTERNET` permission.
  2. `P0_DATA_EXFIL_IPC`: Dangerous permission (contacts/location) with unguarded exported component (activity/provider).
  3. `P0_HARDCODED_CRED_AT_RISK`: Sensitive secret type with matching endpoint family.
  4. `P1_BACKUP_EXTRACTABLE_SECRETS`: `allowBackup` with plaintext storage hit.
  5. `P1_WEAK_CRYPTO_SENSITIVE_FLOW`: AES-ECB or static IV CBC near token/password usage.
  6. `P1_DYNAMIC_LOADING_WITH_DANGEROUS_PERMS`: Dynamic class loading with dangerous permissions.
  7. `P1_PROVIDER_URI_GRANT_MISUSE`: Exported provider with `grantUriPermissions` but no read/write guards.

Findings must be sorted with all `P0` (alphabetical by title) followed by `P1` (alphabetical). No duplicates.

## 5. Rendering (`cli/sections.py`)

Each renderer accepts a `DetectorResult`, `verbosity`, and `max_evidence` and emits lines in the following order:

1. Section header (title).
2. Key metrics (compact).
3. Evidence list (respecting limit and `(+N more)` suffix).
4. Optional notes (one-liners).
5. `Timing: <X.Ys>`.
6. `Status: [BADGE]`.

On detector errors, render the header followed by `[skipped]` and the reason, then continue.

## 6. CLI Options (`cli/options.py`)

- `--profile {quick, full}`:
  - `quick`: runs detectors through Secrets and then Correlation (skip later sections for speed).
  - `full`: runs the entire pipeline.
- `--verbosity {normal, detail, debug}`:
  - `detail`: increases evidence limit (e.g., from 2 to 5).
  - `debug`: appends `raw_debug` output after each section block.
- `--max-evidence N`: overrides default evidence display limit.
- Filters: `--only P0,P1` (show headers for others but skip details), `--group`, `--app` filters.

Presentation changes must not alter `Finding` content.

## 7. Rollups (`core/repository.py`, `cli/progress.py`)

- **Group Summary:**
  - Totals: apps, artifacts, P0/P1/P2 counts.
  - Top three risk titles (by frequency across apps).
  - Slowest artifact.
  - `Finished: <timestamp>`.
- **Repository Summary:**
  - Totals and status buckets (Failed = P0 present, Warn = P1 only, Info = P2 only).
  - Duration, `Started`, `Finished` timestamps.
  - Export hint for downstream tooling.

## 8. Implementation Sequence (Suggested)

1. Renderer scaffolding (`sections.py`, `section_utils.py`, `progress.py`, timestamp formatting).
2. Stage 0 detectors (Integrity, Components hygiene, Permissions).
3. IPC & Provider ACL detectors.
4. Network & Domain Verification detectors.
5. Secrets detector.
6. Storage, WebView, Crypto detectors.
7. Dynamic, File I/O, Interaction detectors.
8. SDKs, Native, Obfuscation detectors.
9. Correlation logic for P0/P1 findings.
10. Summaries, rollups, and CLI polish (`--profile`, `--only`, `--max-evidence`).

## 9. Acceptance Checklist

- Each section reports timing and status.
- No raw secrets are rendered.
- Evidence respects the max limit and displays `(+N more)` when truncated.
- Ordering and wording remain deterministic.
- Timestamp formatting is correct.
- Detectors fail gracefully with `[skipped]` and a one-line reason.

## 10. Example Output Snippets

- `Started: 10-7-2025 11:19 AM`
- `Timing: 0.7s`
- `Status: [WARN]`
- Evidence block:
  - `classes.dex:com/crypto/CipherUtil.java:73  #h:1ab3…`
  - `AndroidManifest.xml:/manifest/application/provider[1]  #h:9f20…`
  - `(+3 more)`

---

This contract is the source of truth for future implementations of the Static Analysis pipeline and its CLI rendering.
